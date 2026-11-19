#include "discovery_backend.h"
#include "utf8.h"

#ifdef __APPLE__
#include <TargetConditionals.h>
#endif

#include <algorithm>
#include <atomic>
#include <deque>
#include <string_view>
#include <utility>

namespace huxerui::localnetwork::detail {

struct ServiceBrowserState {
  using Services = std::map<std::pair<std::string, std::uint64_t>, DiscoveredService>;

  ServiceBrowserState(std::string service_type, ServiceBrowseOptions browse_options)
      : type(std::move(service_type)), options(browse_options) {}

  std::string type;
  ServiceBrowseOptions options;
  std::atomic_bool closed = false;
  std::atomic_flag reading;
  Services visible;
  std::deque<ServiceEvent> events;
};

bool InsertServiceTxt(ServiceTxt& txt, std::string_view key, std::string_view value) {
  if (key.empty() || key.size() > 254 || value.size() > 254 - key.size() || !ValidUtf8Text(value)) return false;
  std::string lower;
  lower.reserve(key.size());
  for (char ch : key) {
    if (ch < ' ' || ch > '~' || ch == '=') return false;
    lower.push_back(ch >= 'A' && ch <= 'Z' ? static_cast<char>(ch - 'A' + 'a') : ch);
  }
  auto total = key.size() + value.size() + 2;
  for (const auto& [name, text] : txt) total += name.size() + text.size() + 2;
  return total <= 1024 && txt.try_emplace(std::move(lower), value).second;
}

void InsertServiceTxtItem(ServiceTxt& txt, std::string_view item) {
  const auto split = item.find('=');
  InsertServiceTxt(txt, item.substr(0, split), split == std::string_view::npos ? std::string_view{} : item.substr(split + 1));
}

ServiceTxt DecodeServiceTxt(std::span<const unsigned char> bytes) {
  ServiceTxt txt;
  while (!bytes.empty()) {
    const auto size = bytes.front();
    bytes = bytes.subspan(1);
    if (bytes.size() < size) break;
    if (size != 0) InsertServiceTxtItem(txt, {reinterpret_cast<const char*>(bytes.data()), size});
    bytes = bytes.subspan(size);
  }
  return txt;
}

std::vector<unsigned char> EncodeServiceTxt(const ServiceTxt& txt) {
  std::vector<unsigned char> bytes;
  for (const auto& [key, value] : txt) {
    bytes.push_back(static_cast<unsigned char>(key.size() + value.size() + 1));
    bytes.insert(bytes.end(), key.begin(), key.end());
    bytes.push_back('=');
    bytes.insert(bytes.end(), value.begin(), value.end());
  }
  return bytes;
}

} // namespace huxerui::localnetwork::detail

namespace huxerui::localnetwork {
namespace {

bool ValidType(std::string_view type) {
  if (!type.starts_with('_') || !type.ends_with("._tcp") || type.size() < 7 || type.size() > 21) return false;
  const auto label = type.substr(1, type.size() - 6);
  return label.front() != '-' && label.back() != '-' && std::ranges::all_of(label, [](char ch) {
    return (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-';
  });
}

bool ValidName(std::string_view name) {
  return !name.empty() && name.size() <= 63 && name.find('.') == std::string_view::npos &&
         name.find('\0') == std::string_view::npos;
}

NetworkError InvalidService() { return {NetworkErrorCode::InvalidEndpoint, 0, "Invalid DNS-SD service details."}; }

bool ValidObservation(std::chrono::milliseconds observation) {
  return observation > std::chrono::milliseconds::zero() && observation <= std::chrono::seconds(10);
}

#if defined(_WIN32) || defined(__ANDROID__) || defined(HUXERUI_LOCALNETWORK_AVAHI) || \
    (defined(__APPLE__) && (TARGET_OS_OSX || TARGET_OS_IOS))
constexpr bool discovery_supported = true;
#else
constexpr bool discovery_supported = false;
#endif

NetworkError Unsupported() { return {NetworkErrorCode::Unsupported, 0, "DNS-SD is unavailable on this platform."}; }

Task<NetworkResult<ServiceEvent>> ReadChange(std::shared_ptr<detail::ServiceBrowserState> state) {
  using Result = NetworkResult<ServiceEvent>;
  const NetworkError closed{NetworkErrorCode::Closed, 0, "The DNS-SD browser is closed."};
  if (!state || state->closed) co_return Result::Failure(closed);
  if (state->reading.test_and_set()) {
    co_return Result::Failure({NetworkErrorCode::Busy, 0, "The DNS-SD browser already has a pending read."});
  }
  struct Reading {
    std::atomic_flag& flag;
    ~Reading() { flag.clear(); }
  } reading{state->reading};
  while (state->events.empty()) {
    auto snapshot = co_await BrowseServicesAsync(state->type, state->options.observation, state->options.scope);
    if (state->closed) co_return Result::Failure(closed);
    if (!snapshot.Succeeded()) co_return Result::Failure(std::move(snapshot).Error());
    detail::ServiceBrowserState::Services visible;
    for (auto& service : snapshot.Value()) {
      auto key = std::pair{service.instance_id, service.scope};
      visible.try_emplace(std::move(key), std::move(service));
    }
    // Keep the previous snapshot across failed observations to avoid spurious removals on transient errors.
    std::deque<ServiceEvent> changes;
    for (const auto& [key, service] : state->visible) {
      if (!visible.contains(key)) changes.push_back({ServiceChange::Removed, service});
    }
    for (const auto& [key, service] : visible) {
      const auto previous = state->visible.find(key);
      if (previous == state->visible.end()) changes.push_back({ServiceChange::Added, service});
      else if (previous->second.display_name != service.display_name) {
        changes.push_back({ServiceChange::DisplayNameChanged, service});
      }
    }
    state->visible = std::move(visible);
    state->events = std::move(changes);
  }
  if (state->closed) co_return Result::Failure(closed);
  auto event = std::move(state->events.front());
  state->events.pop_front();
  co_return Result::Success(std::move(event));
}

} // namespace

ServiceBrowser::ServiceBrowser(std::shared_ptr<detail::ServiceBrowserState> state) : state_(std::move(state)) {}
ServiceBrowser::ServiceBrowser(ServiceBrowser&&) noexcept = default;

ServiceBrowser& ServiceBrowser::operator=(ServiceBrowser&& other) noexcept {
  if (this != &other) {
    Close();
    state_ = std::move(other.state_);
  }
  return *this;
}

ServiceBrowser::~ServiceBrowser() { Close(); }
void ServiceBrowser::Close() noexcept { if (state_) state_->closed = true; }
Task<NetworkResult<ServiceEvent>> ServiceBrowser::NextAsync() { return ReadChange(state_); }

NetworkResult<ServiceBrowser> BrowseServiceChanges(std::string type, ServiceBrowseOptions options) {
  using Result = NetworkResult<ServiceBrowser>;
  if (!ValidType(type) || !ValidObservation(options.observation) || options.scope == 0) {
    return Result::Failure(InvalidService());
  }
  if (!IsDiscoverySupported()) return Result::Failure(Unsupported());
  return Result::Success(ServiceBrowser(std::make_shared<detail::ServiceBrowserState>(std::move(type), options)));
}

ServicePublication::ServicePublication(std::shared_ptr<detail::PublicationState> state) : state_(std::move(state)) {}
ServicePublication::ServicePublication(ServicePublication&&) noexcept = default;

ServicePublication& ServicePublication::operator=(ServicePublication&& other) noexcept {
  if (this != &other) {
    Close();
    state_ = std::move(other.state_);
  }
  return *this;
}

ServicePublication::~ServicePublication() { Close(); }
void ServicePublication::Close() noexcept { if (auto state = std::exchange(state_, {})) state->Close(); }

bool IsDiscoverySupported() noexcept { return discovery_supported; }

Task<NetworkResult<std::vector<DiscoveredService>>> BrowseServicesAsync(
    std::string type, std::chrono::milliseconds observation) {
  return BrowseServicesAsync(std::move(type), observation, std::nullopt);
}

Task<NetworkResult<std::vector<DiscoveredService>>> BrowseServicesAsync(
    std::string type, std::chrono::milliseconds observation, std::optional<std::uint64_t> scope) {
  using Result = NetworkResult<std::vector<DiscoveredService>>;
  if (!ValidType(type) || !ValidObservation(observation) || scope == 0) {
    co_return Result::Failure(InvalidService());
  }
  if constexpr (discovery_supported) {
    auto result = co_await detail::BrowsePlatformServices(std::move(type), {observation, scope});
    if (scope && result.Succeeded()) {
      std::erase_if(result.Value(), [scope](const auto& service) { return service.scope != *scope; });
    }
    co_return result;
  } else {
    co_return Result::Failure(Unsupported());
  }
}

Task<NetworkResult<ResolvedService>> ResolveServiceAsync(DiscoveredService service) {
  using Result = NetworkResult<ResolvedService>;
  if (!ValidType(service.type) || service.instance_id.empty() ||
      service.instance_id.find('\0') != std::string::npos) {
    co_return Result::Failure(InvalidService());
  }
  if constexpr (discovery_supported) {
    co_return co_await detail::ResolvePlatformService(std::move(service));
  } else {
    co_return Result::Failure(Unsupported());
  }
}

bool IsServicePickerSupported() noexcept {
#ifdef __ANDROID__
  return detail::IsPlatformServicePickerSupported();
#else
  return false;
#endif
}

Task<NetworkResult<std::optional<ResolvedService>>> PickServiceAsync(
    std::string type, std::optional<std::uint64_t> android_network_handle) {
  using Result = NetworkResult<std::optional<ResolvedService>>;
  if (!ValidType(type) || android_network_handle == 0) co_return Result::Failure(InvalidService());
#ifdef __ANDROID__
  if (IsServicePickerSupported())
    co_return co_await detail::PickPlatformService(std::move(type), android_network_handle);
#endif
  co_return Result::Failure({NetworkErrorCode::Unsupported, 0, "The system DNS-SD picker is unavailable."});
}

Task<NetworkResult<ServicePublication>> PublishServiceAsync(ServiceAnnouncement announcement) {
  using Result = NetworkResult<ServicePublication>;
  if (!ValidType(announcement.type) || !ValidName(announcement.name) || announcement.endpoint.host.empty() ||
      announcement.endpoint.host.find('\0') != std::string::npos || announcement.endpoint.port == 0) {
    co_return Result::Failure(InvalidService());
  }
  if constexpr (discovery_supported) {
    ServiceTxt normalized;
    for (const auto& [key, value] : announcement.txt) {
      if (!detail::InsertServiceTxt(normalized, key, value)) {
        co_return Result::Failure({NetworkErrorCode::InvalidEndpoint, 0, "Invalid DNS-SD TXT attributes."});
      }
    }
    announcement.txt = std::move(normalized);
    auto published = co_await detail::PublishPlatformService(std::move(announcement));
    if (!published.Succeeded()) co_return Result::Failure(std::move(published).Error());
    co_return Result::Success(ServicePublication(std::move(published).Value()));
  } else {
    co_return Result::Failure(Unsupported());
  }
}

} // namespace huxerui::localnetwork
