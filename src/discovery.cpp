#include "discovery_backend.h"

#include <algorithm>
#include <string_view>
#include <utility>

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

#if !defined(_WIN32) && !defined(__ANDROID__) && !defined(HUXERUI_LOCALNETWORK_AVAHI)
NetworkError Unsupported() { return {NetworkErrorCode::Unsupported, 0, "DNS-SD is unavailable on this platform."}; }
#endif

} // namespace

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

bool IsDiscoverySupported() noexcept {
#if defined(_WIN32) || defined(__ANDROID__) || defined(HUXERUI_LOCALNETWORK_AVAHI)
  return true;
#else
  return false;
#endif
}

Task<NetworkResult<std::vector<DiscoveredService>>> BrowseServicesAsync(
    std::string type, std::chrono::milliseconds observation) {
  using Result = NetworkResult<std::vector<DiscoveredService>>;
  if (!ValidType(type) || observation <= std::chrono::milliseconds::zero() || observation > std::chrono::seconds(10)) {
    co_return Result::Failure(InvalidService());
  }
#if defined(_WIN32) || defined(__ANDROID__) || defined(HUXERUI_LOCALNETWORK_AVAHI)
  co_return co_await detail::BrowsePlatformServices(std::move(type), observation);
#else
  co_return Result::Failure(Unsupported());
#endif
}

Task<NetworkResult<ResolvedService>> ResolveServiceAsync(DiscoveredService service) {
  using Result = NetworkResult<ResolvedService>;
  if (!ValidType(service.type) || service.instance.empty() || service.instance.find('\0') != std::string::npos) {
    co_return Result::Failure(InvalidService());
  }
#if defined(_WIN32) || defined(__ANDROID__) || defined(HUXERUI_LOCALNETWORK_AVAHI)
  co_return co_await detail::ResolvePlatformService(std::move(service));
#else
  co_return Result::Failure(Unsupported());
#endif
}

Task<NetworkResult<ServicePublication>> PublishServiceAsync(ServiceAnnouncement announcement) {
  using Result = NetworkResult<ServicePublication>;
  if (!ValidType(announcement.type) || !ValidName(announcement.name) || announcement.endpoint.host.empty() ||
      announcement.endpoint.host.find('\0') != std::string::npos || announcement.endpoint.port == 0) {
    co_return Result::Failure(InvalidService());
  }
#if defined(_WIN32) || defined(__ANDROID__) || defined(HUXERUI_LOCALNETWORK_AVAHI)
  auto published = co_await detail::PublishPlatformService(std::move(announcement));
  if (!published.Succeeded()) co_return Result::Failure(std::move(published).Error());
  co_return Result::Success(ServicePublication(std::move(published).Value()));
#else
  co_return Result::Failure(Unsupported());
#endif
}

} // namespace huxerui::localnetwork
