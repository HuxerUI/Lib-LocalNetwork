#ifdef HUXERUI_LOCALNETWORK_AVAHI

#include <avahi-client/client.h>
#include <avahi-client/lookup.h>
#include <avahi-client/publish.h>
#include <avahi-common/error.h>
#include <avahi-common/thread-watch.h>

#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>

#include "../../../src/discovery_backend.h"

#include <array>
#include <cstring>
#include <limits>
#include <mutex>
#include <set>
#include <tuple>
#include <utility>

namespace huxerui::localnetwork::detail {
namespace {

using namespace std::chrono_literals;
using Clock = std::chrono::steady_clock;
constexpr char domain[] = "local";
constexpr auto operation_timeout = 8s;
constexpr auto poll_interval = 20ms;

NetworkError AvahiError(int status, std::string message) {
  auto code = NetworkErrorCode::DiscoveryFailed;
  if (status == AVAHI_ERR_ACCESS_DENIED) code = NetworkErrorCode::PermissionDenied;
  else if (status == AVAHI_ERR_NO_DAEMON) code = NetworkErrorCode::Unsupported;
  else if (status == AVAHI_ERR_TIMEOUT) code = NetworkErrorCode::TimedOut;
  message += " ";
  message += avahi_strerror(status);
  return {code, status, std::move(message)};
}

class AvahiSession final {
public:
  AvahiSession() = default;
  AvahiSession(const AvahiSession&) = delete;
  AvahiSession& operator=(const AvahiSession&) = delete;

  static NetworkResult<std::unique_ptr<AvahiSession>> Open() {
    using Result = NetworkResult<std::unique_ptr<AvahiSession>>;
    auto session = std::make_unique<AvahiSession>();
    session->poll_ = avahi_threaded_poll_new();
    if (!session->poll_) {
      return Result::Failure(AvahiError(AVAHI_ERR_NO_MEMORY, "Could not create an Avahi event loop."));
    }
    int status = AVAHI_OK;
    session->client_ = avahi_client_new(avahi_threaded_poll_get(session->poll_), AvahiClientFlags{},
                                       nullptr, nullptr, &status);
    if (!session->client_) return Result::Failure(AvahiError(status, "Could not connect to the Avahi service."));
    if (avahi_threaded_poll_start(session->poll_) < 0) {
      return Result::Failure(AvahiError(AVAHI_ERR_FAILURE, "Could not run the Avahi event loop."));
    }
    session->running_ = true;
    return Result::Success(std::move(session));
  }

  ~AvahiSession() {
    // Stop dispatch before freeing the client and its browser, resolver, or publication.
    if (running_) avahi_threaded_poll_stop(poll_);
    if (client_) avahi_client_free(client_);
    if (poll_) avahi_threaded_poll_free(poll_);
  }

  void lock() noexcept { avahi_threaded_poll_lock(poll_); }
  void unlock() noexcept { avahi_threaded_poll_unlock(poll_); }
  AvahiClient* Client() const noexcept { return client_; }
  int Failure() const noexcept {
    return avahi_client_get_state(client_) == AVAHI_CLIENT_FAILURE ? avahi_client_errno(client_) : AVAHI_OK;
  }

private:
  AvahiThreadedPoll* poll_ = nullptr;
  AvahiClient* client_ = nullptr;
  bool running_ = false;
};

struct BrowseState {
  std::set<std::tuple<std::string, AvahiIfIndex, AvahiProtocol>> visible;
  int error = AVAHI_OK;
};

void OnBrowse(AvahiServiceBrowser* browser, AvahiIfIndex index, AvahiProtocol protocol, AvahiBrowserEvent event,
              const char* name, const char*, const char*, AvahiLookupResultFlags, void* context) noexcept {
  auto& state = *static_cast<BrowseState*>(context);
  if (event == AVAHI_BROWSER_FAILURE) {
    state.error = avahi_client_errno(avahi_service_browser_get_client(browser));
    return;
  }
  if (!name) return;
  try {
    // An instance can be visible using both multicast families on one interface. Track each source until it is lost.
    if (event == AVAHI_BROWSER_NEW && state.visible.size() < 256) state.visible.emplace(name, index, protocol);
    if (event == AVAHI_BROWSER_REMOVE) state.visible.erase({name, index, protocol});
  } catch (...) {
    state.error = AVAHI_ERR_NO_MEMORY;
  }
}

struct ResolveState {
  std::optional<Endpoint> endpoint;
  ServiceTxt txt;
  int error = AVAHI_OK;
};

void OnResolve(AvahiServiceResolver* resolver, AvahiIfIndex index, AvahiProtocol, AvahiResolverEvent event,
               const char*, const char*, const char*, const char*, const AvahiAddress* address,
               std::uint16_t port, AvahiStringList* txt, AvahiLookupResultFlags, void* context) noexcept {
  auto& state = *static_cast<ResolveState*>(context);
  if (event == AVAHI_RESOLVER_FAILURE) {
    state.error = avahi_client_errno(avahi_service_resolver_get_client(resolver));
    return;
  }
  std::array<char, AVAHI_ADDRESS_STR_MAX> host{};
  if (!address || port == 0 || !avahi_address_snprint(host.data(), host.size(), address)) {
    state.error = AVAHI_ERR_INVALID_ADDRESS;
    return;
  }
  try {
    std::string scoped = host.data();
    if (address->proto == AVAHI_PROTO_INET6) {
      const auto* bytes = address->data.ipv6.address;
      if (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80) {
        if (index <= 0) {
          state.error = AVAHI_ERR_INVALID_INTERFACE;
          return;
        }
        scoped += "%" + std::to_string(index);
      }
    }
    state.txt.clear();
    for (auto* item = txt; item; item = avahi_string_list_get_next(item)) {
      const auto* text = reinterpret_cast<const char*>(avahi_string_list_get_text(item));
      if (text) InsertServiceTxtItem(state.txt, {text, avahi_string_list_get_size(item)});
    }
    state.endpoint.emplace(Endpoint{std::move(scoped), port});
  } catch (...) {
    state.error = AVAHI_ERR_NO_MEMORY;
  }
}

struct BindInterface {
  AvahiIfIndex index;
  AvahiProtocol protocol;
};

std::optional<BindInterface> InterfaceFor(const std::string& host) {
  addrinfo hints{};
  hints.ai_flags = AI_NUMERICHOST;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* resolved = nullptr;
  if (getaddrinfo(host.c_str(), nullptr, &hints, &resolved) != 0) return std::nullopt;
  const std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> address(resolved, freeaddrinfo);
  ifaddrs* listed = nullptr;
  if (getifaddrs(&listed) != 0) return std::nullopt;
  const std::unique_ptr<ifaddrs, decltype(&freeifaddrs)> interfaces(listed, freeifaddrs);
  for (auto* row = interfaces.get(); row; row = row->ifa_next) {
    if (!row->ifa_addr || row->ifa_addr->sa_family != address->ai_family || !(row->ifa_flags & IFF_UP) ||
        !(row->ifa_flags & IFF_MULTICAST) || (row->ifa_flags & IFF_LOOPBACK)) continue;
    const auto index = if_nametoindex(row->ifa_name);
    if (index == 0 || index > static_cast<unsigned>(std::numeric_limits<AvahiIfIndex>::max())) continue;
    if (address->ai_family == AF_INET) {
      const auto* actual = reinterpret_cast<const sockaddr_in*>(row->ifa_addr);
      const auto* wanted = reinterpret_cast<const sockaddr_in*>(address->ai_addr);
      if (actual->sin_addr.s_addr == wanted->sin_addr.s_addr) {
        return BindInterface{static_cast<AvahiIfIndex>(index), AVAHI_PROTO_INET};
      }
    } else if (address->ai_family == AF_INET6) {
      const auto* actual = reinterpret_cast<const sockaddr_in6*>(row->ifa_addr);
      const auto* wanted = reinterpret_cast<const sockaddr_in6*>(address->ai_addr);
      if ((!wanted->sin6_scope_id || wanted->sin6_scope_id == index) &&
          std::memcmp(&actual->sin6_addr, &wanted->sin6_addr, sizeof(in6_addr)) == 0) {
        return BindInterface{static_cast<AvahiIfIndex>(index), AVAHI_PROTO_INET6};
      }
    }
  }
  return std::nullopt;
}

class LinuxPublication final : public PublicationState {
public:
  explicit LinuxPublication(std::unique_ptr<AvahiSession> session) : session_(std::move(session)) {}
  ~LinuxPublication() override { Close(); }

  int Start(const ServiceAnnouncement& announcement, BindInterface bind) {
    std::unique_ptr<AvahiStringList, decltype(&avahi_string_list_free)> txt(nullptr, avahi_string_list_free);
    for (const auto& [key, value] : announcement.txt) {
      auto* updated = avahi_string_list_add_pair(txt.get(), key.c_str(), value.c_str());
      if (!updated) return AVAHI_ERR_NO_MEMORY;
      (void)txt.release();
      txt.reset(updated);
    }
    std::scoped_lock lock(*session_);
    auto* client = session_->Client();
    auto* group = avahi_entry_group_new(client, OnStateChanged, this);
    if (!group) return avahi_client_errno(client);
    const int added = avahi_entry_group_add_service_strlst(group, bind.index, bind.protocol, AVAHI_PUBLISH_USE_MULTICAST,
        announcement.name.c_str(), announcement.type.c_str(), domain, nullptr, announcement.endpoint.port, txt.get());
    return added < 0 ? added : avahi_entry_group_commit(group);
  }

  NetworkResult<bool> Status() const {
    using Result = NetworkResult<bool>;
    std::scoped_lock lock(*session_);
    int error = session_->Failure();
    if (state_ == AVAHI_ENTRY_GROUP_COLLISION) error = AVAHI_ERR_COLLISION;
    if (state_ == AVAHI_ENTRY_GROUP_FAILURE) error = avahi_client_errno(session_->Client());
    if (error != AVAHI_OK) return Result::Failure(AvahiError(error, "Could not publish the DNS-SD service."));
    return Result::Success(state_ == AVAHI_ENTRY_GROUP_ESTABLISHED);
  }

  void Close() noexcept override { session_.reset(); }

private:
  static void OnStateChanged(AvahiEntryGroup*, AvahiEntryGroupState state, void* context) noexcept {
    static_cast<LinuxPublication*>(context)->state_ = state;
  }

  AvahiEntryGroupState state_ = AVAHI_ENTRY_GROUP_UNCOMMITED;
  std::unique_ptr<AvahiSession> session_;
};

} // namespace

Task<NetworkResult<std::vector<DiscoveredService>>> BrowsePlatformServices(
    std::string type, ServiceBrowseOptions options) {
  using Result = NetworkResult<std::vector<DiscoveredService>>;
  if (options.scope && *options.scope > static_cast<std::uint64_t>(std::numeric_limits<AvahiIfIndex>::max())) {
    co_return Result::Failure({NetworkErrorCode::InvalidEndpoint, 0, "Invalid DNS-SD interface index."});
  }
  const auto selected = options.scope ? static_cast<AvahiIfIndex>(*options.scope) : AVAHI_IF_UNSPEC;
  BrowseState state;
  auto opened = co_await RunWorker(AvahiSession::Open);
  if (!opened.Succeeded()) co_return Result::Failure(std::move(opened).Error());
  auto session = std::move(opened).Value();
  {
    std::scoped_lock lock(*session);
    auto* client = session->Client();
    if (!avahi_service_browser_new(client, selected, AVAHI_PROTO_UNSPEC, type.c_str(), domain,
                                  AVAHI_LOOKUP_USE_MULTICAST, OnBrowse, &state)) {
      co_return Result::Failure(AvahiError(avahi_client_errno(client), "Could not browse for DNS-SD services."));
    }
  }
  co_await Delay(options.observation);
  std::scoped_lock lock(*session);
  const int error = state.error != AVAHI_OK ? state.error : session->Failure();
  if (error != AVAHI_OK) co_return Result::Failure(AvahiError(error, "DNS-SD browsing failed."));
  std::vector<DiscoveredService> entries;
  for (const auto& [name, index, protocol] : state.visible) {
    const auto scope = index > 0 ? static_cast<std::uint64_t>(index) : 0;
    if (!entries.empty() && entries.back().instance == name && entries.back().scope == scope) continue;
    entries.push_back({name, type, name, scope});
    if (entries.size() == 128) break;
  }
  co_return Result::Success(std::move(entries));
}

Task<NetworkResult<ResolvedService>> ResolvePlatformService(DiscoveredService service) {
  using Result = NetworkResult<ResolvedService>;
  if (service.scope > static_cast<std::uint64_t>(std::numeric_limits<AvahiIfIndex>::max())) {
    co_return Result::Failure({NetworkErrorCode::InvalidEndpoint, 0, "Invalid DNS-SD interface index."});
  }
  ResolveState state;
  auto opened = co_await RunWorker(AvahiSession::Open);
  if (!opened.Succeeded()) co_return Result::Failure(std::move(opened).Error());
  auto session = std::move(opened).Value();
  const auto index = service.scope == 0 ? AVAHI_IF_UNSPEC : static_cast<AvahiIfIndex>(service.scope);
  {
    std::scoped_lock lock(*session);
    auto* client = session->Client();
    if (!avahi_service_resolver_new(client, index, AVAHI_PROTO_UNSPEC, service.instance.c_str(), service.type.c_str(),
                                   domain, AVAHI_PROTO_UNSPEC, AVAHI_LOOKUP_USE_MULTICAST, OnResolve, &state)) {
      co_return Result::Failure(AvahiError(avahi_client_errno(client), "Could not resolve the DNS-SD service."));
    }
  }
  const auto expires = Clock::now() + operation_timeout;
  while (Clock::now() < expires) {
    {
      std::scoped_lock lock(*session);
      const int error = state.error != AVAHI_OK ? state.error : session->Failure();
      if (error != AVAHI_OK) co_return Result::Failure(AvahiError(error, "DNS-SD resolution failed."));
      if (state.endpoint) co_return Result::Success({{std::move(*state.endpoint)}, std::nullopt, std::move(state.txt)});
    }
    co_await Delay(poll_interval);
  }
  co_return Result::Failure({NetworkErrorCode::TimedOut, 0, "DNS-SD resolution timed out."});
}

Task<NetworkResult<std::shared_ptr<PublicationState>>> PublishPlatformService(ServiceAnnouncement announcement) {
  using Result = NetworkResult<std::shared_ptr<PublicationState>>;
  const auto bind = InterfaceFor(announcement.endpoint.host);
  if (!bind) {
    co_return Result::Failure({NetworkErrorCode::InvalidEndpoint, 0,
                               "DNS-SD publication requires a concrete address on an active multicast interface."});
  }
  auto opened = co_await RunWorker(AvahiSession::Open);
  if (!opened.Succeeded()) co_return Result::Failure(std::move(opened).Error());
  auto publication = std::make_shared<LinuxPublication>(std::move(opened).Value());
  if (const int status = publication->Start(announcement, *bind); status < 0) {
    co_return Result::Failure(AvahiError(status, "Could not start DNS-SD publication."));
  }
  const auto expires = Clock::now() + operation_timeout;
  while (Clock::now() < expires) {
    auto status = publication->Status();
    if (!status.Succeeded()) co_return Result::Failure(std::move(status).Error());
    if (status.Value()) co_return Result::Success(std::move(publication));
    co_await Delay(poll_interval);
  }
  co_return Result::Failure({NetworkErrorCode::TimedOut, 0, "DNS-SD publication timed out."});
}

} // namespace huxerui::localnetwork::detail

#endif
