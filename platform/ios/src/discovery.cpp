#include <arpa/inet.h>
#include <dns_sd.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <poll.h>

#include "../../../src/discovery_backend.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <limits>
#include <set>
#include <utility>

namespace huxerui::localnetwork::detail {
namespace {

using namespace std::chrono_literals;
using Clock = std::chrono::steady_clock;
constexpr char domain[] = "local.";
constexpr auto operation_timeout = 8s;
constexpr auto address_observation = 150ms;

// Publish on the interface that owns the listener address so Bonjour advertises a reachable host.
std::optional<std::uint32_t> FindMulticastInterface(const std::string& host) {
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
    if (index == 0) continue;
    if (address->ai_family == AF_INET) {
      const auto* actual = reinterpret_cast<const sockaddr_in*>(row->ifa_addr);
      const auto* wanted = reinterpret_cast<const sockaddr_in*>(address->ai_addr);
      if (actual->sin_addr.s_addr == wanted->sin_addr.s_addr) {
        return index;
      }
    } else if (address->ai_family == AF_INET6) {
      const auto* actual = reinterpret_cast<const sockaddr_in6*>(row->ifa_addr);
      const auto* wanted = reinterpret_cast<const sockaddr_in6*>(address->ai_addr);
      if ((!wanted->sin6_scope_id || wanted->sin6_scope_id == index) &&
          std::memcmp(&actual->sin6_addr, &wanted->sin6_addr, sizeof(in6_addr)) == 0) {
        return index;
      }
    }
  }
  return std::nullopt;
}

NetworkError BonjourError(DNSServiceErrorType status, std::string message) {
  auto code = NetworkErrorCode::DiscoveryFailed;
  if (status == kDNSServiceErr_PolicyDenied || status == kDNSServiceErr_NoAuth) {
    code = NetworkErrorCode::PermissionDenied;
  } else if (status == kDNSServiceErr_ServiceNotRunning) {
    code = NetworkErrorCode::Unsupported;
  } else if (status == kDNSServiceErr_Timeout) {
    code = NetworkErrorCode::TimedOut;
  }
  return {code, status, std::move(message)};
}

class BonjourRequest final {
public:
  BonjourRequest() = default;
  BonjourRequest(const BonjourRequest&) = delete;
  BonjourRequest& operator=(const BonjourRequest&) = delete;
  ~BonjourRequest() { Close(); }

  DNSServiceRef* Out() noexcept { return &ref_; }

  void Close() noexcept {
    if (auto ref = std::exchange(ref_, nullptr)) DNSServiceRefDeallocate(ref);
  }

  DNSServiceErrorType DispatchReady() {
    const auto socket = DNSServiceRefSockFD(ref_);
    if (socket < 0) return kDNSServiceErr_BadReference;
    // Only process readable replies. Bound the batch so a busy browse yields to the application.
    for (int remaining = 32; remaining > 0; --remaining) {
      pollfd descriptor{socket, POLLIN, 0};
      const auto available = poll(&descriptor, 1, 0);
      if (available == 0 || (available < 0 && errno == EINTR)) break;
      if (available < 0 || !(descriptor.revents & POLLIN)) return kDNSServiceErr_Unknown;
      const auto error = DNSServiceProcessResult(ref_);
      if (error != kDNSServiceErr_NoError) return error;
    }
    return kDNSServiceErr_NoError;
  }

private:
  DNSServiceRef ref_ = nullptr;
};

template <class Done>
Task<DNSServiceErrorType> DispatchUntil(BonjourRequest& request, Clock::time_point deadline, Done done) {
  // Process Bonjour replies from the iOS task that owns the request and its callback state.
  while (Clock::now() < deadline && !done()) {
    const auto status = request.DispatchReady();
    if (status != kDNSServiceErr_NoError) co_return status;
    if (!done()) co_await Delay(20ms);
  }
  co_return kDNSServiceErr_NoError;
}

struct BrowseState {
  std::set<std::pair<std::string, std::uint32_t>> visible;
  DNSServiceErrorType error = kDNSServiceErr_NoError;
};

void DNSSD_API OnBrowse(DNSServiceRef, DNSServiceFlags flags, std::uint32_t interface_index,
                       DNSServiceErrorType error, const char* name, const char*, const char*, void* context) noexcept {
  auto& state = *static_cast<BrowseState*>(context);
  if (error != kDNSServiceErr_NoError) {
    state.error = error;
    return;
  }
  if (!name || state.error != kDNSServiceErr_NoError) return;
  try {
    if (!(flags & kDNSServiceFlagsAdd)) state.visible.erase({name, interface_index});
    else if (state.visible.size() < 128) state.visible.emplace(name, interface_index);
  } catch (...) {
    state.error = kDNSServiceErr_NoMemory;
  }
}

struct ResolveState {
  std::string host;
  ServiceTxt txt;
  std::uint32_t interface_index = 0;
  std::uint16_t port = 0;
  DNSServiceErrorType error = kDNSServiceErr_NoError;
};

void DNSSD_API OnResolve(DNSServiceRef, DNSServiceFlags, std::uint32_t interface_index, DNSServiceErrorType error,
                        const char*, const char* host, std::uint16_t port, std::uint16_t txt_length,
                        const unsigned char* txt, void* context) noexcept {
  auto& state = *static_cast<ResolveState*>(context);
  state.error = error;
  if (error != kDNSServiceErr_NoError) return;
  if (!host || !*host || port == 0) {
    state.error = kDNSServiceErr_BadParam;
    return;
  }
  try {
    state.host = host;
    state.interface_index = interface_index;
    state.port = ntohs(port);
    state.txt = txt && txt_length > 0 ? DecodeServiceTxt({txt, txt_length}) : ServiceTxt{};
  } catch (...) {
    state.error = kDNSServiceErr_NoMemory;
  }
}

struct AddressState {
  std::vector<Endpoint> endpoints;
  Clock::time_point first_address{};
  std::uint16_t port;
  DNSServiceErrorType error = kDNSServiceErr_NoError;
};

void DNSSD_API OnAddress(DNSServiceRef, DNSServiceFlags flags, std::uint32_t interface_index,
                        DNSServiceErrorType error, const char*, const sockaddr* address,
                        std::uint32_t, void* context) noexcept {
  auto& state = *static_cast<AddressState*>(context);
  // An IPv4-only or IPv6-only host may report a missing record for the other family.
  if (error == kDNSServiceErr_NoSuchRecord) return;
  if (error != kDNSServiceErr_NoError) {
    state.error = error;
    return;
  }
  if (!address || state.error != kDNSServiceErr_NoError) return;
  std::array<char, INET6_ADDRSTRLEN> numeric{};
  std::uint32_t scope = 0;
  if (address->sa_family == AF_INET) {
    const auto* v4 = reinterpret_cast<const sockaddr_in*>(address);
    if (!inet_ntop(AF_INET, &v4->sin_addr, numeric.data(), numeric.size())) return;
  } else if (address->sa_family == AF_INET6) {
    const auto* v6 = reinterpret_cast<const sockaddr_in6*>(address);
    if (!inet_ntop(AF_INET6, &v6->sin6_addr, numeric.data(), numeric.size())) return;
    if (IN6_IS_ADDR_LINKLOCAL(&v6->sin6_addr)) {
      scope = v6->sin6_scope_id == 0 ? interface_index : v6->sin6_scope_id;
      if (scope == 0) return;
    }
  } else {
    return;
  }
  try {
    std::string host = numeric.data();
    if (scope != 0) host += "%" + std::to_string(scope);
    const auto known = std::ranges::find(state.endpoints, host, &Endpoint::host);
    if (!(flags & kDNSServiceFlagsAdd)) {
      if (known != state.endpoints.end()) state.endpoints.erase(known);
    } else if (known == state.endpoints.end() && state.endpoints.size() < 16) {
      if (state.endpoints.empty()) state.first_address = Clock::now();
      state.endpoints.push_back({std::move(host), state.port});
    }
  } catch (...) {
    state.error = kDNSServiceErr_NoMemory;
  }
}

class BonjourPublication final : public PublicationState {
public:
  Task<NetworkResult<void>> Register(const ServiceAnnouncement& announcement, std::uint32_t interface_index) {
    using Result = NetworkResult<void>;
    const auto txt = EncodeServiceTxt(announcement.txt);
    // Let Bonjour disambiguate identical instance labels on the same network.
    const auto error = DNSServiceRegister(request_.Out(), 0, interface_index,
        announcement.name.c_str(), announcement.type.c_str(), domain, nullptr, htons(announcement.endpoint.port),
        static_cast<std::uint16_t>(txt.size()), txt.data(), OnRegister, this);
    if (error != kDNSServiceErr_NoError) co_return Result::Failure(BonjourError(error, "Could not publish the service."));
    const auto status = co_await DispatchUntil(request_, Clock::now() + operation_timeout, [this] { return finished_; });
    if (status != kDNSServiceErr_NoError) co_return Result::Failure(BonjourError(status, "Bonjour publication failed."));
    if (error_ != kDNSServiceErr_NoError) co_return Result::Failure(BonjourError(error_, "Bonjour publication failed."));
    if (!finished_) co_return Result::Failure(BonjourError(kDNSServiceErr_Timeout, "Bonjour publication timed out."));
    co_return Result::Success();
  }

  void Close() noexcept override { request_.Close(); }

private:
  static void DNSSD_API OnRegister(DNSServiceRef, DNSServiceFlags, DNSServiceErrorType error,
                                   const char*, const char*, const char*, void* context) noexcept {
    auto& self = *static_cast<BonjourPublication*>(context);
    self.error_ = error;
    self.finished_ = true;
  }

  BonjourRequest request_;
  DNSServiceErrorType error_ = kDNSServiceErr_NoError;
  bool finished_ = false;
};

} // namespace

Task<NetworkResult<std::vector<DiscoveredService>>> BrowsePlatformServices(
    std::string type, ServiceBrowseOptions options) {
  using Result = NetworkResult<std::vector<DiscoveredService>>;
  if (options.scope && *options.scope > std::numeric_limits<std::uint32_t>::max()) {
    co_return Result::Failure({NetworkErrorCode::InvalidEndpoint, 0, "Invalid DNS-SD interface index."});
  }
  BrowseState state;
  BonjourRequest request;
  const auto index = static_cast<std::uint32_t>(options.scope.value_or(kDNSServiceInterfaceIndexAny));
  const auto started = DNSServiceBrowse(request.Out(), 0, index, type.c_str(), domain, OnBrowse, &state);
  if (started != kDNSServiceErr_NoError) {
    co_return Result::Failure(BonjourError(started, "Could not browse for Bonjour services."));
  }
  const auto status = co_await DispatchUntil(request, Clock::now() + options.observation,
                                            [&state] { return state.error != kDNSServiceErr_NoError; });
  const auto error = state.error != kDNSServiceErr_NoError ? state.error : status;
  if (error != kDNSServiceErr_NoError) co_return Result::Failure(BonjourError(error, "Bonjour browsing failed."));
  std::vector<DiscoveredService> entries;
  for (const auto& [name, interface_index] : state.visible) entries.push_back({name, type, name, interface_index});
  co_return Result::Success(std::move(entries));
}

Task<NetworkResult<ResolvedService>> ResolvePlatformService(DiscoveredService service) {
  using Result = NetworkResult<ResolvedService>;
  if (service.scope > std::numeric_limits<std::uint32_t>::max()) {
    co_return Result::Failure({NetworkErrorCode::InvalidEndpoint, 0, "Invalid DNS-SD interface index."});
  }

  ResolveState state;
  BonjourRequest resolve;
  const auto deadline = Clock::now() + operation_timeout;
  const auto started = DNSServiceResolve(resolve.Out(), 0, static_cast<std::uint32_t>(service.scope),
      service.instance.c_str(), service.type.c_str(), domain, OnResolve, &state);
  if (started != kDNSServiceErr_NoError) co_return Result::Failure(BonjourError(started, "Could not resolve the service."));
  const auto status = co_await DispatchUntil(resolve, deadline, [&state] {
    return !state.host.empty() || state.error != kDNSServiceErr_NoError;
  });
  const auto error = state.error != kDNSServiceErr_NoError ? state.error : status;
  if (error != kDNSServiceErr_NoError) co_return Result::Failure(BonjourError(error, "Bonjour resolution failed."));
  if (state.host.empty()) co_return Result::Failure(BonjourError(kDNSServiceErr_Timeout, "Bonjour resolution timed out."));
  resolve.Close();

  AddressState addresses{.port = state.port};
  BonjourRequest lookup;
  const auto queried = DNSServiceGetAddrInfo(lookup.Out(), kDNSServiceFlagsForceMulticast, state.interface_index,
      kDNSServiceProtocol_IPv4 | kDNSServiceProtocol_IPv6, state.host.c_str(), OnAddress, &addresses);
  if (queried != kDNSServiceErr_NoError) co_return Result::Failure(BonjourError(queried, "Could not resolve the host address."));
  // Allow both address families to arrive within the original resolve deadline.
  const auto lookup_status = co_await DispatchUntil(lookup, deadline, [&addresses] {
    return addresses.error != kDNSServiceErr_NoError ||
           (!addresses.endpoints.empty() && Clock::now() - addresses.first_address >= address_observation);
  });
  const auto lookup_error = addresses.error != kDNSServiceErr_NoError ? addresses.error : lookup_status;
  if (lookup_error != kDNSServiceErr_NoError) {
    co_return Result::Failure(BonjourError(lookup_error, "Bonjour address resolution failed."));
  }
  if (addresses.endpoints.empty()) {
    co_return Result::Failure(BonjourError(kDNSServiceErr_Timeout, "Bonjour address resolution timed out."));
  }
  co_return Result::Success({std::move(addresses.endpoints), std::nullopt, std::move(state.txt)});
}

Task<NetworkResult<std::shared_ptr<PublicationState>>> PublishPlatformService(ServiceAnnouncement announcement) {
  using Result = NetworkResult<std::shared_ptr<PublicationState>>;
  const auto bind = FindMulticastInterface(announcement.endpoint.host);
  if (!bind) {
    co_return Result::Failure({NetworkErrorCode::InvalidEndpoint, 0,
                               "Bonjour publication requires a concrete address on an active multicast interface."});
  }
  auto publication = std::make_shared<BonjourPublication>();
  auto registered = co_await publication->Register(announcement, *bind);
  if (!registered.Succeeded()) co_return Result::Failure(std::move(registered).Error());
  co_return Result::Success(std::move(publication));
}

} // namespace huxerui::localnetwork::detail
