#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <windns.h>

#include "../../../src/discovery_backend.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <map>
#include <mutex>
#include <utility>

namespace huxerui::localnetwork::detail {
namespace {

using namespace std::chrono_literals;
using Clock = std::chrono::steady_clock;
using Instance = std::unique_ptr<DNS_SERVICE_INSTANCE, decltype(&DnsServiceFreeInstance)>;

NetworkError Error(DWORD status, std::string message) {
  const auto code = status == ERROR_ACCESS_DENIED ? NetworkErrorCode::PermissionDenied : NetworkErrorCode::DiscoveryFailed;
  return {code, static_cast<int>(status), std::move(message)};
}

std::wstring Wide(std::string_view text) {
  if (text.empty()) return {};
  const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
  if (size <= 0) return {};
  std::wstring result(static_cast<std::size_t>(size), L'\0');
  MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), result.data(), size);
  return result;
}

std::string Utf8(std::wstring_view text) {
  if (text.empty()) return {};
  const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()),
                                       nullptr, 0, nullptr, nullptr);
  if (size <= 0) return {};
  std::string result(static_cast<std::size_t>(size), '\0');
  WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), result.data(), size,
                      nullptr, nullptr);
  return result;
}

DWORD BindInterface(const IP4_ADDRESS* v4, const IP6_ADDRESS* v6) {
  MIB_UNICASTIPADDRESS_TABLE* addresses = nullptr;
  if (GetUnicastIpAddressTable(v4 ? AF_INET : AF_INET6, &addresses) != NO_ERROR) return 0;
  const std::unique_ptr<MIB_UNICASTIPADDRESS_TABLE, decltype(&FreeMibTable)> table(addresses, FreeMibTable);
  for (ULONG i = 0; i < table->NumEntries; ++i) {
    const auto& row = table->Table[i];
    if (v4 && row.Address.Ipv4.sin_addr.s_addr == *v4) return row.InterfaceIndex;
    if (v6 && std::memcmp(&row.Address.Ipv6.sin6_addr, v6, sizeof(*v6)) == 0) return row.InterfaceIndex;
  }
  return 0;
}

template <class T> class PendingRequests {
public:
  void* Retain(std::shared_ptr<T> value) {
    std::scoped_lock lock(mutex_);
    const auto id = next_++;
    entries_.emplace(id, std::move(value));
    return reinterpret_cast<void*>(id);
  }

  std::shared_ptr<T> Find(void* cookie) {
    std::scoped_lock lock(mutex_);
    const auto found = entries_.find(reinterpret_cast<std::uintptr_t>(cookie));
    return found == entries_.end() ? nullptr : found->second;
  }

  void Release(void* cookie) {
    std::scoped_lock lock(mutex_);
    entries_.erase(reinterpret_cast<std::uintptr_t>(cookie));
  }

private:
  // Callbacks use opaque cookies so a delayed platform completion cannot dereference canceled request storage.
  std::mutex mutex_;
  std::uintptr_t next_ = 1;
  std::map<std::uintptr_t, std::shared_ptr<T>> entries_;
};

struct BrowseRequest {
  std::mutex mutex;
  std::wstring query;
  std::string type;
  std::map<std::string, DiscoveredService, std::less<>> services;
  DWORD error = ERROR_SUCCESS;
  DNS_SERVICE_CANCEL cancel{};
};

PendingRequests<BrowseRequest>& Browsing() { static PendingRequests<BrowseRequest> requests; return requests; }

void WINAPI OnBrowse(DWORD status, void* cookie, PDNS_RECORD records) noexcept {
  struct Records {
    PDNS_RECORD value;
    ~Records() { if (value) DnsRecordListFree(value, DnsFreeRecordList); }
  } owned{records};
  auto state = Browsing().Find(cookie);
  if (!state) return;
  std::scoped_lock lock(state->mutex);
  if (status != ERROR_SUCCESS && status != DNS_INFO_NO_RECORDS && status != ERROR_CANCELLED) state->error = status;
  try {
    for (auto* record = reinterpret_cast<PDNS_RECORDW>(records); record; record = record->pNext) {
      if (record->wType != DNS_TYPE_PTR || !record->Data.PTR.pNameHost) continue;
      const std::wstring_view full = record->Data.PTR.pNameHost;
      const auto separator = full.find(L'.');
      if (separator == std::wstring_view::npos) continue;
      auto key = Utf8(full);
      if (!key.empty() && key.back() == '.') key.pop_back();
      if (record->dwTtl == 0) {
        state->services.erase(key);
      } else if (state->services.size() < 128) {
        state->services.try_emplace(key, DiscoveredService{Utf8(full.substr(0, separator)), state->type, key, 0});
      }
    }
  } catch (...) {
    state->error = ERROR_OUTOFMEMORY;
  }
}

struct ResolveRequest {
  std::mutex mutex;
  std::wstring query;
  DNS_SERVICE_CANCEL cancel{};
  std::optional<NetworkResult<ResolvedService>> result;
};

PendingRequests<ResolveRequest>& Resolving() { static PendingRequests<ResolveRequest> requests; return requests; }

void WINAPI OnResolve(DWORD status, void* cookie, PDNS_SERVICE_INSTANCE value) noexcept {
  Instance instance(value, DnsServiceFreeInstance);
  auto state = Resolving().Find(cookie);
  if (!state) return;
  std::scoped_lock lock(state->mutex);
  using Result = NetworkResult<ResolvedService>;
  try {
    if (status != ERROR_SUCCESS || !instance || instance->wPort == 0) {
      state->result = Result::Failure(Error(status, "Could not resolve the DNS-SD service."));
      return;
    }
    ResolvedService service;
    std::array<char, INET6_ADDRSTRLEN> address{};
    if (instance->ip4Address && InetNtopA(AF_INET, instance->ip4Address, address.data(), address.size())) {
      service.endpoints.push_back({address.data(), instance->wPort});
    }
    if (instance->ip6Address && InetNtopA(AF_INET6, instance->ip6Address, address.data(), address.size())) {
      std::string host = address.data();
      if (IN6_IS_ADDR_LINKLOCAL(reinterpret_cast<const IN6_ADDR*>(instance->ip6Address))) {
        if (instance->dwInterfaceIndex != 0) host += "%" + std::to_string(instance->dwInterfaceIndex);
        else host.clear();
      }
      if (!host.empty()) service.endpoints.push_back({std::move(host), instance->wPort});
    }
    state->result = service.endpoints.empty() ? Result::Failure(Error(0, "The service has no usable addresses."))
                                             : Result::Success(std::move(service));
  } catch (...) {
    state->result = Result::Failure(Error(ERROR_OUTOFMEMORY, "Could not retain the DNS-SD service addresses."));
  }
}

class WindowsPublication final : public PublicationState, public std::enable_shared_from_this<WindowsPublication> {
public:
  explicit WindowsPublication(Instance instance) : interface_(instance->dwInterfaceIndex), instance_(std::move(instance)) {}

  DWORD Start() {
    registration_ = Requests().Retain(shared_from_this());
    DNS_SERVICE_REGISTER_REQUEST request{
        DNS_QUERY_REQUEST_VERSION1, interface_, instance_.get(), OnRegister, registration_, nullptr, FALSE};
    const auto status = DnsServiceRegister(&request, &cancel_);
    if (status != DNS_REQUEST_PENDING) {
      Requests().Release(registration_);
      status_ = status;
    }
    return status;
  }

  DWORD Status() const {
    std::scoped_lock lock(mutex_);
    return status_;
  }

  void Close() noexcept override {
    DWORD status;
    {
      std::scoped_lock lock(mutex_);
      if (std::exchange(closed_, true)) return;
      status = status_;
    }
    if (status == ERROR_SUCCESS) Withdraw();
    if (status == DNS_REQUEST_PENDING && DnsServiceRegisterCancel(&cancel_) == ERROR_SUCCESS) {
      Requests().Release(registration_);
    }
  }

private:
  static PendingRequests<WindowsPublication>& Requests() {
    static PendingRequests<WindowsPublication> requests;
    return requests;
  }

  static void WINAPI OnRegister(DWORD status, void* cookie, PDNS_SERVICE_INSTANCE value) noexcept {
    auto self = Requests().Find(cookie);
    Requests().Release(cookie);
    if (!self) {
      if (value) DnsServiceFreeInstance(value);
      return;
    }
    bool closed;
    {
      std::scoped_lock lock(self->mutex_);
      if (value && value != self->instance_.get()) self->instance_.reset(value);
      // Keep withdrawal on the same interface when the system returns a replacement instance.
      self->instance_->dwInterfaceIndex = self->interface_;
      self->status_ = status;
      closed = self->closed_;
    }
    if (closed && status == ERROR_SUCCESS) self->Withdraw();
  }

  static void WINAPI OnWithdraw(DWORD, void* cookie, PDNS_SERVICE_INSTANCE value) noexcept {
    auto self = Requests().Find(cookie);
    if (value && (!self || value != self->instance_.get())) DnsServiceFreeInstance(value);
    Requests().Release(cookie);
  }

  void Withdraw() noexcept {
    try {
      const auto cookie = Requests().Retain(shared_from_this());
      DNS_SERVICE_REGISTER_REQUEST request{
          DNS_QUERY_REQUEST_VERSION1, interface_, instance_.get(), OnWithdraw, cookie, nullptr, FALSE};
      if (DnsServiceDeRegister(&request, &withdrawal_) != DNS_REQUEST_PENDING) Requests().Release(cookie);
    } catch (...) {
    }
  }

  const DWORD interface_;
  Instance instance_;
  mutable std::mutex mutex_;
  DWORD status_ = DNS_REQUEST_PENDING;
  bool closed_ = false;
  DNS_SERVICE_CANCEL cancel_{};
  DNS_SERVICE_CANCEL withdrawal_{};
  void* registration_ = nullptr;
};

} // namespace

Task<NetworkResult<std::vector<DiscoveredService>>> BrowsePlatformServices(std::string type,
                                                                           std::chrono::milliseconds observation) {
  using Result = NetworkResult<std::vector<DiscoveredService>>;
  auto state = std::make_shared<BrowseRequest>();
  state->type = std::move(type);
  state->query = Wide(state->type + ".local");
  const auto cookie = Browsing().Retain(state);
  struct Request {
    BrowseRequest& state;
    void* cookie;
    bool started = false;
    ~Request() {
      if (started) DnsServiceBrowseCancel(&state.cancel);
      Browsing().Release(cookie);
    }
  } owned{*state, cookie};
  DNS_SERVICE_BROWSE_REQUEST request{DNS_QUERY_REQUEST_VERSION1, 0, state->query.c_str(), {OnBrowse}, cookie};
  const auto status = DnsServiceBrowse(&request, &state->cancel);
  if (status != DNS_REQUEST_PENDING) co_return Result::Failure(Error(status, "Could not browse for DNS-SD services."));
  owned.started = true;
  co_await Delay(observation);
  std::scoped_lock lock(state->mutex);
  if (state->error != ERROR_SUCCESS) co_return Result::Failure(Error(state->error, "DNS-SD browsing failed."));
  std::vector<DiscoveredService> entries;
  for (auto& [key, service] : state->services) entries.push_back(std::move(service));
  co_return Result::Success(std::move(entries));
}

Task<NetworkResult<ResolvedService>> ResolvePlatformService(DiscoveredService service) {
  using Result = NetworkResult<ResolvedService>;
  auto state = std::make_shared<ResolveRequest>();
  state->query = Wide(service.instance);
  if (state->query.empty() || service.scope > std::numeric_limits<DWORD>::max()) {
    co_return Result::Failure(Error(ERROR_INVALID_PARAMETER, "Invalid DNS-SD instance name."));
  }
  const auto cookie = Resolving().Retain(state);
  struct Request {
    ResolveRequest& state;
    void* cookie;
    bool pending = false;
    ~Request() {
      if (pending) DnsServiceResolveCancel(&state.cancel);
      Resolving().Release(cookie);
    }
  } owned{*state, cookie};
  DNS_SERVICE_RESOLVE_REQUEST request{DNS_QUERY_REQUEST_VERSION1, static_cast<DWORD>(service.scope), state->query.data(),
                                      OnResolve, cookie};
  const auto status = DnsServiceResolve(&request, &state->cancel);
  if (status != DNS_REQUEST_PENDING) co_return Result::Failure(Error(status, "Could not resolve the DNS-SD service."));
  owned.pending = true;
  const auto expires = Clock::now() + 8s;
  while (Clock::now() < expires) {
    {
      std::scoped_lock lock(state->mutex);
      if (state->result) {
        owned.pending = false;
        co_return std::move(*state->result);
      }
    }
    co_await Delay(20ms);
  }
  co_return Result::Failure({NetworkErrorCode::TimedOut, 0, "DNS-SD resolution timed out."});
}

Task<NetworkResult<std::shared_ptr<PublicationState>>> PublishPlatformService(ServiceAnnouncement announcement) {
  using Result = NetworkResult<std::shared_ptr<PublicationState>>;
  std::array<wchar_t, 256> host_name{};
  DWORD host_size = static_cast<DWORD>(host_name.size());
  if (!GetComputerNameExW(ComputerNameDnsHostname, host_name.data(), &host_size)) {
    co_return Result::Failure(Error(GetLastError(), "Could not obtain the system DNS host name."));
  }
  std::wstring host(host_name.data(), host_size);
  host += L".local";
  const auto service = Wide(announcement.name + "." + announcement.type + ".local");
  const auto address = Wide(announcement.endpoint.host);
  IP4_ADDRESS ip4{};
  IP6_ADDRESS ip6{};
  auto* v4 = InetPtonW(AF_INET, address.c_str(), &ip4) == 1 ? &ip4 : nullptr;
  auto* v6 = InetPtonW(AF_INET6, address.c_str(), &ip6) == 1 ? &ip6 : nullptr;
  const auto* ipv6 = reinterpret_cast<const IN6_ADDR*>(&ip6);
  if (service.empty() || (!v4 && !v6) || (v4 && (ip4 == INADDR_ANY || (ntohl(ip4) >> 24) == 127)) ||
      (v6 && (IN6_IS_ADDR_UNSPECIFIED(ipv6) || IN6_IS_ADDR_LOOPBACK(ipv6)))) {
    co_return Result::Failure(Error(ERROR_INVALID_PARAMETER, "DNS-SD publication requires a concrete bind address."));
  }
  Instance value(DnsServiceConstructInstance(service.c_str(), host.c_str(), v4, v6, announcement.endpoint.port,
                                              0, 0, 0, nullptr, nullptr), DnsServiceFreeInstance);
  if (!value) co_return Result::Failure(Error(GetLastError(), "Could not construct the DNS-SD registration."));
  // A registration on every interface can resolve to a VPN address even though the listener only accepts Wi-Fi.
  value->dwInterfaceIndex = BindInterface(v4, v6);
  if (value->dwInterfaceIndex == 0) {
    co_return Result::Failure(Error(ERROR_NOT_FOUND, "The listener address is not on an active network interface."));
  }
  auto publication = std::make_shared<WindowsPublication>(std::move(value));
  struct Registration {
    WindowsPublication& publication;
    bool transferred = false;
    ~Registration() { if (!transferred) publication.Close(); }
  } owned{*publication};
  publication->Start();
  const auto expires = Clock::now() + 8s;
  while (Clock::now() < expires) {
    const auto status = publication->Status();
    if (status == ERROR_SUCCESS) {
      owned.transferred = true;
      co_return Result::Success(std::move(publication));
    }
    if (status != DNS_REQUEST_PENDING) co_return Result::Failure(Error(status, "DNS-SD publication failed."));
    co_await Delay(20ms);
  }
  co_return Result::Failure({NetworkErrorCode::TimedOut, 0, "DNS-SD publication timed out."});
}

} // namespace huxerui::localnetwork::detail
