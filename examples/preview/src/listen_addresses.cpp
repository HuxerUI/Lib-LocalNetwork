#if defined(__ANDROID__) && !defined(__ANDROID_UNAVAILABLE_SYMBOLS_ARE_WEAK__)
// Guard the interface enumeration call at runtime on older Android releases.
#define __ANDROID_UNAVAILABLE_SYMBOLS_ARE_WEAK__
#endif

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#elif !defined(__EMSCRIPTEN__)
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#endif

#include "listen_addresses.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <memory>
#include <tuple>
#include <utility>

namespace local_network_preview {
namespace {

using namespace huxerui;
using namespace huxerui::localnetwork;
using AddressResult = NetworkResult<std::vector<ListenAddress>>;

#ifndef __EMSCRIPTEN__
bool IsInvitationIpv4(const in_addr& address) {
  const auto value = ntohl(address.s_addr);
  return value != 0 && (value >> 24) != 127 && (value >> 28) < 14;
}

bool IsInvitationIpv6(const in6_addr& address) {
  // A link-local IPv6 scope identifies an interface on the originating device.
  return !IN6_IS_ADDR_UNSPECIFIED(&address) && !IN6_IS_ADDR_LOOPBACK(&address) &&
         !IN6_IS_ADDR_LINKLOCAL(&address) && !IN6_IS_ADDR_MULTICAST(&address) &&
         !IN6_IS_ADDR_V4MAPPED(&address);
}

void AddAddress(std::vector<ListenAddress>& addresses, const sockaddr& address, const std::string& name) {
  std::array<char, INET6_ADDRSTRLEN> host{};
  if (address.sa_family == AF_INET) {
    const auto& ipv4 = reinterpret_cast<const sockaddr_in&>(address).sin_addr;
    if (!IsInvitationIpv4(ipv4) || !inet_ntop(AF_INET, &ipv4, host.data(), host.size())) return;
  } else if (address.sa_family == AF_INET6) {
    const auto& ipv6 = reinterpret_cast<const sockaddr_in6&>(address).sin6_addr;
    if (!IsInvitationIpv6(ipv6) || !inet_ntop(AF_INET6, &ipv6, host.data(), host.size())) return;
  } else {
    return;
  }
  addresses.push_back({host.data(), name});
}

#ifdef _WIN32
std::string InterfaceName(const IP_ADAPTER_ADDRESSES& adapter) {
  if (adapter.FriendlyName) {
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, adapter.FriendlyName, -1, nullptr, 0,
                                         nullptr, nullptr);
    if (size > 1) {
      std::string name(static_cast<std::size_t>(size), '\0');
      if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, adapter.FriendlyName, -1, name.data(), size,
                             nullptr, nullptr) != 0) {
        name.pop_back();
        return name;
      }
    }
  }
  return adapter.AdapterName ? adapter.AdapterName : "";
}

AddressResult EnumerateAddresses() {
  constexpr ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
  ULONG size = 15 * 1024;
  std::vector<unsigned char> buffer(size);
  auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
  auto status = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, adapters, &size);
  // Adapter configuration can change while the system reports the required buffer size.
  for (int attempt = 0; status == ERROR_BUFFER_OVERFLOW && attempt < 2; ++attempt) {
    buffer.resize(size);
    adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
    status = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, adapters, &size);
  }
  if (status == ERROR_NO_DATA) return AddressResult::Success({});
  if (status != NO_ERROR)
    return AddressResult::Failure({NetworkErrorCode::System, static_cast<int>(status), "Could not list local addresses."});

  std::vector<ListenAddress> addresses;
  for (auto* adapter = adapters; adapter; adapter = adapter->Next) {
    if (adapter->OperStatus != IfOperStatusUp || adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK ||
        adapter->IfType == IF_TYPE_TUNNEL || adapter->IfType == IF_TYPE_PPP ||
        adapter->IfType == IF_TYPE_WWANPP || adapter->IfType == IF_TYPE_WWANPP2) continue;
    const auto name = InterfaceName(*adapter);
    for (auto* entry = adapter->FirstUnicastAddress; entry; entry = entry->Next) {
      if (entry->Address.lpSockaddr && entry->DadState == IpDadStatePreferred)
        AddAddress(addresses, *entry->Address.lpSockaddr, name);
    }
  }
  return AddressResult::Success(std::move(addresses));
}
#else
AddressResult EnumerateAddresses() {
#ifdef __ANDROID__
  if (!__builtin_available(android 24, *)) {
    return AddressResult::Failure({NetworkErrorCode::Unsupported, 0, "Local address listing is unavailable."});
  }
#endif
  ifaddrs* listed = nullptr;
  if (getifaddrs(&listed) != 0)
    return AddressResult::Failure({NetworkErrorCode::System, errno, "Could not list local addresses."});
  const std::unique_ptr<ifaddrs, decltype(&freeifaddrs)> interfaces(listed, freeifaddrs);

  constexpr auto active = IFF_UP | IFF_RUNNING;
  std::vector<ListenAddress> addresses;
  for (auto* entry = interfaces.get(); entry; entry = entry->ifa_next) {
    if (!entry->ifa_addr || !entry->ifa_name || (entry->ifa_flags & active) != active ||
        (entry->ifa_flags & (IFF_LOOPBACK | IFF_POINTOPOINT))) continue;
    AddAddress(addresses, *entry->ifa_addr, entry->ifa_name);
  }
  return AddressResult::Success(std::move(addresses));
}
#endif
#endif

} // namespace

bool IsInvitationAddress(const std::string& host) {
#ifndef __EMSCRIPTEN__
  if (host.size() >= INET6_ADDRSTRLEN || host.find('\0') != std::string::npos) return false;
  in_addr ipv4{};
  if (inet_pton(AF_INET, host.c_str(), &ipv4) == 1) return IsInvitationIpv4(ipv4);
  in6_addr ipv6{};
  return inet_pton(AF_INET6, host.c_str(), &ipv6) == 1 && IsInvitationIpv6(ipv6);
#else
  return false;
#endif
}

Task<AddressResult> ListListenAddressesAsync() {
#ifndef __EMSCRIPTEN__
  auto result = co_await RunWorker(EnumerateAddresses);
  if (!result.Succeeded()) co_return result;
  auto& addresses = result.Value();
  const auto key = [](const ListenAddress& entry) { return std::tie(entry.interface_name, entry.host); };
  std::ranges::sort(addresses, {}, key);
  const auto duplicates = std::ranges::unique(addresses, {}, key);
  addresses.erase(duplicates.begin(), duplicates.end());
  co_return result;
#else
  co_return AddressResult::Failure({NetworkErrorCode::Unsupported, 0, "Local address listing is unavailable."});
#endif
}

} // namespace local_network_preview
