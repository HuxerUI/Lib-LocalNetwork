#if defined(__ANDROID__) && !defined(__ANDROID_UNAVAILABLE_SYMBOLS_ARE_WEAK__)
// Interface enumeration is guarded at runtime. Keep this translation unit loadable on API 23.
#define __ANDROID_UNAVAILABLE_SYMBOLS_ARE_WEAK__
#endif

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#elif !defined(__EMSCRIPTEN__)
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include "socket_io.h"

#include <cstring>

namespace huxerui::localnetwork::detail {

#ifndef __EMSCRIPTEN__
namespace {

bool SameAddress(const sockaddr& first, const sockaddr& second) noexcept {
  if (first.sa_family != second.sa_family) return false;
  if (first.sa_family == AF_INET) {
    return reinterpret_cast<const sockaddr_in&>(first).sin_addr.s_addr ==
           reinterpret_cast<const sockaddr_in&>(second).sin_addr.s_addr;
  }
  return std::memcmp(&reinterpret_cast<const sockaddr_in6&>(first).sin6_addr,
                     &reinterpret_cast<const sockaddr_in6&>(second).sin6_addr, sizeof(in6_addr)) == 0;
}

#ifdef _WIN32
std::optional<std::uint32_t> FindInterface(const sockaddr& address) noexcept {
  MIB_UNICASTIPADDRESS_TABLE* listed = nullptr;
  if (GetUnicastIpAddressTable(address.sa_family, &listed) != NO_ERROR || !listed) return {};
  const std::unique_ptr<MIB_UNICASTIPADDRESS_TABLE, decltype(&FreeMibTable)> interfaces(listed, FreeMibTable);
  std::optional<std::uint32_t> match;
  for (ULONG i = 0; i < interfaces->NumEntries; ++i) {
    const auto& row = interfaces->Table[i];
    if (!row.InterfaceIndex || !SameAddress(address, reinterpret_cast<const sockaddr&>(row.Address))) continue;
    if (match && *match != row.InterfaceIndex) return {};
    match = row.InterfaceIndex;
  }
  return match;
}
#else
std::optional<std::uint32_t> FindInterface(const sockaddr& address, const ifaddrs* listed) noexcept {
  std::optional<std::uint32_t> match;
  for (auto* row = listed; row; row = row->ifa_next) {
    if (!row->ifa_addr || !row->ifa_name || !SameAddress(address, *row->ifa_addr)) continue;
    const auto index = if_nametoindex(row->ifa_name);
    if (index == 0) continue;
    if (match && *match != index) return {};
    match = index;
  }
  return match;
}

std::optional<std::uint32_t> FindInterface(const sockaddr& address) noexcept {
#ifdef __ANDROID__
  if (__builtin_available(android 24, *)) {
#else
  {
#endif
    ifaddrs* listed = nullptr;
    if (getifaddrs(&listed) != 0 || !listed) return {};
    const std::unique_ptr<ifaddrs, decltype(&freeifaddrs)> interfaces(listed, freeifaddrs);
    return FindInterface(address, interfaces.get());
  }
#ifdef __ANDROID__
  return {};
#endif
}
#endif

} // namespace

std::optional<std::uint32_t> LocalInterfaceIndex(const sockaddr& address) noexcept {
  if (address.sa_family == AF_INET) return FindInterface(address);
  if (address.sa_family != AF_INET6) return {};

  const auto& ipv6 = reinterpret_cast<const sockaddr_in6&>(address);
  if (IN6_IS_ADDR_LINKLOCAL(&ipv6.sin6_addr)) {
#ifdef _WIN32
    const auto index = ipv6.sin6_scope_struct.Zone;
#else
    const auto index = ipv6.sin6_scope_id;
#endif
    if (index != 0) return index;
  }
  if (IN6_IS_ADDR_V4MAPPED(&ipv6.sin6_addr)) {
    // A dual-stack listener can report the local IPv4 address in mapped IPv6 form.
    sockaddr_in ipv4{};
    ipv4.sin_family = AF_INET;
    const auto* bytes = reinterpret_cast<const unsigned char*>(&ipv6.sin6_addr);
    std::memcpy(&ipv4.sin_addr, bytes + 12, sizeof(ipv4.sin_addr));
    return FindInterface(reinterpret_cast<const sockaddr&>(ipv4));
  }
  // A local address may belong to more than one interface. Report an index only for a unique match.
  return FindInterface(address);
}
#endif

} // namespace huxerui::localnetwork::detail
