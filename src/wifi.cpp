#include "wifi_backend.h"

#ifdef __APPLE__
#include <TargetConditionals.h>
#endif

#include <algorithm>

namespace huxerui::localnetwork::detail {

bool ValidWifiSsid(std::string_view ssid) {
  if (ssid.empty() || ssid.size() > 32) return false;
  for (std::size_t i = 0; i < ssid.size();) {
    const auto first = static_cast<unsigned char>(ssid[i++]);
    if (first == 0) return false;
    if (first < 0x80) continue;
    if (first < 0xC2 || first > 0xF4) return false;
    const std::size_t trailing = first < 0xE0 ? 1 : first < 0xF0 ? 2 : 3;
    if (ssid.size() - i < trailing) return false;
    const auto next = static_cast<unsigned char>(ssid[i]);
    if ((first == 0xE0 && next < 0xA0) || (first == 0xED && next >= 0xA0) ||
        (first == 0xF0 && next < 0x90) || (first == 0xF4 && next >= 0x90)) return false;
    for (std::size_t j = 0; j < trailing; ++j) {
      if ((static_cast<unsigned char>(ssid[i++]) & 0xC0) != 0x80) return false;
    }
  }
  return true;
}

} // namespace huxerui::localnetwork::detail

namespace huxerui::localnetwork {
namespace {

#if defined(_WIN32) || defined(__ANDROID__) || defined(HUXERUI_LOCALNETWORK_GIO) || \
    (defined(__APPLE__) && TARGET_OS_OSX)
constexpr bool wifi_scan_supported = true;
#else
constexpr bool wifi_scan_supported = false;
#endif

#if defined(__APPLE__) && TARGET_OS_IOS
constexpr bool wifi_join_supported = true;
#else
constexpr bool wifi_join_supported = wifi_scan_supported;
#endif

} // namespace

WifiNetworkLease::WifiNetworkLease(std::shared_ptr<detail::WifiNetworkState> state) : state_(std::move(state)) {}

std::optional<std::uint64_t> WifiNetworkLease::AndroidNetwork() const noexcept { return state_->AndroidNetwork(); }

bool IsWifiScanSupported() noexcept { return wifi_scan_supported; }

bool IsWifiJoinSupported() noexcept { return wifi_join_supported; }

Task<NetworkResult<WifiScanResult>> ScanWifiAsync() {
  using Result = NetworkResult<WifiScanResult>;
  if constexpr (wifi_scan_supported) {
    auto scan = co_await detail::ScanPlatformWifi();
    if (!scan.Succeeded()) co_return scan;
    auto& networks = scan.Value().networks;
    std::erase_if(networks, [](const auto& network) { return !detail::ValidWifiSsid(network.ssid); });
    const auto key = [](const auto& network) {
      return std::pair<std::string_view, WifiSecurity>{network.ssid, network.security};
    };
    std::ranges::sort(networks, {}, key);
    const auto duplicates = std::ranges::unique(networks, {}, key);
    networks.erase(duplicates.begin(), duplicates.end());
    co_return scan;
  } else {
    co_return Result::Failure({NetworkErrorCode::Unsupported, 0, "Open system Wi-Fi settings to view available networks."});
  }
}

Task<NetworkResult<WifiJoinResult>> JoinWifiAsync(WifiJoinRequest request) {
  using Result = NetworkResult<WifiJoinResult>;
  if (!detail::ValidWifiSsid(request.ssid)) {
    co_return Result::Failure({NetworkErrorCode::InvalidWifiConfiguration, 0, "Enter a valid Wi-Fi network name."});
  }
  if (request.security == WifiSecurity::Other) {
    co_return Result::Failure({NetworkErrorCode::Unsupported, 0, "Join this Wi-Fi network in system settings."});
  }
  const auto& password = request.passphrase;
  if ((request.security == WifiSecurity::Open && !password.empty()) ||
      (request.security != WifiSecurity::Open &&
       (password.size() < 8 || password.size() > 63 ||
        !std::ranges::all_of(password, [](char value) { return value >= 0x20 && value <= 0x7E; })))) {
    co_return Result::Failure({NetworkErrorCode::InvalidWifiConfiguration, 0, "Enter a valid Wi-Fi passphrase."});
  }
  if constexpr (wifi_join_supported) {
    co_return co_await detail::JoinPlatformWifi(std::move(request));
  } else {
    co_return Result::Failure({NetworkErrorCode::Unsupported, 0, "Join the hotspot in system Wi-Fi settings."});
  }
}

} // namespace huxerui::localnetwork
