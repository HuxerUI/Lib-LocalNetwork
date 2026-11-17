#include "wifi_backend.h"
#include "utf8.h"

#ifdef __APPLE__
#include <TargetConditionals.h>
#endif

#include <algorithm>

namespace huxerui::localnetwork::detail {

bool ValidWifiSsid(std::string_view ssid) {
  return !ssid.empty() && ssid.size() <= 32 && ValidUtf8Text(ssid);
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

constexpr std::size_t max_http_body = 1024 * 1024;

bool ValidHttpHeader(const HttpHeader& header) {
  constexpr std::string_view punctuation = "!#$%&'*+-.^_`|~";
  return !header.name.empty() && header.name.size() <= 256 && header.value.size() <= 8192 &&
      std::ranges::all_of(header.name, [punctuation](char ch) {
        return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
               (ch >= '0' && ch <= '9') || punctuation.find(ch) != std::string_view::npos;
      }) && header.value.find_first_of("\r\n") == std::string::npos && detail::ValidUtf8Text(header.value);
}

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

Task<NetworkResult<std::shared_ptr<const WifiNetworkLease>>> SelectWifiRouteAsync(std::string ssid) {
  using Result = NetworkResult<std::shared_ptr<const WifiNetworkLease>>;
  if (!detail::ValidWifiSsid(ssid)) {
    co_return Result::Failure({NetworkErrorCode::InvalidWifiConfiguration, 0, "Enter a valid Wi-Fi network name."});
  }
#ifdef __ANDROID__
  co_return co_await detail::SelectPlatformWifiRoute(std::move(ssid));
#else
  co_return Result::Failure({NetworkErrorCode::Unsupported, 0, "Selecting an app-scoped Wi-Fi route requires Android."});
#endif
}

Task<NetworkResult<WifiJoinResult>> JoinSavedWifiProfileAsync(std::string profile) {
  using Result = NetworkResult<WifiJoinResult>;
  if (profile.empty() || profile.size() > 1020 || !detail::ValidUtf8Text(profile)) {
    co_return Result::Failure({NetworkErrorCode::InvalidWifiConfiguration, 0, "Invalid Wi-Fi profile identifier."});
  }
#if defined(_WIN32) || defined(HUXERUI_LOCALNETWORK_GIO)
  co_return co_await detail::JoinPlatformWifiProfile(std::move(profile));
#else
  co_return Result::Failure({NetworkErrorCode::Unsupported, 0, "Activate the Wi-Fi profile in system settings."});
#endif
}

Task<NetworkResult<HttpResponse>> SendWifiHttpAsync(HttpRequest request, std::shared_ptr<const WifiNetworkLease> network) {
  using Result = NetworkResult<HttpResponse>;
  if (request.url.size() > 8192 || !detail::ValidUtf8Text(request.url) ||
      !(request.url.starts_with("http://") || request.url.starts_with("https://")) ||
      !request.timeout || *request.timeout <= std::chrono::milliseconds::zero() ||
      *request.timeout > std::chrono::minutes(10) || request.body.size() > max_http_body ||
      request.headers.size() > 128 || !std::ranges::all_of(request.headers, ValidHttpHeader) ||
      ((request.method == HttpMethod::Get || request.method == HttpMethod::Head) && !request.body.empty())) {
    co_return Result::Failure({NetworkErrorCode::InvalidEndpoint, 0, "Invalid accessory HTTP request."});
  }
#ifdef __ANDROID__
  if (!network || !network->AndroidNetwork()) {
    co_return Result::Failure({NetworkErrorCode::NetworkLost, 0, "The selected Wi-Fi network was lost."});
  }
  co_return co_await detail::SendPlatformWifiHttp(std::move(request), std::move(network));
#else
  co_return Result::Failure({NetworkErrorCode::Unsupported, 0, "Wi-Fi-bound HTTP requires Android."});
#endif
}

} // namespace huxerui::localnetwork
