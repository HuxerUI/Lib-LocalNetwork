#pragma once

#include <huxerui/local_network_wifi.h>

#include <string_view>
#include <utility>

namespace huxerui::localnetwork::detail {

class WifiNetworkState {
public:
  virtual ~WifiNetworkState() = default;
  virtual std::optional<std::uint64_t> AndroidNetwork() const noexcept = 0;
};

struct WifiNetworkAccess {
  static std::shared_ptr<const WifiNetworkLease> Create(std::shared_ptr<WifiNetworkState> state) {
    return std::shared_ptr<const WifiNetworkLease>(new WifiNetworkLease(std::move(state)));
  }
  static const std::shared_ptr<WifiNetworkState>& State(const WifiNetworkLease& lease) { return lease.state_; }
};

bool ValidWifiSsid(std::string_view ssid);
Task<NetworkResult<WifiScanResult>> ScanPlatformWifi();
Task<NetworkResult<WifiJoinResult>> JoinPlatformWifi(WifiJoinRequest request);
#if defined(_WIN32) || defined(HUXERUI_LOCALNETWORK_GIO)
Task<NetworkResult<WifiJoinResult>> JoinPlatformWifiProfile(std::string profile);
#endif
#ifdef __ANDROID__
Task<NetworkResult<std::shared_ptr<const WifiNetworkLease>>> SelectPlatformWifiRoute(std::string ssid);
Task<NetworkResult<HttpResponse>> SendPlatformWifiHttp(
    HttpRequest request, std::shared_ptr<const WifiNetworkLease> network);
#endif
void InstallPlatformWifi(ApplicationContext& context);

} // namespace huxerui::localnetwork::detail
