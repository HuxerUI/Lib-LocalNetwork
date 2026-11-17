#pragma once

/// @file
/// @brief Nearby Wi-Fi networks and association with a known Wi-Fi hotspot.
///
/// Include <huxerui/local_network_wifi.h> and link HuxerUI::LocalNetwork. Launch the tasks from a
/// foreground application TaskScope. The host requests any runtime permissions and provides a
/// system Wi-Fi settings entry when the platform cannot perform an operation.

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <huxerui/local_network_common.h>
#include <huxerui/task.h>

namespace huxerui::localnetwork {

/// @brief Authentication supported by a nearby Wi-Fi network or requested for association.
enum class WifiSecurity {
  Open,         ///< No authentication.
  Wpa2Personal, ///< WPA2-Personal, including transition networks that accept WPA2.
  Wpa3Personal, ///< WPA3-Personal with SAE.
  Other,        ///< Security observed in a scan that needs a system Wi-Fi profile.
};

/// @brief One visible network, grouped by SSID and security when several access points advertise it.
struct WifiNetwork {
  /// Exact UTF-8 SSID. The list omits hidden names and SSIDs that cannot be represented as UTF-8.
  std::string ssid;
  /// Authentication reported by the platform.
  WifiSecurity security = WifiSecurity::Other;
};

/// @brief Nearby networks returned by a bounded scan.
struct WifiScanResult {
  /// Visible Wi-Fi networks. An empty list is a valid result.
  std::vector<WifiNetwork> networks;
  /// True if at least one adapter completed a scan during this call.
  bool refreshed = false;
};

/// @brief Requested lifetime of a Wi-Fi configuration.
enum class WifiJoinMode {
  PlatformDefault, ///< Use the documented platform policy for the connection.
  Temporary,       ///< Join without saving a persistent configuration.
  Persistent,      ///< Ask the system to keep the configuration.
};

/// @brief Credentials for a visible, known Wi-Fi hotspot.
struct WifiJoinRequest {
  /// Exact SSID as UTF-8, between 1 and 32 bytes. Do not include surrounding quotes.
  std::string ssid;
  /// Authentication scheme of the hotspot.
  WifiSecurity security = WifiSecurity::Open;
  /// Printable ASCII passphrase, 8 to 63 bytes for WPA2 or WPA3. Leave empty for an open network.
  std::string passphrase;
  /// An explicit mode fails if the platform cannot honor it.
  WifiJoinMode mode = WifiJoinMode::PlatformDefault;
};

/// @brief What the system could confirm after a join request.
enum class WifiJoinStatus {
  Associated,            ///< The system reported association with the requested SSID.
  ConfigurationAccepted, ///< The system accepted the configuration. Association could not be confirmed.
};

namespace detail {
class WifiNetworkState;
struct WifiNetworkAccess;
}

/// @brief Keeps an app-scoped Android Wi-Fi network request active.
///
/// Pass this lease through TcpDialOptions::wifi_network to bind DNS and sockets to that network.
/// A dial retains the lease for the connection's lifetime. After the system loses the network, obtain a new lease
/// by joining again. Release all owners of a lease to release its system request.
class WifiNetworkLease final {
public:
  /// A lease is shared through the handle returned by JoinWifiAsync().
  WifiNetworkLease(const WifiNetworkLease&) = delete;
  /// Ownership of a lease is transferred by copying or moving its shared handle.
  WifiNetworkLease& operator=(const WifiNetworkLease&) = delete;

  /// Returns the Android system network handle while the requested network is available.
  std::optional<std::uint64_t> AndroidNetwork() const noexcept;

private:
  explicit WifiNetworkLease(std::shared_ptr<detail::WifiNetworkState> state);
  std::shared_ptr<detail::WifiNetworkState> state_;
  friend struct detail::WifiNetworkAccess;
};

/// @brief Confirmed association or accepted configuration, with an app-scoped route when available.
struct WifiJoinResult {
  /// Whether the system could confirm association.
  WifiJoinStatus status;
  /// Set for successful Android app-scoped joins with a usable network address.
  std::shared_ptr<const WifiNetworkLease> network;
};

/// @brief Reports whether the build includes a Wi-Fi scan adapter.
/// @return True on supported Windows, macOS, Linux, and Android builds. Runtime permission and adapter checks
/// happen during scanning. iOS and Web hosts use system Wi-Fi settings.
bool IsWifiScanSupported() noexcept;

/// @brief Reports whether the build includes an adapter for joining a known Wi-Fi network.
/// @return True when the platform provides a join path. Permission, radio state, and per-mode support are
/// checked when joining. Web hosts use system Wi-Fi settings.
bool IsWifiJoinSupported() noexcept;

/// @brief Requests a scan and returns available nearby Wi-Fi networks.
///
/// Android requires ACCESS_FINE_LOCATION and enabled system Location for scan results.
/// Windows and macOS can also require location authorization. Linux uses NetworkManager when configured.
/// @return A lazy task yielding the visible list and its freshness, or a NetworkError.
Task<NetworkResult<WifiScanResult>> ScanWifiAsync();

/// @brief Requests association with a known Wi-Fi hotspot.
///
/// The system can ask the user to approve the request. Some platforms can switch the device's current Wi-Fi.
/// For Android joins, request NEARBY_WIFI_DEVICES on Android 13 and later, or location access on earlier releases.
/// iOS hosts need the Hotspot Configuration entitlement. The Wi-Fi Information entitlement can enable SSID verification.
/// Canceling stops result delivery. A device-wide association already submitted to the system can still complete.
/// An Android app-scoped request is released on cancellation. Use the Wi-Fi lease for subsequent Android dials.
/// @param request Exact SSID, security, passphrase, and requested configuration lifetime.
/// @return A lazy task yielding the observed join status and an Android route if applicable, or a NetworkError.
Task<NetworkResult<WifiJoinResult>> JoinWifiAsync(WifiJoinRequest request);

} // namespace huxerui::localnetwork
