#pragma once

/// @file
/// @brief Shared endpoint, error, and application integration declarations for Lib-LocalNetwork.
///
/// Link HuxerUI::LocalNetwork. Each capability header exposes these shared declarations.

#include <cstdint>
#include <optional>
#include <string>

#include <huxerui/data.h>

namespace huxerui {
class ApplicationContext;
}

namespace huxerui::localnetwork {

/// @brief A host and TCP port. IPv6 literals use the unbracketed form and may include an interface scope.
struct Endpoint {
  /// Numeric address or ASCII DNS hostname. Listening requires a numeric address.
  std::string host;
  /// TCP port. Zero asks the system to allocate a port for a listener.
  std::uint16_t port = 0;
};

/// @brief Portable failure categories for local network operations.
enum class NetworkErrorCode {
  InvalidEndpoint,  ///< An address, port, or dial option does not meet the operation's requirements.
  Unsupported,      ///< The requested operation or routing constraint is unavailable on this platform.
  ResolveFailed,    ///< The requested host could not be resolved.
  NetworkLost,      ///< A required network is no longer available for binding.
  PermissionDenied, ///< The system or the host's bridge policy denied the operation.
  AddressInUse,     ///< The requested local address and port are in use.
  ConnectionFailed, ///< The socket operation failed before establishing a connection.
  TimedOut,         ///< The operation did not complete by its deadline.
  Closed,           ///< The listener or connection has been closed.
  Busy,             ///< Another operation is pending or the session reached a resource limit.
  InvalidIdentity,  ///< A device credential is invalid or could not be created.
  Authentication,   ///< TLS or peer authentication failed.
  PairingRejected,  ///< A pairing invitation or request was rejected.
  Protocol,         ///< The peer sent an invalid session message.
  System,           ///< An operation failed without a more specific category.
  DiscoveryFailed,  ///< The platform rejected a DNS-SD operation.
  InvalidWifiConfiguration, ///< A Wi-Fi network name or credential is invalid.
  WifiScanFailed,   ///< The system could not provide nearby Wi-Fi networks.
  WifiJoinFailed,   ///< The system could not join the Wi-Fi network.
};

/// @brief An operational failure with a portable category and optional system diagnostic.
struct NetworkError {
  /// Stable category for application decisions.
  NetworkErrorCode code;
  /// Operation-specific diagnostic number from the system or TLS library, or zero when unavailable.
  int diagnostic_code = 0;
  /// Human-readable context. Applications should use code for decisions.
  std::string message;
};

/// Result of a local network operation. Stream operations use IoResult.
template <class T> using NetworkResult = Result<T, NetworkError>;

/// @brief Route information captured when a connection is established.
struct ConnectionPath {
  /// Actual local socket address and port. Empty with port zero when the platform does not expose it.
  Endpoint local;
  /// Actual address and port of the connected socket peer. Empty with port zero when unavailable.
  Endpoint remote;
  /// Platform interface index associated with the local socket address, when it can be identified unambiguously.
  std::optional<std::uint32_t> interface_index;
  /// Android system network handle used to bind this socket, including handles obtained from Wi-Fi leases.
  /// Empty for a socket using the system's default route or for an accepted socket without an explicit binding.
  std::optional<std::uint64_t> android_network_handle;
  /// True when the byte streams are carried through the WSS bridge.
  bool via_bridge = false;
};

/// @brief Platform and build support for a local network operation.
enum class CapabilityStatus {
  Unsupported,        ///< The platform or build does not implement the operation.
  Available,          ///< The operation is implemented and can be attempted with its normal inputs.
  RequiresPermission, ///< The operation can require a runtime permission or other system authorization.
  RequiresUserAction, ///< The operation uses system UI or can require an explicit user confirmation.
};

/// @brief Local network capabilities of the current build and platform.
struct Capabilities {
  /// Direct outbound TCP.
  CapabilityStatus tcp_dial = CapabilityStatus::Unsupported;
  /// Direct incoming TCP.
  CapabilityStatus tcp_listen = CapabilityStatus::Unsupported;
  /// Outbound TLS with platform certificate trust.
  CapabilityStatus tls_dial = CapabilityStatus::Unsupported;
  /// Incoming TLS with application-provided server credentials.
  CapabilityStatus tls_listen = CapabilityStatus::Unsupported;
  /// Outbound HuxerUI paired TLS.
  CapabilityStatus paired_tls_dial = CapabilityStatus::Unsupported;
  /// Incoming HuxerUI paired TLS. The application supplies the pairing approval policy.
  CapabilityStatus paired_tls_listen = CapabilityStatus::Unsupported;
  /// Direct DNS-SD browsing, resolution, and publication.
  CapabilityStatus dns_sd = CapabilityStatus::Unsupported;
  /// System picker for access to one DNS-SD service.
  CapabilityStatus dns_sd_picker = CapabilityStatus::Unsupported;
  /// Nearby Wi-Fi scan. The status covers authorization for a fresh scan.
  CapabilityStatus wifi_scan = CapabilityStatus::Unsupported;
  /// Association with a known Wi-Fi hotspot.
  CapabilityStatus wifi_join = CapabilityStatus::Unsupported;
  /// Activation of a saved system Wi-Fi profile.
  CapabilityStatus wifi_join_saved_profile = CapabilityStatus::Unsupported;
  /// Selection of a Wi-Fi route after joining in system settings.
  CapabilityStatus wifi_route_selection = CapabilityStatus::Unsupported;
  /// Outbound TCP binding to an Android network handle or Wi-Fi lease.
  CapabilityStatus android_network_binding = CapabilityStatus::Unsupported;
  /// HTTP and HTTPS over an Android Wi-Fi lease.
  CapabilityStatus wifi_bound_http = CapabilityStatus::Unsupported;
  /// Desktop WSS bridge hosting.
  CapabilityStatus web_bridge_host = CapabilityStatus::Unsupported;
  /// Access to a desktop WSS bridge from the browser.
  CapabilityStatus web_bridge_client = CapabilityStatus::Unsupported;
};

/// @brief Reports current platform and build support without prompting or opening a network connection.
///
/// Permission and user-action statuses describe prerequisites. The query does not check the current grant,
/// running system services, hardware, or reachability. Use the operation result to report runtime failures.
/// @return The capabilities available to this application on the current platform.
Capabilities GetCapabilities() noexcept;

/// @brief Registers LocalNetwork's platform integration for an application.
///
/// Add this function to the host's application hooks before running Android DNS-SD, Wi-Fi, or system-trusted TLS tasks.
/// @param context Application context receiving the platform registrations.
void Install(ApplicationContext& context);

} // namespace huxerui::localnetwork
