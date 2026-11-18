#pragma once

/// @file
/// @brief Shared endpoint, error, and application integration declarations for Lib-LocalNetwork.
///
/// Link HuxerUI::LocalNetwork. Each capability header exposes these shared declarations.

#include <cstdint>
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

/// @brief Actual local and peer endpoints of an established connection.
struct ConnectionPath {
  /// Address and port bound to the socket after establishment.
  Endpoint local;
  /// Address and port of the connected peer.
  Endpoint remote;
};

/// @brief Registers LocalNetwork's platform integration for an application.
///
/// Add this function to the host's application hooks before running Android DNS-SD, Wi-Fi, or system-trusted TLS tasks.
/// @param context Application context receiving the platform registrations.
void Install(ApplicationContext& context);

} // namespace huxerui::localnetwork
