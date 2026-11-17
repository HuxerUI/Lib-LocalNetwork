#pragma once

/// @file
/// @brief Unified outbound connections to manually entered addresses and DNS-SD services.
///
/// Include <huxerui/local_network_connection.h> and link HuxerUI::LocalNetwork. Run connection tasks in a
/// HuxerUI TaskScope. On Android, add Install() to the application hooks for discovery and platform TLS trust.

#include <variant>

#include <huxerui/local_network_discovery.h>
#include <huxerui/local_network_pairing.h>
#include <huxerui/local_network_tls.h>

namespace huxerui::localnetwork {

/// An address obtained from the application or a scoped service reference returned by DNS-SD browsing.
using Target = std::variant<Endpoint, DiscoveredService>;

/// @brief Transport requested for an accessory connection.
enum class DialMode {
  Tls, ///< TLS with the platform's trusted certificates and server name verification.
  Tcp, ///< Unencrypted TCP without peer authentication.
};

/// @brief Transport, routing, and server identity for an accessory dial.
struct DialOptions {
  /// Selects the accessory protocol. The default uses platform-trusted TLS.
  DialMode mode = DialMode::Tls;
  /// TCP timeout and optional Android routing constraint. A DNS-SD dial applies the timeout to each candidate.
  TcpDialOptions tcp;
  /// Expected certificate DNS name or IP address. Required for TLS with a DNS-SD target. An empty value with
  /// an explicit endpoint uses its host. Leave this empty for plain TCP.
  std::string server_name;
};

/// @brief Security applied to an established connection.
enum class ConnectionSecurity {
  PlainTcp,    ///< Unencrypted TCP.
  PlatformTls, ///< TLS authenticated against platform trust and a server name.
  PairedTls,   ///< TLS authenticated against a HuxerUI device identity.
};

/// @brief Security details reported by an established connection.
struct SecurityInfo {
  /// Security applied by the transport.
  ConnectionSecurity mode;
  /// Authenticated peer public-key identifier for a paired TLS session.
  std::optional<PeerId> peer;
};

/// @brief Owns a TCP, accessory TLS, or paired TLS connection through a common stream interface.
///
/// Keep the connection in place while its borrowed streams or outstanding tasks are in use. One read and
/// one write can run concurrently. Canceling a pending stream operation closes both directions.
class Connection final {
public:
  /// Takes ownership of a plain TCP connection.
  explicit Connection(TcpConnection connection);
  /// Takes ownership of a platform-trusted TLS connection.
  explicit Connection(TlsConnection connection);
  /// Takes ownership of a paired TLS connection.
  explicit Connection(PairedConnection connection);

  /// Transfers ownership of the connection and its streams.
  Connection(Connection&&) noexcept;
  /// Closes the current connection and transfers ownership from the supplied connection.
  Connection& operator=(Connection&&) noexcept;
  /// Closes the connection and releases its streams.
  ~Connection();

  /// Returns the input stream. An empty successful read indicates an orderly end of input.
  AsyncInputStream& Input() noexcept;
  /// Returns the output stream for application bytes.
  AsyncOutputStream& Output() noexcept;
  /// Returns the actual TCP endpoints recorded by the transport.
  const ConnectionPath& Path() const noexcept;
  /// Returns the connection's security mode and paired peer identifier, when available.
  SecurityInfo Security() const noexcept;
  /// Finishes the output stream and signals end of output to the peer while leaving input available.
  Task<IoResult<void>> ShutdownWriteAsync();
  /// Returns a lazy task that closes both directions. Keep the connection in place until the task completes.
  Task<NetworkResult<void>> CloseAsync();
  /// Closes both directions immediately. Pending operations observe closure through the underlying transport.
  void Close() noexcept;

private:
  std::variant<TcpConnection, TlsConnection, PairedConnection> transport_;
};

/// @brief Connects to a HuxerUI peer using TLS pairing or a remembered public key.
///
/// Resolves DNS-SD targets on their original scope. Tries other resolved endpoints after connection failures
/// or timeouts. A pairing or authentication failure ends the dial.
/// @param target Explicit address or DNS-SD service reference.
/// @param identity Local device identity used for TLS client authentication.
/// @param credential Expected peer public key or first-time pairing code.
/// @param options TCP deadline per endpoint and optional Android routing constraint.
/// @return A lazy task yielding an authenticated connection or a NetworkError.
Task<NetworkResult<Connection>> ConnectAsync(
    Target target, DeviceIdentity identity, PeerCredential credential, TcpDialOptions options = {});

/// @brief Dials an accessory using platform-trusted TLS or explicitly selected plain TCP.
///
/// Resolves DNS-SD targets on their original scope and tries other addresses after connection failures or
/// timeouts. Certificate failures end the dial. For a DNS-SD TLS target, supply the expected name independently
/// of the discovery response.
/// @param target Explicit address or DNS-SD service reference.
/// @param options Transport mode, optional Android routing constraint, and certificate name.
/// @return A lazy task yielding a connection or a NetworkError.
Task<NetworkResult<Connection>> DialAsync(Target target, DialOptions options = {});

} // namespace huxerui::localnetwork
