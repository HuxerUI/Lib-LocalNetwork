#pragma once

/// @file
/// @brief Unified listeners and connections with TCP, direct TLS, and paired TLS modes.
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
  ServerTls,   ///< TLS accepted by a listener that presents a server certificate without authenticating the client.
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
  /// Takes ownership of a dialed or accepted direct TLS connection.
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
  /// Finishes the output stream and signals end of output to the peer. Complete the application exchange first
  /// when using TLS 1.2, whose closure alert ends the session.
  Task<IoResult<void>> ShutdownWriteAsync();
  /// Returns a lazy task that closes both directions. Keep the connection in place until the task completes.
  Task<NetworkResult<void>> CloseAsync();
  /// Closes both directions immediately. Pending operations observe closure through the underlying transport.
  void Close() noexcept;

private:
  std::variant<TcpConnection, TlsConnection, PairedConnection> transport_;
};

/// @brief Transport used for incoming connections.
enum class ListenMode {
  PairedTls, ///< TLS 1.3 with mutual device authentication and application pairing policy.
  Tls,       ///< Direct TLS with a server certificate supplied by the application.
  Tcp,       ///< Unencrypted TCP without peer authentication.
};

/// @brief Local identity and authorization policy for a paired listener.
struct PairedListenOptions {
  /// Device identity presented to dialing peers. Copies share revocations with the application.
  DeviceIdentity identity;
  /// Remembered peers, optional existing invitation, and approval callback for new peers.
  /// The callback runs in the application task scope. Capture any UI state or services it needs.
  PairingPolicy policy;
};

/// @brief Bind address and credentials for the selected incoming transport.
struct ListenOptions {
  /// Numeric bind address and port. Zero requests a system-assigned port. The default binds to loopback.
  Endpoint endpoint{"127.0.0.1", 0};
  /// Defaults to authenticated device sessions. Select Tls or Tcp explicitly for other protocols.
  ListenMode mode = ListenMode::PairedTls;
  /// Required in PairedTls mode.
  std::optional<PairedListenOptions> pairing;
  /// PEM leaf certificate followed by its intermediate certificates in issuer order for Tls mode.
  std::string certificate_pem;
  /// Unencrypted matching PEM private key for Tls mode. Move the options to transfer the key buffer.
  std::string private_key_pem;
};

namespace detail {
struct ListenerState;
}

/// @brief Owns a listening endpoint and its DNS-SD registrations.
///
/// Open the listener before advertising it or creating an invitation. Each accepted connection has its own
/// lifetime. Run asynchronous operations on the application thread in a HuxerUI TaskScope.
class Listener final {
public:
  /// Transfers ownership of the listener and its registrations.
  Listener(Listener&&) noexcept;
  /// Closes the current listener and transfers ownership from the supplied listener.
  Listener& operator=(Listener&&) noexcept;
  /// Closes the listener and withdraws its registrations. Accepted connections stay open.
  ~Listener();

  /// Returns the bound numeric address and actual port, or an empty endpoint after a move.
  const Endpoint& LocalEndpoint() const noexcept;

  /// @brief Publishes this listener's bound endpoint until the listener closes.
  ///
  /// Publication requires a concrete address on an interface that supports DNS-SD. A publication failure
  /// leaves the listener available for direct connections.
  /// @param name DNS-SD instance label, using the same syntax as ServiceAnnouncement::name.
  /// @param type TCP service type, using the same syntax as BrowseServicesAsync().
  /// @param txt Public TXT attributes. Keep pairing credentials out of DNS-SD.
  /// @return A lazy task that registers the service or returns a NetworkError.
  Task<NetworkResult<void>> AdvertiseAsync(std::string name, std::string type, ServiceTxt txt = {});

  /// @brief Creates a five-minute invitation for a paired listener.
  ///
  /// Share the code through a trusted exchange and supply LocalEndpoint() to the dialing peer separately.
  /// A successful call replaces the invitation used by subsequent TCP accepts. An accept already authenticating
  /// a peer keeps its original policy.
  /// @return An invitation, Closed for a closed listener, or Unsupported for a listener in another mode.
  NetworkResult<PairingOffer> CreateInvite();

  /// @brief Waits for the next connection and completes the selected transport's handshake.
  /// @return A lazy task yielding an owning connection. A concurrent accept returns Busy. Closing the listener
  /// ends a pending accept with Closed. Cancel the task to stop waiting and keep listening.
  Task<NetworkResult<Connection>> AcceptAsync();

  /// Stops accepting, ends pending handshakes or approvals, and requests withdrawal of all registrations.
  /// Connections already returned by AcceptAsync() stay open.
  void Close() noexcept;

private:
  explicit Listener(std::shared_ptr<detail::ListenerState> state);
  static Task<NetworkResult<Connection>> Accept(std::shared_ptr<detail::ListenerState> state);
  static Task<NetworkResult<void>> Advertise(std::shared_ptr<detail::ListenerState> state, ServiceAnnouncement service);

  std::shared_ptr<detail::ListenerState> state_;
  friend Task<NetworkResult<Listener>> ListenAsync(ListenOptions options);
};

/// @brief Opens a direct listener using the requested transport and credentials.
///
/// On Web, use the bridge API for incoming connections.
/// @param options Numeric bind endpoint and the settings for the selected transport.
/// @return A lazy task yielding an owning listener or a NetworkError.
Task<NetworkResult<Listener>> ListenAsync(ListenOptions options);

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
