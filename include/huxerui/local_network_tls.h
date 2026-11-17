#pragma once

/// @file
/// @brief Direct TLS connections using the platform's trusted certificates and application-provided server credentials.
///
/// Include <huxerui/local_network_tls.h> and link HuxerUI::LocalNetwork. Run listener, dial, and stream tasks in
/// a HuxerUI TaskScope. On Android, add Install() to the application's hooks for server certificate validation
/// when dialing.

#include <huxerui/local_network_tcp.h>

namespace huxerui::localnetwork {

namespace detail {
struct TlsListenerState;
class TlsSocket;
}

/// @brief Routing and server identity for an outbound TLS connection.
struct TlsDialOptions {
  /// TCP deadline and optional Android network handle or Wi-Fi lease. TLS has a separate handshake deadline.
  TcpDialOptions tcp;
  /// Expected DNS name in ASCII, including IDNA A-labels, or an unbracketed IP address. An empty value uses
  /// the endpoint's host and excludes its IPv6 interface scope. A DNS name also supplies the TLS server name.
  /// Set this explicitly when dialing a numeric address whose certificate identifies the server by DNS name.
  std::string server_name;
};

/// @brief An owning TLS connection with independent input and output streams.
///
/// Keep this object at the same address while its borrowed streams are in use. Each direction supports one
/// pending operation. Canceling a pending stream operation closes both directions.
class TlsConnection final {
public:
  /// Transfers ownership of the connection and its streams.
  TlsConnection(TlsConnection&&) noexcept;
  /// Closes the current connection and transfers ownership from the supplied connection.
  TlsConnection& operator=(TlsConnection&&) noexcept;
  /// Closes the connection and releases its streams.
  ~TlsConnection();

  /// Returns the input stream. A successful empty read indicates an orderly TLS close notification.
  AsyncInputStream& Input() noexcept;
  /// Returns the output stream. Await its CloseAsync() to send a TLS close notification. TLS 1.3 lets the
  /// peer continue writing after receiving it. With TLS 1.2, complete the application exchange before closing output.
  AsyncOutputStream& Output() noexcept;
  /// Returns the actual TCP endpoints established before the TLS handshake.
  const ConnectionPath& Path() const noexcept;
  /// Reports whether the peer certificate chain and server name were verified by a TLS dial.
  /// Connections accepted by a TlsListener do not authenticate the client and return false.
  bool IsPeerAuthenticated() const noexcept;
  /// Closes both directions immediately without waiting for the peer.
  void Close() noexcept;

private:
  TlsConnection(std::shared_ptr<detail::TlsSocket> socket, ConnectionPath path, bool peer_authenticated);

  std::shared_ptr<detail::TlsSocket> socket_;
  ConnectionPath path_;
  AsyncInputStream input_;
  AsyncOutputStream output_;
  bool peer_authenticated_;

  friend class TlsListener;
  friend Task<NetworkResult<TlsConnection>> DialTlsAsync(Endpoint endpoint, TlsDialOptions options);
};

/// Reports whether the build provides a TLS client and a platform trust backend.
bool IsTlsClientSupported() noexcept;

/// @brief Dials a server using TLS 1.2 or TLS 1.3 and validates its certificate before exposing streams.
///
/// The server must present a trusted certificate chain and a matching DNS or IP subject alternative name.
/// The TLS backend rejects unsupported critical certificate extensions during the handshake.
/// Any required Android Wi-Fi lease is retained by the TCP socket for the lifetime of the TLS connection.
/// @param endpoint Address or hostname and nonzero TCP port to dial.
/// @param options Routing options and optional override for the expected certificate name.
/// @return A lazy task yielding a TLS connection or a NetworkError. Certificate failures use Authentication.
/// Web builds return Unsupported for direct TLS.
Task<NetworkResult<TlsConnection>> DialTlsAsync(Endpoint endpoint, TlsDialOptions options = {});

/// @brief Local address and credentials for a direct TLS server.
struct TlsListenOptions {
  /// Numeric local address and TCP port. Zero requests a system-assigned port. The default binds to loopback.
  Endpoint endpoint{"127.0.0.1", 0};
  /// PEM server certificate followed by its intermediate certificates in issuer order.
  std::string certificate_pem;
  /// Unencrypted PEM private key matching the server certificate. Move these options if the caller no longer needs them.
  std::string private_key_pem;
};

/// @brief Owns a TCP listener that negotiates TLS before exposing an accepted connection.
///
/// The listener presents the application's certificate. It does not request a client certificate.
class TlsListener final {
public:
  /// Transfers ownership of the listener and any pending accept.
  TlsListener(TlsListener&&) noexcept;
  /// Closes the current listener and transfers ownership from the supplied listener.
  TlsListener& operator=(TlsListener&&) noexcept;
  /// Closes the listener and ends any pending accept. Previously accepted connections stay open.
  ~TlsListener();

  /// Returns the bound address and port, or an empty endpoint after ownership has been transferred.
  const Endpoint& LocalEndpoint() const noexcept;
  /// Returns a lazy task for the next TLS connection. One accept, including its handshake, may be pending.
  /// A failed handshake releases its TCP connection and leaves the listener available for subsequent accepts.
  /// Closing the listener ends a pending accept with Closed. Cancel the task to stop waiting and keep listening.
  Task<NetworkResult<TlsConnection>> AcceptAsync();
  /// Stops accepting and closes any TCP connection still negotiating TLS. Previously accepted connections stay open.
  void Close() noexcept;

private:
  explicit TlsListener(std::shared_ptr<detail::TlsListenerState> state);
  static Task<NetworkResult<TlsConnection>> Accept(std::shared_ptr<detail::TlsListenerState> state);

  std::shared_ptr<detail::TlsListenerState> state_;

  friend Task<NetworkResult<TlsListener>> ListenTlsAsync(TlsListenOptions options);
};

/// @brief Binds a TCP listener with application-supplied credentials for TLS 1.2 and TLS 1.3.
///
/// The library parses the certificate chain and checks that the private key matches the leaf certificate.
/// Clients verify the server's identity using their own trust policy. Applications authorize requests after accept.
/// @param options Local bind address, PEM certificate chain, and matching PEM private key.
/// @return A lazy task yielding a listener or a NetworkError. Invalid credentials use Authentication.
/// Web builds return Unsupported for direct TLS listeners.
Task<NetworkResult<TlsListener>> ListenTlsAsync(TlsListenOptions options);

} // namespace huxerui::localnetwork
