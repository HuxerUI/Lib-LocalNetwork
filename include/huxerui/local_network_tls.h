#pragma once

/// @file
/// @brief Client TLS connections to accessories using the platform's trusted certificates.
///
/// Include <huxerui/local_network_tls.h> and link HuxerUI::LocalNetwork. Run dial and stream tasks in a
/// HuxerUI TaskScope. On Android, add Install() to the application's hooks to enable certificate validation.

#include <huxerui/local_network_tcp.h>

namespace huxerui::localnetwork {

namespace detail {
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

/// @brief An owning TLS client connection with independent input and output streams.
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
  /// Returns the output stream. Await its CloseAsync() to send a TLS close notification and keep reading.
  AsyncOutputStream& Output() noexcept;
  /// Returns the actual TCP endpoints established before the TLS handshake.
  const ConnectionPath& Path() const noexcept;
  /// Closes both directions immediately without waiting for the server.
  void Close() noexcept;

private:
  TlsConnection(std::shared_ptr<detail::TlsSocket> socket, ConnectionPath path);

  std::shared_ptr<detail::TlsSocket> socket_;
  ConnectionPath path_;
  AsyncInputStream input_;
  AsyncOutputStream output_;

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

} // namespace huxerui::localnetwork
