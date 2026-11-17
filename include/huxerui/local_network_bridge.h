#pragma once

/// @file
/// @brief A browser WSS connection bridged to one authenticated local-network peer.
///
/// Include <huxerui/local_network_bridge.h> and link HuxerUI::LocalNetwork. Use the bridge on the owning
/// application thread and the Web client on the browser's main thread. The desktop host authorizes the browser
/// origin and chooses the paired connection.

#include <huxerui/local_network_pairing.h>

namespace huxerui::localnetwork {

namespace detail {
class BridgeSession;
struct BridgeAccess;
struct WebBridgeListenerState;
}

/// @brief Credentials and bind address for the desktop WSS listener.
struct WebBridgeListenOptions {
  /// Numeric local address and TCP port. The default binds only to IPv4 loopback on a system-assigned port.
  Endpoint endpoint{"127.0.0.1", 0};
  /// Exact browser Origin, including the port when nondefault. Use HTTPS, or HTTP on localhost, 127.0.0.1, or [::1].
  std::string origin;
  /// PEM server certificate and any intermediate certificates. The browser must trust the chain and address.
  std::string certificate_pem;
  /// Unencrypted PEM key for the server certificate. Keep it in application-owned secret storage.
  std::string private_key_pem;
};

/// @brief Options to redeem a desktop host's one-time WSS grant.
struct WebBridgeDialOptions {
  /// Browser-trusted WSS URL, ending in /huxer-lan/v1.
  std::string url;
  /// Hexadecimal grant code displayed by the desktop host. Keep it out of URLs, logs, and browser persistence.
  std::string grant;
  /// When supplied, require the desktop bridge to report this downstream TLS peer.
  std::optional<PeerId> expected_peer;
};

/// @brief A browser byte stream with downstream identity verified by the desktop bridge.
///
/// The browser authenticates the bridge through WSS. The bridge authenticates the LAN peer through paired TLS
/// and can access the relayed bytes. Keep this object in place while its borrowed streams are in use.
/// Each direction supports one pending operation. Canceling a pending operation closes the connection.
class WebBridgeConnection final {
public:
  /// Transfers ownership of the browser connection and its streams.
  WebBridgeConnection(WebBridgeConnection&&) noexcept;
  /// Closes the current connection and transfers ownership from the supplied connection.
  WebBridgeConnection& operator=(WebBridgeConnection&&) noexcept;
  /// Closes the browser connection.
  ~WebBridgeConnection();

  /// Returns the input stream. A successful empty read indicates an orderly end of input.
  AsyncInputStream& Input() noexcept;
  /// Returns the output stream. Await its CloseAsync() to end output and keep receiving.
  AsyncOutputStream& Output() noexcept;
  /// Returns the peer identifier reported by the authenticated bridge.
  const PeerId& Peer() const noexcept;
  /// Closes both directions and abandons pending I/O.
  void Close() noexcept;

private:
  WebBridgeConnection(std::shared_ptr<detail::BridgeSession> session, PeerId peer);
  std::shared_ptr<detail::BridgeSession> session_;
  PeerId peer_;
  AsyncInputStream input_;
  AsyncOutputStream output_;
  friend struct detail::BridgeAccess;
};

/// @brief An owning desktop listener that can relay one paired session to an authorized browser.
class WebBridgeListener final {
public:
  /// Transfers the listener and its one-time grant.
  WebBridgeListener(WebBridgeListener&&) noexcept;
  /// Closes the current listener and transfers ownership from the supplied listener.
  WebBridgeListener& operator=(WebBridgeListener&&) noexcept;
  /// Withdraws the grant and closes the listener.
  ~WebBridgeListener();

  /// Returns the actual bound address and port. Use the certificate's hostname in the browser URL.
  const Endpoint& LocalEndpoint() const noexcept;
  /// Returns the one-time code to deliver to the authorized browser after local approval. Copy it before awaiting
  /// a relay. Redeeming the code or closing the listener invalidates the view.
  std::string_view Grant() const noexcept;

  /// @brief Waits for the authorized browser and relays the supplied paired session in both directions.
  ///
  /// The browser can redeem the grant once. Supply a TaskScope that remains alive while relaying. Closing the
  /// listener or canceling the relay ends both directions and releases the paired connection.
  /// @param peer An authenticated connection with both streams still unused by other operations.
  /// @param tasks Owning application or window task scope used for concurrent reads and writes.
  /// @return A lazy task yielding success after both directions finish or a NetworkError.
  Task<NetworkResult<void>> RelayAsync(PairedConnection peer, TaskScope tasks);

  /// Closes the listener and any active relay.
  void Close() noexcept;

private:
  explicit WebBridgeListener(std::shared_ptr<detail::WebBridgeListenerState> state);
  std::shared_ptr<detail::WebBridgeListenerState> state_;
  friend Task<NetworkResult<WebBridgeListener>> ListenWebBridgeAsync(WebBridgeListenOptions options);
};

/// @brief Opens a desktop WSS listener and generates a one-time grant.
/// @param options Local bind address, approved origin, and the WSS certificate and key.
/// @return A lazy task yielding a listener or a NetworkError. Windows, macOS, and Linux support hosting when
/// the desktop bridge backend is enabled. Other builds return Unsupported.
Task<NetworkResult<WebBridgeListener>> ListenWebBridgeAsync(WebBridgeListenOptions options);

/// @brief Establishes a browser connection to the desktop bridge and verifies the reported peer when requested.
/// @param options WSS address, one-time grant, and optional expected downstream peer identifier.
/// @return A lazy task yielding browser byte streams or a NetworkError. Native builds return Unsupported.
Task<NetworkResult<WebBridgeConnection>> ConnectWebBridgeAsync(WebBridgeDialOptions options);

} // namespace huxerui::localnetwork
