#pragma once

/// @file
/// @brief Browser access to authorized local-network services and paired byte streams through WSS.
///
/// Include <huxerui/local_network_bridge.h> and link HuxerUI::LocalNetwork. Use the bridge on the owning
/// application thread and the Web client on the browser's main thread. The desktop host approves the origin
/// and either selects an existing paired connection or grants scoped control of local-network services.

#include <vector>

#include <huxerui/local_network_discovery.h>
#include <huxerui/local_network_pairing.h>

namespace huxerui::localnetwork {

namespace detail {
class BridgeSession;
struct BridgeAccess;
struct BridgeControlState;
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
  /// Reports that the stream uses the WSS bridge. The browser does not expose the underlying socket endpoints.
  const ConnectionPath& Path() const noexcept;
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

/// @brief A numeric endpoint and peer public key that a browser may dial together.
struct WebBridgeDialPermission {
  /// Exact numeric address and nonzero port. Use the address format returned by discovery when applicable.
  Endpoint endpoint;
  /// Device public key the desktop host must authenticate before forwarding bytes.
  PeerId peer;
};

/// @brief Limits approved by the desktop application before sharing a control grant.
struct WebBridgePolicy {
  /// Desktop identity used for both dialing and accepting paired connections.
  DeviceIdentity identity;
  /// Exact DNS-SD service types that the browser can browse and resolve.
  std::vector<std::string> browse_types;
  /// Optional nonzero desktop interface index for all browser DNS-SD browsing.
  std::optional<std::uint64_t> browse_interface;
  /// Exact endpoint and peer combinations allowed for outbound paired connections.
  std::vector<WebBridgeDialPermission> dial_targets;
  /// Concrete local LAN address for browser-registered listeners. Omit to disable registration and publication.
  /// Each listener uses a system-assigned port on this address.
  std::optional<std::string> listen_address;
  /// Policy for peers connecting to browser-registered listeners. Approval runs on the desktop application thread.
  PairingPolicy incoming;
  /// Exact DNS-SD service types that can be published for a registered listener.
  std::vector<std::string> publish_types;
};

/// @brief A listener registered through a browser control session.
struct WebBridgeListenerRegistration {
  /// Opaque nonzero identifier valid for the control connection that registered it.
  std::uint32_t id = 0;
  /// Actual desktop listening address and system-assigned port.
  Endpoint endpoint;
};

/// @brief Options for opening the browser control connection.
struct WebBridgeControlOptions {
  /// Browser-trusted WSS URL ending in /huxer-lan/v1.
  std::string url;
  /// One-time grant shared by the desktop application. Keep it out of URLs, logs, and browser persistence.
  std::string grant;
};

/// @brief An authorized browser control connection and owner of its registered services.
///
/// Only one control request can be outstanding. After DialAsync() or AcceptAsync() obtains its data grant, it
/// continues on a separate WSS connection and the control connection can process another request. Canceling an
/// in-flight control request closes the control connection. Disconnecting it withdraws its publications, closes
/// its listeners, and ends its data connections.
class WebBridgeControl final {
public:
  /// Transfers ownership of the control connection and its registered services.
  WebBridgeControl(WebBridgeControl&&) noexcept;
  /// Closes the current control connection and transfers ownership from the supplied connection.
  WebBridgeControl& operator=(WebBridgeControl&&) noexcept;
  /// Closes the control connection and releases its resources.
  ~WebBridgeControl();

  /// Browses one approved DNS-SD service type. Each successful call replaces that type's previous snapshot.
  /// Returns a snapshot after a 2.5-second observation window.
  Task<NetworkResult<std::vector<DiscoveredService>>> BrowseAsync(std::string type);
  /// Resolves a service from the latest snapshot for its type on this control connection.
  Task<NetworkResult<ResolvedService>> ResolveAsync(DiscoveredService service);
  /// Dials an approved numeric endpoint and authenticates the expected peer.
  /// Supply a pairing code for a first connection. An empty code uses the remembered peer public key.
  Task<NetworkResult<WebBridgeConnection>> DialAsync(Endpoint endpoint, PeerId peer, std::string pairing_code = {});
  /// Registers a listener on the desktop application's approved address.
  Task<NetworkResult<WebBridgeListenerRegistration>> ListenAsync();
  /// Publishes an approved service type and public TXT attributes for the registered listener.
  /// To publish again for the same listener, withdraw its current publication first.
  Task<NetworkResult<void>> PublishAsync(std::uint32_t listener, std::string name, std::string type,
                                         ServiceTxt txt = {});
  /// Withdraws the publication while keeping the registered listener available for direct connections.
  Task<NetworkResult<void>> WithdrawAsync(std::uint32_t listener);
  /// Accepts and authenticates one incoming peer using the desktop application's pairing policy.
  /// Keep at most one accept pending per listener. After the control request completes, canceling the accept
  /// closes its data connection and releases the pending accept on the desktop.
  Task<NetworkResult<WebBridgeConnection>> AcceptAsync(std::uint32_t listener);
  /// Stops accepting and withdraws the associated publication. Established connections can continue while the
  /// control connection remains open.
  Task<NetworkResult<void>> CloseListenerAsync(std::uint32_t listener);
  /// Closes the control connection and revokes access granted through it.
  void Close() noexcept;

private:
  explicit WebBridgeControl(std::shared_ptr<detail::BridgeControlState> state);
  std::shared_ptr<detail::BridgeControlState> state_;
  friend Task<NetworkResult<WebBridgeControl>> ConnectWebBridgeControlAsync(WebBridgeControlOptions options);
};

/// @brief An owning desktop WSS listener for an authorized browser.
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
  /// Returns the one-time code to deliver to the authorized browser after local approval. Copy it before starting
  /// RelayAsync() or ServeAsync(). Redeeming the code or closing the listener invalidates the view.
  std::string_view Grant() const noexcept;

  /// @brief Waits for the authorized browser and relays the supplied paired session in both directions.
  ///
  /// The browser can redeem the grant once. Supply a TaskScope that remains alive while relaying. Closing the
  /// listener or canceling the relay ends both directions and releases the paired connection.
  /// @param peer An authenticated connection with both streams still unused by other operations.
  /// @param tasks Owning application or window task scope used for concurrent reads and writes.
  /// @return A lazy task yielding success after both directions finish or a NetworkError.
  Task<NetworkResult<void>> RelayAsync(PairedConnection peer, TaskScope tasks);

  /// @brief Serves one browser control session and its paired data connections.
  ///
  /// Redeeming the listener grant starts the control session. The listener closes when that session ends.
  /// Supply a task scope on the owning application thread that stays alive for the duration of the service.
  /// @param policy Authorized services, endpoints, peer identities, and incoming pairing policy.
  /// @param tasks Owning scope for WSS connections and bidirectional forwarding.
  /// @return A lazy task that completes when the browser disconnects or the listener closes.
  Task<NetworkResult<void>> ServeAsync(WebBridgePolicy policy, TaskScope tasks);

  /// Closes the listener and any active relay or control session.
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

/// @brief Redeems the one-time host grant and opens a scoped browser control connection.
/// @param options Browser-trusted WSS address and one-time control grant.
/// @return A lazy task yielding a control connection or a NetworkError. Native builds return Unsupported.
Task<NetworkResult<WebBridgeControl>> ConnectWebBridgeControlAsync(WebBridgeControlOptions options);

} // namespace huxerui::localnetwork
