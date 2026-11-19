#pragma once

/// @file
/// @brief Local TCP listeners, connections, and HuxerUI asynchronous byte streams.
///
/// Include <huxerui/local_network_tcp.h> and link HuxerUI::LocalNetwork. Run the returned tasks in a HuxerUI TaskScope.
/// ListenTcpAsync() creates a listener, TcpListener::AcceptAsync() accepts an incoming connection,
/// and DialTcpAsync() opens an outgoing connection. Both directions expose the SDK's asynchronous byte streams over plain TCP.
/// @see local_network_discovery.h for DNS-SD, local_network_tls.h for accessory TLS clients, and
/// local_network_pairing.h for paired TLS sessions.

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>

#include <huxerui/local_network_common.h>
#include <huxerui/stream.h>

namespace huxerui::localnetwork {

class WifiNetworkLease;

namespace detail {
class TcpSocket;
struct TcpConnectionAccess;
}

/// @brief Options for an outbound TCP connection.
struct TcpDialOptions {
  /// Positive timeout for address resolution and all connection attempts combined.
  /// An in-flight system address lookup can outlast this timeout. The task checks the deadline when the lookup returns.
  std::chrono::milliseconds timeout = std::chrono::seconds(10);
  /// Optional nonzero Android system network handle, for example from android.net.Network.getNetworkHandle().
  ///
  /// Android uses this handle for both resolution and every socket attempt. Keep any system network request that
  /// maintains the network active until the connection closes. Leave this empty to use system routing.
  /// Supplying a nonzero handle outside Android returns Unsupported.
  std::optional<std::uint64_t> android_network_handle;
  /// Optional app-scoped Android Wi-Fi lease from JoinWifiAsync(). The connection retains it until close.
  /// A lost lease fails the dial. Set either this field or android_network_handle.
  std::shared_ptr<const WifiNetworkLease> wifi_lease;
};

/// @brief An owning TCP connection with independent input and output stream handles.
///
/// Perform at most one operation per stream. A read and a write can run concurrently. The streams returned by
/// Input() and Output() are borrowed. Keep the connection alive at the same address until their tasks finish.
/// Destroying the connection or canceling a pending stream operation closes both directions.
class TcpConnection final {
public:
  /// Transfers the connection and its streams to this handle.
  TcpConnection(TcpConnection&&) noexcept;
  /// Closes the current connection and transfers ownership from the supplied handle.
  TcpConnection& operator=(TcpConnection&&) noexcept;
  /// Closes the socket and releases both stream handles.
  ~TcpConnection();

  /// Returns the input stream. An empty successful read indicates the peer closed its output.
  AsyncInputStream& Input() noexcept;
  /// Returns the output stream. Await its CloseAsync() to shut down TCP writes and keep reading from the peer.
  AsyncOutputStream& Output() noexcept;
  /// Returns the actual endpoints and available route details recorded when the connection was established.
  const ConnectionPath& Path() const noexcept;
  /// Closes both directions without waiting for the peer. Calling this again has no effect.
  void Close() noexcept;

private:
  TcpConnection(std::shared_ptr<detail::TcpSocket> socket, ConnectionPath path);

  std::shared_ptr<detail::TcpSocket> socket_;
  ConnectionPath path_;
  AsyncInputStream input_;
  AsyncOutputStream output_;

  friend class TcpListener;
  friend struct detail::TcpConnectionAccess;
  friend Task<NetworkResult<TcpConnection>> DialTcpAsync(Endpoint endpoint, TcpDialOptions options);
};

/// @brief An owning TCP listener. Closing it leaves previously accepted connections open.
class TcpListener final {
public:
  /// Transfers the listener to this handle.
  TcpListener(TcpListener&&) noexcept;
  /// Closes the current listener and transfers ownership from the supplied handle.
  TcpListener& operator=(TcpListener&&) noexcept;
  /// Closes the listening socket.
  ~TcpListener();

  /// Returns the actual numeric address and port, including a port allocated by the system.
  const Endpoint& LocalEndpoint() const noexcept;
  /// @brief Waits for the next incoming connection.
  ///
  /// Closing the listener ends a pending accept with Closed. Cancel the task to stop waiting and keep listening.
  /// @return A lazy task yielding an owning connection. A concurrent accept returns Busy.
  Task<NetworkResult<TcpConnection>> AcceptAsync();
  /// Stops accepting new connections and releases the listening socket.
  void Close() noexcept;

private:
  TcpListener(std::shared_ptr<detail::TcpSocket> socket, Endpoint endpoint);
  static Task<NetworkResult<TcpConnection>> Accept(std::shared_ptr<detail::TcpSocket> socket);

  std::shared_ptr<detail::TcpSocket> socket_;
  Endpoint endpoint_;

  friend Task<NetworkResult<TcpListener>> ListenTcpAsync(Endpoint endpoint);
};

/// @brief Reports whether the platform provides direct TCP listeners and connections.
/// @return True when direct TCP is implemented. Actual connections depend on system permissions and reachability.
bool IsTcpSupported() noexcept;

/// @brief Opens a plain TCP listener on an explicit numeric local address.
/// @param endpoint Numeric bind address. Use `0.0.0.0` or `::` for a wildcard, and port zero for a system-assigned port.
/// @return A lazy task yielding a listener with its actual bound endpoint, or a NetworkError.
Task<NetworkResult<TcpListener>> ListenTcpAsync(Endpoint endpoint);

/// @brief Establishes a plain TCP connection without blocking the application thread on resolution.
///
/// Canceling the task skips result delivery. A system address lookup already in progress may finish in the background.
/// @param endpoint Numeric address or hostname with a nonzero port. Supply an IPv6 scope when needed.
/// @param options Connection deadline and optional Android network handle or Wi-Fi lease.
/// @return A lazy task yielding an owning connection or a NetworkError.
Task<NetworkResult<TcpConnection>> DialTcpAsync(Endpoint endpoint, TcpDialOptions options = {});

} // namespace huxerui::localnetwork
