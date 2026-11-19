#pragma once

#include <optional>
#include <span>

#include <huxerui/local_network_tcp.h>

struct sockaddr;

namespace huxerui::localnetwork::detail {

/// Looks up the interface of a local socket address without changing the route.
std::optional<std::uint32_t> LocalInterfaceIndex(const sockaddr& address) noexcept;

/// Nonblocking socket access used by the TLS transport.
class SocketIo {
public:
  virtual ~SocketIo() = default;
  /// Returns bytes read. Zero means end of stream. An empty optional means the caller should retry.
  virtual IoResult<std::optional<std::size_t>> Receive(std::span<std::byte> bytes) = 0;
  /// Returns bytes written. A successful zero means the caller should retry.
  virtual IoResult<std::size_t> Send(std::span<const std::byte> bytes) = 0;
  /// Checks whether this socket can still be used locally.
  virtual bool IsOpen() const noexcept = 0;
  /// Releases the socket and ends access from both directions.
  virtual void Close() noexcept = 0;
};

struct TcpConnectionAccess {
  /// Transfers socket ownership to the TLS transport. The connection's byte streams must still be unused.
  static std::shared_ptr<SocketIo> TakeSocket(TcpConnection& connection);
  /// Checks for a numeric, non-wildcard address without performing DNS.
  static bool IsConcreteAddress(const std::string& host);
};

} // namespace huxerui::localnetwork::detail
