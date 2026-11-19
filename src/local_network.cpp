#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#elif !defined(__EMSCRIPTEN__)
#include <cerrno>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#ifdef __ANDROID__
#include <android/multinetwork.h>
#endif

#include <huxerui/local_network_tcp.h>
#include "socket_io.h"
#include "discovery_backend.h"
#include "wifi_backend.h"
#ifdef __ANDROID__
#include "tls_backend.h"
#endif

#include <algorithm>
#include <atomic>
#include <mutex>
#include <span>
#include <stop_token>
#include <utility>

namespace huxerui::localnetwork {
namespace detail {

#ifndef __EMSCRIPTEN__
namespace {

using namespace std::chrono_literals;
using Clock = std::chrono::steady_clock;
constexpr auto retry_interval = 8ms;
constexpr std::size_t stream_chunk = 64 * 1024;

#ifdef _WIN32
using SocketHandle = SOCKET;
using AddressSize = int;
constexpr SocketHandle invalid_socket = INVALID_SOCKET;
constexpr int send_flags = 0;
constexpr int shutdown_write = SD_SEND;
constexpr int permission_denied = WSAEACCES;
constexpr int address_in_use = WSAEADDRINUSE;
constexpr int timed_out = WSAETIMEDOUT;

int SocketError() noexcept { return WSAGetLastError(); }
void CloseSocket(SocketHandle handle) noexcept { closesocket(handle); }
bool RetryIo(int error) noexcept { return error == WSAEWOULDBLOCK || error == WSAEINTR; }
bool ConnectPending(int error) noexcept { return RetryIo(error) || error == WSAEINPROGRESS; }

int InitializeSockets() noexcept {
  struct Winsock {
    int error;
    Winsock() noexcept {
      WSADATA data{};
      error = WSAStartup(MAKEWORD(2, 2), &data);
    }
    ~Winsock() {
      if (error == 0) WSACleanup();
    }
  };
  static const Winsock winsock;
  return winsock.error;
}

int SetNonblocking(SocketHandle handle) noexcept {
  u_long enabled = 1;
  return ioctlsocket(handle, FIONBIO, &enabled);
}

int CheckConnectReady(SocketHandle handle) noexcept {
  fd_set writable;
  fd_set failed;
  FD_ZERO(&writable);
  FD_ZERO(&failed);
  FD_SET(handle, &writable);
  FD_SET(handle, &failed);
  timeval immediate{};
  return select(0, nullptr, &writable, &failed, &immediate);
}
#else
using SocketHandle = int;
using AddressSize = socklen_t;
constexpr SocketHandle invalid_socket = -1;
#ifdef MSG_NOSIGNAL
constexpr int send_flags = MSG_NOSIGNAL;
#else
constexpr int send_flags = 0;
#endif
constexpr int shutdown_write = SHUT_WR;
constexpr int permission_denied = EACCES;
constexpr int address_in_use = EADDRINUSE;
constexpr int timed_out = ETIMEDOUT;

int SocketError() noexcept { return errno; }
void CloseSocket(SocketHandle handle) noexcept { close(handle); }
bool RetryIo(int error) noexcept { return error == EAGAIN || error == EWOULDBLOCK || error == EINTR; }
bool ConnectPending(int error) noexcept { return RetryIo(error) || error == EINPROGRESS; }
int InitializeSockets() noexcept { return 0; }

int SetNonblocking(SocketHandle handle) noexcept {
  const int flags = fcntl(handle, F_GETFL, 0);
  return flags < 0 ? -1 : fcntl(handle, F_SETFL, flags | O_NONBLOCK);
}

int CheckConnectReady(SocketHandle handle) noexcept {
  pollfd writable{handle, POLLOUT, 0};
  return poll(&writable, 1, 0);
}
#endif

NetworkError SocketFailure(NetworkErrorCode code, int error, std::string message) {
  if (error == permission_denied
#ifndef _WIN32
      || error == EPERM
#endif
  ) {
    code = NetworkErrorCode::PermissionDenied;
  } else if (error == address_in_use) {
    code = NetworkErrorCode::AddressInUse;
  } else if (error == timed_out) {
    code = NetworkErrorCode::TimedOut;
  }
  return {code, error, std::move(message)};
}

NetworkError ClosedSocket() { return {NetworkErrorCode::Closed, 0, "The TCP socket is closed."}; }

IoError StreamFailure(int error, std::string message) {
  const auto failure = SocketFailure(NetworkErrorCode::System, error, std::move(message));
  if (failure.code == NetworkErrorCode::PermissionDenied) return {IoErrorCode::PermissionDenied, failure.message};
  if (failure.code == NetworkErrorCode::TimedOut) return {IoErrorCode::Timeout, failure.message};
  return {IoErrorCode::Io, failure.message};
}

using Addresses = std::unique_ptr<addrinfo, decltype(&freeaddrinfo)>;

NetworkResult<Addresses> Resolve(const Endpoint& endpoint, std::optional<std::uint64_t> network, bool numeric) {
  if (const int error = InitializeSockets(); error != 0) {
    return NetworkResult<Addresses>::Failure(
        SocketFailure(NetworkErrorCode::System, error, "Could not initialize sockets."));
  }
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_NUMERICSERV | (numeric ? AI_NUMERICHOST : 0);
  const auto port = std::to_string(endpoint.port);
  addrinfo* addresses = nullptr;
  int result;
#ifdef __ANDROID__
  if (network) {
    result = android_getaddrinfofornetwork(*network, endpoint.host.c_str(), port.c_str(), &hints, &addresses);
    if (result == EAI_SYSTEM && (errno == ENONET || errno == ENETDOWN || errno == ENODEV)) {
      return NetworkResult<Addresses>::Failure(
          {NetworkErrorCode::NetworkLost, errno, "The selected Android network is unavailable."});
    }
  } else
#endif
  {
#ifndef __ANDROID__
    if (network) {
      return NetworkResult<Addresses>::Failure(
          {NetworkErrorCode::Unsupported, 0, "Android network binding is unavailable on this platform."});
    }
#endif
    result = getaddrinfo(endpoint.host.c_str(), port.c_str(), &hints, &addresses);
  }
  if (result != 0) {
    const auto code = numeric ? NetworkErrorCode::InvalidEndpoint : NetworkErrorCode::ResolveFailed;
    return NetworkResult<Addresses>::Failure({code, result, "Could not resolve the TCP address."});
  }
  return NetworkResult<Addresses>::Success(Addresses(addresses, freeaddrinfo));
}

bool ValidHost(const std::string& host) noexcept { return !host.empty() && host.find('\0') == std::string::npos; }

} // namespace
#endif

class TcpSocket
#ifndef __EMSCRIPTEN__
    final : public SocketIo, public std::enable_shared_from_this<TcpSocket>
#endif
{
public:
#ifdef __EMSCRIPTEN__
  void Close() noexcept {}
#else
  explicit TcpSocket(SocketHandle handle) noexcept : handle_(handle) {}
  ~TcpSocket() override { Close(); }

  static NetworkResult<std::shared_ptr<TcpSocket>> Open(const addrinfo& address) {
    const auto handle = socket(address.ai_family, address.ai_socktype, address.ai_protocol);
    if (handle == invalid_socket) {
      return NetworkResult<std::shared_ptr<TcpSocket>>::Failure(
          SocketFailure(NetworkErrorCode::System, SocketError(), "Could not open a TCP socket."));
    }
    return Adopt(handle);
  }

  bool RetainWifiNetwork(std::shared_ptr<const WifiNetworkLease> network) {
    // Construct the callback before locking. For an already lost lease it closes the socket inline.
    auto callback = std::make_unique<WifiLossCallback>(WifiNetworkAccess::State(*network)->LossToken(),
                                                        CloseOnWifiLoss{weak_from_this()});
    std::scoped_lock lock(mutex_);
    // Recheck after subscribing. A later notification closes the socket through the callback.
    if (handle_ == invalid_socket || !network->AndroidNetwork()) return false;
    wifi_network_ = std::move(network);
    wifi_loss_callback_ = std::move(callback);
    return true;
  }

  NetworkResult<void> Listen(const addrinfo& address) {
    const int enabled = 1;
#ifdef _WIN32
    constexpr int reuse_option = SO_EXCLUSIVEADDRUSE;
#else
    constexpr int reuse_option = SO_REUSEADDR;
#endif
    if (setsockopt(handle_, SOL_SOCKET, reuse_option, reinterpret_cast<const char*>(&enabled), sizeof(enabled)) != 0 ||
        bind(handle_, address.ai_addr, static_cast<AddressSize>(address.ai_addrlen)) != 0 ||
        listen(handle_, SOMAXCONN) != 0) {
      return NetworkResult<void>::Failure(
          SocketFailure(NetworkErrorCode::System, SocketError(), "Could not listen on the TCP address."));
    }
    return NetworkResult<void>::Success();
  }

  NetworkResult<bool> Connect(const addrinfo& address, std::optional<std::uint64_t> network) {
#ifdef __ANDROID__
    // Bind before connect so even a numeric address cannot fall back to the process's default network.
    if (network && android_setsocknetwork(*network, handle_) != 0) {
      return NetworkResult<bool>::Failure(
          SocketFailure(NetworkErrorCode::NetworkLost, SocketError(), "Could not bind to the selected Android network."));
    }
#else
    if (network) {
      return NetworkResult<bool>::Failure({NetworkErrorCode::Unsupported, 0, "Android network binding is unavailable."});
    }
#endif
    if (connect(handle_, address.ai_addr, static_cast<AddressSize>(address.ai_addrlen)) == 0) {
      return NetworkResult<bool>::Success(true);
    }
    const int error = SocketError();
    if (ConnectPending(error)) return NetworkResult<bool>::Success(false);
    return NetworkResult<bool>::Failure(
        SocketFailure(NetworkErrorCode::ConnectionFailed, error, "TCP connection failed."));
  }

  NetworkResult<bool> CheckConnect() {
    const int ready = CheckConnectReady(handle_);
    if (ready == 0) return NetworkResult<bool>::Success(false);
    if (ready < 0) {
      const int error = SocketError();
      if (RetryIo(error)) return NetworkResult<bool>::Success(false);
      return NetworkResult<bool>::Failure(
          SocketFailure(NetworkErrorCode::ConnectionFailed, error, "Could not check the TCP connection."));
    }
    int error = 0;
    AddressSize size = sizeof(error);
    if (getsockopt(handle_, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &size) != 0) error = SocketError();
    if (error == 0) return NetworkResult<bool>::Success(true);
    return NetworkResult<bool>::Failure(
        SocketFailure(NetworkErrorCode::ConnectionFailed, error, "TCP connection failed."));
  }

  NetworkResult<Endpoint> Address(bool peer, std::optional<std::uint32_t>* interface_index = nullptr) {
    sockaddr_storage address{};
    auto* sock_address = reinterpret_cast<sockaddr*>(&address);
    AddressSize size = sizeof(address);
    {
      std::scoped_lock lock(mutex_);
      if (handle_ == invalid_socket) return NetworkResult<Endpoint>::Failure(ClosedSocket());
      const int result = peer ? getpeername(handle_, sock_address, &size) : getsockname(handle_, sock_address, &size);
      if (result != 0) {
        return NetworkResult<Endpoint>::Failure(
            SocketFailure(NetworkErrorCode::System, SocketError(), "Could not read the socket endpoint."));
      }
    }
    char host[NI_MAXHOST]{};
    const int formatted = getnameinfo(sock_address, size, host, sizeof(host), nullptr, 0, NI_NUMERICHOST);
    if (formatted != 0) {
      return NetworkResult<Endpoint>::Failure(
          {NetworkErrorCode::System, formatted, "Could not format the socket address."});
    }
    auto port = address.ss_family == AF_INET ? reinterpret_cast<const sockaddr_in*>(&address)->sin_port
                                            : reinterpret_cast<const sockaddr_in6*>(&address)->sin6_port;
    if (interface_index) *interface_index = LocalInterfaceIndex(*sock_address);
    return NetworkResult<Endpoint>::Success(Endpoint{host, ntohs(port)});
  }

  NetworkResult<ConnectionPath> Path(std::optional<std::uint64_t> android_network_handle = {}) {
    std::optional<std::uint32_t> interface_index;
    auto local = Address(false, &interface_index);
    if (!local.Succeeded()) return NetworkResult<ConnectionPath>::Failure(std::move(local).Error());
    auto remote = Address(true);
    if (!remote.Succeeded()) return NetworkResult<ConnectionPath>::Failure(std::move(remote).Error());
    return NetworkResult<ConnectionPath>::Success(
        {std::move(local).Value(), std::move(remote).Value(), interface_index, android_network_handle});
  }

  NetworkResult<std::shared_ptr<TcpSocket>> TryAccept() {
    std::scoped_lock lock(mutex_);
    if (handle_ == invalid_socket) return NetworkResult<std::shared_ptr<TcpSocket>>::Failure(ClosedSocket());
    const auto accepted = accept(handle_, nullptr, nullptr);
    if (accepted != invalid_socket) return Adopt(accepted);
    const int error = SocketError();
    if (RetryIo(error)) return NetworkResult<std::shared_ptr<TcpSocket>>::Success(nullptr);
    return NetworkResult<std::shared_ptr<TcpSocket>>::Failure(
        SocketFailure(NetworkErrorCode::System, error, "Could not accept the TCP connection."));
  }

  IoResult<std::optional<std::size_t>> Receive(std::span<std::byte> bytes) override {
    using Result = IoResult<std::optional<std::size_t>>;
    std::scoped_lock lock(mutex_);
    if (auto error = StreamError()) return Result::Failure(std::move(*error));
    const auto count = recv(handle_, reinterpret_cast<char*>(bytes.data()), static_cast<int>(bytes.size()), 0);
    if (count >= 0) return Result::Success(static_cast<std::size_t>(count));
    const int error = SocketError();
    if (RetryIo(error)) return Result::Success(std::nullopt);
    return Result::Failure(StreamFailure(error, "Could not read from the TCP connection."));
  }

  IoResult<std::size_t> Send(std::span<const std::byte> bytes) override {
    std::scoped_lock lock(mutex_);
    if (auto error = StreamError()) return IoResult<std::size_t>::Failure(std::move(*error));
    const auto count = send(handle_, reinterpret_cast<const char*>(bytes.data()),
                            static_cast<int>(bytes.size()), send_flags);
    if (count > 0) return IoResult<std::size_t>::Success(static_cast<std::size_t>(count));
    const int error = count < 0 ? SocketError() : 0;
    if (RetryIo(error)) return IoResult<std::size_t>::Success(0);
    return IoResult<std::size_t>::Failure(StreamFailure(error, "Could not write to the TCP connection."));
  }

  IoResult<void> ShutdownWrite() {
    std::scoped_lock lock(mutex_);
    if (auto error = StreamError()) return IoResult<void>::Failure(std::move(*error));
    if (shutdown(handle_, shutdown_write) == 0) return IoResult<void>::Success();
    return IoResult<void>::Failure(StreamFailure(SocketError(), "Could not close the TCP output."));
  }

  bool IsOpen() const noexcept override {
    std::scoped_lock lock(mutex_);
    return handle_ != invalid_socket && !WifiLost();
  }

  void Close() noexcept override { CloseSocketAndReleaseWifi(false); }

  std::atomic_bool accepting{false};

private:
  struct CloseOnWifiLoss {
    std::weak_ptr<TcpSocket> socket;
    void operator()() const noexcept {
      if (auto bound = socket.lock()) bound->CloseSocketAndReleaseWifi(true);
    }
  };
  using WifiLossCallback = std::stop_callback<CloseOnWifiLoss>;

  // Caller holds the socket mutex.
  bool WifiLost() const noexcept { return wifi_lost_ || (wifi_network_ && !wifi_network_->AndroidNetwork()); }

  std::optional<IoError> StreamError() const {
    if (WifiLost()) return IoError{IoErrorCode::Io, "The selected Wi-Fi network was lost."};
    if (handle_ == invalid_socket) return IoError{IoErrorCode::Io, "The TCP connection is closed."};
    return std::nullopt;
  }

  void CloseSocketAndReleaseWifi(bool network_lost) noexcept {
    // Unregister before releasing the lease. Callback removal can wait, so destroy both after unlocking.
    std::shared_ptr<const WifiNetworkLease> network;
    std::unique_ptr<WifiLossCallback> callback;
    {
      std::scoped_lock lock(mutex_);
      if (handle_ == invalid_socket) return;
      wifi_lost_ = network_lost;
      CloseSocket(std::exchange(handle_, invalid_socket));
      callback = std::move(wifi_loss_callback_);
      network = std::move(wifi_network_);
    }
  }

  static NetworkResult<std::shared_ptr<TcpSocket>> Adopt(SocketHandle handle) {
    struct PendingSocket {
      SocketHandle handle;
      ~PendingSocket() {
        if (handle != invalid_socket) CloseSocket(handle);
      }
    } pending{handle};
    if (SetNonblocking(handle) != 0) {
      return NetworkResult<std::shared_ptr<TcpSocket>>::Failure(
          SocketFailure(NetworkErrorCode::System, SocketError(), "Could not configure a nonblocking TCP socket."));
    }
#ifdef SO_NOSIGPIPE
    const int enabled = 1;
    if (setsockopt(handle, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled)) != 0) {
      return NetworkResult<std::shared_ptr<TcpSocket>>::Failure(
          SocketFailure(NetworkErrorCode::System, SocketError(), "Could not configure TCP output."));
    }
#endif
    auto socket = std::make_shared<TcpSocket>(handle);
    pending.handle = invalid_socket;
    return NetworkResult<std::shared_ptr<TcpSocket>>::Success(std::move(socket));
  }

  // Serialize handle access with Close so a cancelled operation cannot touch a reused descriptor.
  mutable std::mutex mutex_;
  SocketHandle handle_;
  std::shared_ptr<const WifiNetworkLease> wifi_network_;
  std::unique_ptr<WifiLossCallback> wifi_loss_callback_;
  bool wifi_lost_ = false;
#endif
};

#ifndef __EMSCRIPTEN__
namespace {

Task<IoResult<Bytes>> Read(std::shared_ptr<TcpSocket> socket, std::stop_token stop, std::size_t maximum_bytes) {
  std::stop_callback close_on_cancel(stop, [socket] { socket->Close(); });
  Bytes bytes((std::min)(maximum_bytes, stream_chunk));
  // A stalled connection yields to the owning task scope without occupying a worker thread.
  for (;;) {
    auto received = socket->Receive(bytes);
    if (!received.Succeeded()) co_return IoResult<Bytes>::Failure(std::move(received).Error());
    if (received.Value()) {
      bytes.resize(*received.Value());
      co_return IoResult<Bytes>::Success(std::move(bytes));
    }
    co_await Delay(retry_interval);
  }
}

Task<IoResult<void>> Write(std::shared_ptr<TcpSocket> socket, std::stop_token stop, Bytes bytes) {
  std::stop_callback close_on_cancel(stop, [socket] { socket->Close(); });
  auto remaining = std::span<const std::byte>(bytes);
  while (!remaining.empty()) {
    auto sent = socket->Send(remaining.first((std::min)(remaining.size(), stream_chunk)));
    if (!sent.Succeeded()) co_return IoResult<void>::Failure(std::move(sent).Error());
    remaining = remaining.subspan(sent.Value());
    if (!remaining.empty()) co_await Delay(sent.Value() == 0 ? retry_interval : 1ms);
  }
  co_return IoResult<void>::Success();
}

Task<IoResult<void>> FinishOutput(std::shared_ptr<TcpSocket> socket, std::stop_token stop) {
  std::stop_callback close_on_cancel(stop, [socket] { socket->Close(); });
  co_return socket->ShutdownWrite();
}

} // namespace
#endif
} // namespace detail

std::shared_ptr<detail::SocketIo> detail::TcpConnectionAccess::TakeSocket(
#ifdef __EMSCRIPTEN__
    TcpConnection&
#else
    TcpConnection& connection
#endif
) {
#ifdef __EMSCRIPTEN__
  return {};
#else
  return std::move(connection.socket_);
#endif
}

#ifndef __EMSCRIPTEN__
bool detail::TcpConnectionAccess::IsConcreteAddress(const std::string& host) {
  if (!detail::ValidHost(host)) return false;
  auto result = detail::Resolve({host, 0}, {}, true);
  if (!result.Succeeded() || !result.Value()) return false;
  const auto& address = *result.Value();
  if (address.ai_family == AF_INET)
    return reinterpret_cast<const sockaddr_in*>(address.ai_addr)->sin_addr.s_addr != INADDR_ANY;
  if (address.ai_family != AF_INET6) return false;
  const auto& ip = reinterpret_cast<const sockaddr_in6*>(address.ai_addr)->sin6_addr;
  return !IN6_IS_ADDR_UNSPECIFIED(&ip) && !IN6_IS_ADDR_V4MAPPED(&ip);
}

TcpConnection::TcpConnection(std::shared_ptr<detail::TcpSocket> socket, ConnectionPath path)
    : socket_(std::move(socket)), path_(std::move(path)),
      input_(AsyncInputStream::FromReader([socket = socket_](std::stop_token stop, std::size_t maximum_bytes) {
        return detail::Read(socket, stop, maximum_bytes);
      })),
      output_(AsyncOutputStream::FromWriter(
          [socket = socket_](std::stop_token stop, Bytes bytes) {
            return detail::Write(socket, stop, std::move(bytes));
          },
          [socket = socket_](std::stop_token stop) { return detail::FinishOutput(socket, stop); })) {}
#endif

TcpConnection::TcpConnection(TcpConnection&&) noexcept = default;

TcpConnection& TcpConnection::operator=(TcpConnection&& other) noexcept {
  if (this != &other) {
    Close();
    socket_ = std::move(other.socket_);
    path_ = std::move(other.path_);
    input_ = std::move(other.input_);
    output_ = std::move(other.output_);
  }
  return *this;
}

TcpConnection::~TcpConnection() { Close(); }
AsyncInputStream& TcpConnection::Input() noexcept { return input_; }
AsyncOutputStream& TcpConnection::Output() noexcept { return output_; }
const ConnectionPath& TcpConnection::Path() const noexcept { return path_; }
void TcpConnection::Close() noexcept { if (socket_) socket_->Close(); }

TcpListener::TcpListener(std::shared_ptr<detail::TcpSocket> socket, Endpoint endpoint)
    : socket_(std::move(socket)), endpoint_(std::move(endpoint)) {}

TcpListener::TcpListener(TcpListener&&) noexcept = default;

TcpListener& TcpListener::operator=(TcpListener&& other) noexcept {
  if (this != &other) {
    Close();
    socket_ = std::move(other.socket_);
    endpoint_ = std::move(other.endpoint_);
  }
  return *this;
}

TcpListener::~TcpListener() { Close(); }
const Endpoint& TcpListener::LocalEndpoint() const noexcept { return endpoint_; }
void TcpListener::Close() noexcept { if (socket_) socket_->Close(); }
Task<NetworkResult<TcpConnection>> TcpListener::AcceptAsync() { return Accept(socket_); }

Task<NetworkResult<TcpConnection>> TcpListener::Accept(std::shared_ptr<detail::TcpSocket> socket) {
  using Result = NetworkResult<TcpConnection>;
#ifdef __EMSCRIPTEN__
  co_return Result::Failure({NetworkErrorCode::Unsupported, 0, "Direct TCP is unavailable on this platform."});
#else
  if (!socket) co_return Result::Failure(detail::ClosedSocket());
  if (socket->accepting.exchange(true)) {
    co_return Result::Failure({NetworkErrorCode::Busy, 0, "The TCP listener already has a pending accept."});
  }
  struct PendingAccept {
    detail::TcpSocket& socket;
    ~PendingAccept() { socket.accepting.store(false); }
  } pending{*socket};
  for (;;) {
    auto accepted = socket->TryAccept();
    if (!accepted.Succeeded()) co_return Result::Failure(std::move(accepted).Error());
    if (auto client = std::move(accepted).Value()) {
      auto path = client->Path();
      if (!path.Succeeded()) co_return Result::Failure(std::move(path).Error());
      co_return Result::Success(TcpConnection(std::move(client), std::move(path).Value()));
    }
    co_await Delay(detail::retry_interval);
  }
#endif
}

bool IsTcpSupported() noexcept {
#ifdef __EMSCRIPTEN__
  return false;
#else
  return true;
#endif
}

Task<NetworkResult<TcpListener>> ListenTcpAsync(Endpoint endpoint) {
  using Result = NetworkResult<TcpListener>;
#ifdef __EMSCRIPTEN__
  co_return Result::Failure({NetworkErrorCode::Unsupported, 0, "Direct TCP is unavailable on this platform."});
#else
  if (!detail::ValidHost(endpoint.host)) {
    co_return Result::Failure({NetworkErrorCode::InvalidEndpoint, 0, "A numeric listen address is required."});
  }
  auto resolved = detail::Resolve(endpoint, {}, true);
  if (!resolved.Succeeded()) co_return Result::Failure(std::move(resolved).Error());
  auto socket = detail::TcpSocket::Open(*resolved.Value());
  if (!socket.Succeeded()) co_return Result::Failure(std::move(socket).Error());
  auto started = socket.Value()->Listen(*resolved.Value());
  if (!started.Succeeded()) co_return Result::Failure(std::move(started).Error());
  auto local = socket.Value()->Address(false);
  if (!local.Succeeded()) co_return Result::Failure(std::move(local).Error());
  co_return Result::Success(TcpListener(std::move(socket).Value(), std::move(local).Value()));
#endif
}

Task<NetworkResult<TcpConnection>> DialTcpAsync(Endpoint endpoint, TcpDialOptions options) {
  using Result = NetworkResult<TcpConnection>;
#ifdef __EMSCRIPTEN__
  co_return Result::Failure({NetworkErrorCode::Unsupported, 0, "Direct TCP is unavailable on this platform."});
#else
  if (!detail::ValidHost(endpoint.host) || endpoint.port == 0 ||
      options.timeout <= std::chrono::milliseconds::zero() || options.android_network_handle == 0 ||
      (options.android_network_handle && options.wifi_lease)) {
    co_return Result::Failure(
        {NetworkErrorCode::InvalidEndpoint, 0, "A host, nonzero port, and valid dial options are required."});
  }
  const NetworkError network_lost{NetworkErrorCode::NetworkLost, 0, "The selected Wi-Fi network was lost."};
  auto network = options.android_network_handle;
  if (options.wifi_lease) {
    network = options.wifi_lease->AndroidNetwork();
    if (!network) co_return Result::Failure(network_lost);
  }
  const auto lost = [&] { return options.wifi_lease && !options.wifi_lease->AndroidNetwork(); };
  const auto now = detail::Clock::now();
  const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(detail::Clock::time_point::max() - now);
  const auto deadline = options.timeout >= remaining ? detail::Clock::time_point::max() : now + options.timeout;
  auto resolved = co_await RunWorker(detail::Resolve, std::move(endpoint), network, false);
  const NetworkError timeout{NetworkErrorCode::TimedOut, 0, "The TCP connection timed out."};
  if (lost()) co_return Result::Failure(network_lost);
  if (detail::Clock::now() >= deadline) co_return Result::Failure(timeout);
  if (!resolved.Succeeded()) co_return Result::Failure(std::move(resolved).Error());

  NetworkError failure{NetworkErrorCode::ConnectionFailed, 0, "No TCP addresses were available."};
  for (auto address = resolved.Value().get(); address; address = address->ai_next) {
    if (detail::Clock::now() >= deadline) co_return Result::Failure(timeout);
    auto opened = detail::TcpSocket::Open(*address);
    if (!opened.Succeeded()) {
      failure = std::move(opened).Error();
      continue;
    }
    auto socket = std::move(opened).Value();
    auto connected = socket->Connect(*address, network);
    while (connected.Succeeded() && !connected.Value()) {
      if (detail::Clock::now() >= deadline) co_return Result::Failure(timeout);
      co_await Delay(detail::retry_interval);
      if (lost()) co_return Result::Failure(network_lost);
      connected = socket->CheckConnect();
    }
    if (!connected.Succeeded()) {
      failure = std::move(connected).Error();
      if (failure.code == NetworkErrorCode::NetworkLost) co_return Result::Failure(std::move(failure));
      continue;
    }
    if (detail::Clock::now() >= deadline) co_return Result::Failure(timeout);
    // Capture the handle used by Connect(), including handles from a Wi-Fi lease or DNS-SD resolution.
    auto path = socket->Path(network);
    if (!path.Succeeded()) co_return Result::Failure(std::move(path).Error());
    if (options.wifi_lease && !socket->RetainWifiNetwork(options.wifi_lease))
      co_return Result::Failure(network_lost);
    co_return Result::Success(TcpConnection(std::move(socket), std::move(path).Value()));
  }
  co_return Result::Failure(std::move(failure));
#endif
}

#ifdef __ANDROID__
void Install(ApplicationContext& context) {
  detail::InstallPlatformDiscovery(context);
  detail::InstallPlatformWifi(context);
  detail::InstallPlatformTlsTrust(context);
}
#else
void Install(ApplicationContext&) {}
#endif

} // namespace huxerui::localnetwork
