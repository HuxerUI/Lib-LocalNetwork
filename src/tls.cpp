#ifdef HUXERUI_LOCALNETWORK_TLS
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif
#endif

#include "tls_backend.h"

#include <algorithm>
#include <utility>

#ifdef HUXERUI_LOCALNETWORK_TLS
#include "socket_io.h"

#include <mutex>

#include <huxerui/local_network_wifi.h>
#endif

namespace huxerui::localnetwork {

#ifdef HUXERUI_LOCALNETWORK_TLS
namespace detail {

struct TlsListenerState {
  TcpListener listener;
  std::shared_ptr<IdentityState> credentials;
  std::mutex mutex;
  std::shared_ptr<SocketIo> pending;
  bool accepting = false;

  TlsListenerState(TcpListener tcp, std::shared_ptr<IdentityState> identity)
      : listener(std::move(tcp)), credentials(std::move(identity)) {}
};

} // namespace detail
#endif

namespace {

#ifdef HUXERUI_LOCALNETWORK_TLS
bool Alphanumeric(char value) {
  return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9');
}

bool ValidDnsName(std::string_view name) {
  if (name.empty() || name.size() > 253) return false;
  while (!name.empty()) {
    const auto dot = name.find('.');
    const auto label = name.substr(0, dot);
    if (label.empty() || label.size() > 63 || !Alphanumeric(label.front()) || !Alphanumeric(label.back()) ||
        !std::ranges::all_of(label, [](char ch) { return Alphanumeric(ch) || ch == '-'; })) return false;
    if (dot == std::string_view::npos) return true;
    name.remove_prefix(dot + 1);
  }
  return false;
}

std::optional<detail::TlsServerName> ParseServerName(std::string host) {
  if (host.empty() || host.find('\0') != std::string::npos) return std::nullopt;
  detail::TlsServerName name;
  const auto scope = host.find('%');
  if (scope != std::string::npos) {
    if (host.find(':') == std::string::npos || scope + 1 == host.size()) return std::nullopt;
    host.resize(scope);
  }
  if (inet_pton(AF_INET6, host.c_str(), name.address.data()) == 1) {
    name.address_size = 16;
  } else if (scope != std::string::npos) {
    return std::nullopt;
  } else if (inet_pton(AF_INET, host.c_str(), name.address.data()) == 1) {
    name.address_size = 4;
  } else {
    if (host.ends_with('.')) host.pop_back();
    // A name consisting of digits and dots must parse as an IPv4 address.
    if (!ValidDnsName(host) || std::ranges::all_of(host, [](char ch) { return (ch >= '0' && ch <= '9') || ch == '.'; }))
      return std::nullopt;
  }
  name.host = std::move(host);
  return name;
}

NetworkError ClosedListener() { return {NetworkErrorCode::Closed, 0, "The TLS listener is closed."}; }
#endif

} // namespace

#ifdef HUXERUI_LOCALNETWORK_TLS
TlsConnection::TlsConnection(std::shared_ptr<detail::TlsSocket> socket, ConnectionPath path, bool peer_authenticated)
    : socket_(std::move(socket)), path_(std::move(path)),
      input_(detail::MakeTlsInput(socket_)), output_(detail::MakeTlsOutput(socket_)),
      peer_authenticated_(peer_authenticated) {}
#endif

TlsConnection::TlsConnection(TlsConnection&&) noexcept = default;

TlsConnection& TlsConnection::operator=(TlsConnection&& other) noexcept {
  if (this != &other) {
    Close();
    socket_ = std::move(other.socket_);
    path_ = std::move(other.path_);
    input_ = std::move(other.input_);
    output_ = std::move(other.output_);
    peer_authenticated_ = other.peer_authenticated_;
  }
  return *this;
}

TlsConnection::~TlsConnection() { Close(); }
AsyncInputStream& TlsConnection::Input() noexcept { return input_; }
AsyncOutputStream& TlsConnection::Output() noexcept { return output_; }
const ConnectionPath& TlsConnection::Path() const noexcept { return path_; }
bool TlsConnection::IsPeerAuthenticated() const noexcept { return socket_ && peer_authenticated_; }
void TlsConnection::Close() noexcept { detail::CloseTlsSocket(socket_); }

bool IsTlsClientSupported() noexcept {
#ifdef HUXERUI_LOCALNETWORK_TLS
  return true;
#else
  return false;
#endif
}

Task<NetworkResult<TlsConnection>> DialTlsAsync(Endpoint endpoint, TlsDialOptions options) {
  using Result = NetworkResult<TlsConnection>;
#ifdef HUXERUI_LOCALNETWORK_TLS
  auto server = ParseServerName(options.server_name.empty() ? endpoint.host : std::move(options.server_name));
  if (!server) co_return Result::Failure({NetworkErrorCode::InvalidEndpoint, 0, "Invalid TLS server name."});
  const auto lease = options.tcp.wifi_lease;
  auto dialed = co_await DialTcpAsync(std::move(endpoint), std::move(options.tcp));
  if (!dialed.Succeeded()) co_return Result::Failure(dialed.Error());
  auto path = dialed.Value().Path();
  auto tls = co_await detail::ConnectSystemTls(std::move(dialed).Value(), std::move(*server));
  if (lease && !lease->AndroidNetwork())
    co_return Result::Failure({NetworkErrorCode::NetworkLost, 0, "The selected Wi-Fi network was lost."});
  if (!tls.Succeeded()) co_return Result::Failure(tls.Error());
  co_return Result::Success(TlsConnection(std::move(tls).Value(), std::move(path), true));
#else
  co_return Result::Failure({NetworkErrorCode::Unsupported, 0, "Direct TLS is unavailable on this platform."});
#endif
}

TlsListener::TlsListener(std::shared_ptr<detail::TlsListenerState> state) : state_(std::move(state)) {}
TlsListener::TlsListener(TlsListener&&) noexcept = default;

TlsListener& TlsListener::operator=(TlsListener&& other) noexcept {
  if (this != &other) {
    Close();
    state_ = std::move(other.state_);
  }
  return *this;
}

TlsListener::~TlsListener() { Close(); }

const Endpoint& TlsListener::LocalEndpoint() const noexcept {
  static const Endpoint empty;
#ifdef HUXERUI_LOCALNETWORK_TLS
  if (state_) return state_->listener.LocalEndpoint();
#endif
  return empty;
}

void TlsListener::Close() noexcept {
#ifdef HUXERUI_LOCALNETWORK_TLS
  if (!state_) return;
  std::scoped_lock lock(state_->mutex);
  state_->credentials.reset();
  state_->listener.Close();
  // An accepted TCP socket still negotiating TLS belongs to the listener until the handshake is handed off.
  if (state_->pending) state_->pending->Close();
#endif
}

Task<NetworkResult<TlsConnection>> TlsListener::AcceptAsync() { return Accept(state_); }

Task<NetworkResult<TlsConnection>> TlsListener::Accept(std::shared_ptr<detail::TlsListenerState> state) {
  using Result = NetworkResult<TlsConnection>;
#ifdef HUXERUI_LOCALNETWORK_TLS
  if (!state) co_return Result::Failure(ClosedListener());
  {
    std::scoped_lock lock(state->mutex);
    if (!state->credentials) co_return Result::Failure(ClosedListener());
    if (state->accepting) {
      co_return Result::Failure({NetworkErrorCode::Busy, 0, "The TLS listener already has a pending accept."});
    }
    state->accepting = true;
  }
  // Keep the accept slot through the handshake and release it if the task is canceled.
  struct PendingAccept {
    detail::TlsListenerState& state;
    ~PendingAccept() {
      std::scoped_lock lock(state.mutex);
      state.pending.reset();
      state.accepting = false;
    }
  } guard{*state};

  auto accepted = co_await state->listener.AcceptAsync();
  if (!accepted.Succeeded()) co_return Result::Failure(accepted.Error());
  auto path = accepted.Value().Path();
  auto socket = detail::TcpConnectionAccess::TakeSocket(accepted.Value());
  std::shared_ptr<detail::IdentityState> credentials;
  {
    std::scoped_lock lock(state->mutex);
    if (!state->credentials) co_return Result::Failure(ClosedListener());
    credentials = state->credentials;
    state->pending = socket;
  }
  auto tls = co_await detail::AcceptServerTls(std::move(socket), std::move(credentials));
  {
    std::scoped_lock lock(state->mutex);
    if (!state->credentials) co_return Result::Failure(ClosedListener());
    state->pending.reset();
  }
  if (!tls.Succeeded()) co_return Result::Failure(tls.Error());
  co_return Result::Success(TlsConnection(std::move(tls).Value(), std::move(path), false));
#else
  co_return Result::Failure({NetworkErrorCode::Unsupported, 0, "Direct TLS is unavailable on this platform."});
#endif
}

Task<NetworkResult<TlsListener>> ListenTlsAsync(TlsListenOptions options) {
  using Result = NetworkResult<TlsListener>;
#ifdef HUXERUI_LOCALNETWORK_TLS
  // Transfer the PEM before returning the lazy task, which may be discarded without running.
  auto prepare = detail::PrepareTlsServerCredentials(
      std::move(options.certificate_pem), std::move(options.private_key_pem));
  return [](Endpoint endpoint, decltype(prepare) prepare_credentials) -> Task<Result> {
    auto credentials = co_await std::move(prepare_credentials);
    if (!credentials.Succeeded()) co_return Result::Failure(credentials.Error());
    auto listener = co_await ListenTcpAsync(std::move(endpoint));
    if (!listener.Succeeded()) co_return Result::Failure(listener.Error());
    co_return Result::Success(TlsListener(std::make_shared<detail::TlsListenerState>(
        std::move(listener).Value(), std::move(credentials).Value())));
  }(std::move(options.endpoint), std::move(prepare));
#else
  co_return Result::Failure({NetworkErrorCode::Unsupported, 0, "Direct TLS is unavailable on this platform."});
#endif
}

} // namespace huxerui::localnetwork
