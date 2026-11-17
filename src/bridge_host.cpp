#include "bridge_backend.h"

#ifdef HUXERUI_LOCALNETWORK_WSLAY
#include "bridge_tls.h"

#include <algorithm>
#include <array>
#include <map>

#include <mbedtls/base64.h>
#include <mbedtls/sha1.h>

#ifdef _MSC_VER
#include <BaseTsd.h>
using ssize_t = SSIZE_T;
#endif
#include <wslay/wslay.h>
#endif

namespace huxerui::localnetwork {
namespace detail {

struct WebBridgeListenerState {
  Endpoint endpoint;
  std::string grant;
#ifdef HUXERUI_LOCALNETWORK_WSLAY
  std::string origin;
  TcpListener listener;
  std::shared_ptr<IdentityState> certificate;
  std::shared_ptr<SocketIo> active_socket;
  std::shared_ptr<PairedConnection> active_peer;
  bool closed = false;

  void Close() noexcept {
    closed = true;
    grant.clear();
    listener.Close();
    if (active_socket) active_socket->Close();
    if (active_peer) active_peer->Close();
  }
#endif
};

#ifdef HUXERUI_LOCALNETWORK_WSLAY
namespace {

using namespace std::chrono_literals;
constexpr auto retry_interval = 4ms;
constexpr std::size_t max_header_bytes = 8192;

char LowerAscii(char ch) {
  return ch >= 'A' && ch <= 'Z' ? static_cast<char>(ch + ('a' - 'A')) : ch;
}

bool EqualsAscii(std::string_view left, std::string_view right) {
  return std::ranges::equal(left, right, {}, LowerAscii, LowerAscii);
}

std::string_view TrimHeader(std::string_view value) {
  const auto first = value.find_first_not_of(" \t");
  if (first == std::string_view::npos) return {};
  return value.substr(first, value.find_last_not_of(" \t") - first + 1);
}

bool ContainsUpgrade(std::string_view tokens) {
  while (!tokens.empty()) {
    const auto comma = tokens.find(',');
    if (EqualsAscii(TrimHeader(tokens.substr(0, comma)), "upgrade")) return true;
    if (comma == std::string_view::npos) break;
    tokens.remove_prefix(comma + 1);
  }
  return false;
}

bool ValidOrigin(std::string_view origin) {
  const auto scheme = origin.find("://");
  if (scheme == std::string_view::npos) return false;
  const auto host = origin.substr(scheme + 3);
  if (host.empty() || host.find_first_of("/?#@*") != std::string_view::npos ||
      std::ranges::any_of(host, [](unsigned char ch) { return ch <= 32 || ch >= 127; })) return false;
  if (origin.starts_with("https://")) return true;
  if (!origin.starts_with("http://")) return false;
  const auto port = host.find(':', host.starts_with("[::1]") ? 5 : 0);
  const auto name = host.substr(0, port);
  return name == "localhost" || name == "127.0.0.1" || name == "[::1]";
}

std::string UpgradeResponse(std::string_view request, std::string_view origin) {
  const auto first = request.find("\r\n");
  const std::string request_line = std::string("GET ") + bridge_path + " HTTP/1.1";
  if (first == std::string_view::npos || request.substr(0, first) != request_line) return {};
  request.remove_prefix(first + 2);
  std::map<std::string, std::string_view, std::less<>> headers;
  while (!request.empty()) {
    const auto next = request.find("\r\n");
    if (next == std::string_view::npos) return {};
    if (next == 0) break;
    const auto line = request.substr(0, next);
    const auto colon = line.find(':');
    if (colon == 0 || colon == std::string_view::npos) return {};
    std::string name(line.substr(0, colon));
    std::ranges::transform(name, name.begin(), LowerAscii);
    if (!headers.emplace(std::move(name), TrimHeader(line.substr(colon + 1))).second) return {};
    request.remove_prefix(next + 2);
  }
  if (headers["host"].empty() || headers["origin"] != origin || !ContainsUpgrade(headers["connection"]) ||
      !EqualsAscii(headers["upgrade"], "websocket") || headers["sec-websocket-version"] != "13" ||
      headers["sec-websocket-protocol"] != bridge_protocol) return {};

  // RFC 6455 requires a base64 nonce and a SHA-1 response for this HTTP upgrade only.
  const auto key = headers["sec-websocket-key"];
  std::array<unsigned char, 16> nonce{};
  std::size_t count = 0;
  if (key.size() != 24 || mbedtls_base64_decode(nonce.data(), nonce.size(), &count,
      reinterpret_cast<const unsigned char*>(key.data()), key.size()) != 0 || count != nonce.size()) return {};
  const auto challenge = std::string(key) + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  std::array<unsigned char, 20> digest{};
  if (mbedtls_sha1(reinterpret_cast<const unsigned char*>(challenge.data()), challenge.size(), digest.data()) != 0)
    return {};
  std::array<unsigned char, 32> response{};
  if (mbedtls_base64_encode(response.data(), response.size(), &count, digest.data(), digest.size()) != 0) return {};
  return "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
         "Sec-WebSocket-Protocol: " + std::string(bridge_protocol) + "\r\nSec-WebSocket-Accept: " +
         std::string(reinterpret_cast<const char*>(response.data()), count) + "\r\n\r\n";
}

Task<bool> Upgrade(SocketIo& socket, std::string_view origin, BridgeClock::time_point deadline) {
  std::array<char, max_header_bytes> request{};
  std::size_t size = 0;
  while (size < request.size() && BridgeClock::now() < deadline) {
    auto read = socket.Receive(std::as_writable_bytes(std::span(request).subspan(size)));
    if (!read.Succeeded() || read.Value() == std::optional<std::size_t>(0)) co_return false;
    if (!read.Value()) {
      co_await Delay(retry_interval);
      continue;
    }
    size += *read.Value();
    std::string_view received(request.data(), size);
    const auto end = received.find("\r\n\r\n");
    if (end == std::string_view::npos) continue;
    // A browser starts sending WebSocket messages only after receiving the upgrade response.
    if (end + 4 != size) co_return false;
    auto response = UpgradeResponse(received, origin);
    auto bytes = std::as_bytes(std::span(response));
    if (bytes.empty()) co_return false;
    while (!bytes.empty() && BridgeClock::now() < deadline) {
      auto sent = socket.Send(bytes);
      if (!sent.Succeeded()) co_return false;
      if (sent.Value() == 0) co_await Delay(retry_interval);
      else bytes = bytes.subspan(sent.Value());
    }
    co_return bytes.empty();
  }
  co_return false;
}

class HostWebSocket final : public BridgeTransport {
public:
  explicit HostWebSocket(std::shared_ptr<SocketIo> socket) : socket_(std::move(socket)) {
    const wslay_event_callbacks callbacks{Receive, Send, nullptr, nullptr, nullptr, nullptr, OnMessage};
    if (wslay_event_context_server_init(&context_, &callbacks, this) == 0) {
      wslay_event_config_set_max_recv_msg_length(context_, bridge_chunk + 1);
    } else {
      context_ = nullptr;
    }
  }

  ~HostWebSocket() override {
    Close();
    if (context_) wslay_event_context_free(context_);
  }

  bool Poll() override {
    if (!context_ || failed_) return false;
    // Limit each poll and queued pongs even when a client sends a continuous stream of control frames.
    receive_budget_ = 2 * bridge_chunk;
    if (wslay_event_send(context_) != 0 || wslay_event_recv(context_) != 0 || wslay_event_send(context_) != 0)
      failed_ = true;
    return !failed_ && wslay_event_want_read(context_);
  }

  IoResult<bool> TrySend(std::span<const std::byte> packet) override {
    if (context_ && !failed_) {
      if (wslay_event_get_queued_msg_count(context_) >= 4) return IoResult<bool>::Success(false);
      const wslay_event_msg message{WSLAY_BINARY_FRAME, reinterpret_cast<const std::uint8_t*>(packet.data()),
                                   packet.size()};
      if (wslay_event_queue_msg(context_, &message) == 0) return IoResult<bool>::Success(true);
    }
    return IoResult<bool>::Failure({IoErrorCode::Io, "Could not queue a WSS message."});
  }

  Task<bool> Finish() {
    const auto deadline = BridgeClock::now() + 2s;
    while (!failed_ && wslay_event_want_write(context_) && BridgeClock::now() < deadline) {
      if (wslay_event_send(context_) != 0) co_return false;
      if (wslay_event_want_write(context_)) co_await Delay(retry_interval);
    }
    if (failed_ || wslay_event_want_write(context_)) co_return false;
    // WebSocket control frames have priority. Send Close only after the stream's End packet has been flushed.
    if (!wslay_event_get_close_sent(context_) &&
        (wslay_event_queue_close(context_, WSLAY_CODE_NORMAL_CLOSURE, nullptr, 0) != 0 ||
         wslay_event_send(context_) != 0)) co_return false;
    while (BridgeClock::now() < deadline && !wslay_event_get_close_received(context_) && Poll())
      co_await Delay(retry_interval);
    co_return wslay_event_get_close_sent(context_) != 0;
  }

  void Close() noexcept override {
    failed_ = true;
    socket_->Close();
  }

private:
  static ssize_t Receive(wslay_event_context_ptr context, std::uint8_t* bytes, std::size_t count, int, void* user) {
    auto& self = *static_cast<HostWebSocket*>(user);
    try {
      if (!self.failed_ && self.receive_budget_ && wslay_event_get_queued_msg_count(context) < 4) {
        auto read = self.socket_->Receive(std::as_writable_bytes(std::span(bytes, std::min(count, self.receive_budget_))));
        if (!read.Succeeded() || read.Value() == std::optional<std::size_t>(0)) {
          wslay_event_set_error(context, WSLAY_ERR_CALLBACK_FAILURE);
          return -1;
        }
        if (read.Value()) {
          self.receive_budget_ -= *read.Value();
          return static_cast<ssize_t>(*read.Value());
        }
      }
      wslay_event_set_error(context, WSLAY_ERR_WOULDBLOCK);
    } catch (...) {
      wslay_event_set_error(context, WSLAY_ERR_CALLBACK_FAILURE);
    }
    return -1;
  }

  static ssize_t Send(wslay_event_context_ptr context, const std::uint8_t* bytes, std::size_t count, int, void* user) {
    try {
      auto sent = static_cast<HostWebSocket*>(user)->socket_->Send(std::as_bytes(std::span(bytes, count)));
      if (sent.Succeeded() && sent.Value()) return static_cast<ssize_t>(sent.Value());
      wslay_event_set_error(context, sent.Succeeded() ? WSLAY_ERR_WOULDBLOCK : WSLAY_ERR_CALLBACK_FAILURE);
    } catch (...) {
      wslay_event_set_error(context, WSLAY_ERR_CALLBACK_FAILURE);
    }
    return -1;
  }

  static void OnMessage(wslay_event_context_ptr, const wslay_event_on_msg_recv_arg* message, void* user) {
    auto& self = *static_cast<HostWebSocket*>(user);
    if (wslay_is_ctrl_frame(message->opcode)) return;
    try {
      if (message->opcode == WSLAY_BINARY_FRAME &&
          self.ReceivePacket(std::as_bytes(std::span(message->msg, message->msg_length)))) return;
    } catch (...) {
      // A callback must never let an exception cross the C WebSocket library.
    }
    self.failed_ = true;
  }

  std::shared_ptr<SocketIo> socket_;
  wslay_event_context_ptr context_ = nullptr;
  std::size_t receive_budget_ = 0;
  bool failed_ = false;
};

Task<std::shared_ptr<HostWebSocket>> WaitForBrowser(std::shared_ptr<WebBridgeListenerState> state) {
  while (!state->closed) {
    auto accepted = co_await state->listener.AcceptAsync();
    if (!accepted.Succeeded() || state->closed) co_return nullptr;
    state->active_socket = TcpConnectionAccess::TakeSocket(accepted.Value());
    const auto deadline = BridgeClock::now() + 10s;
    auto tls = co_await AcceptBridgeTls(state->active_socket, state->certificate, deadline);
    if (!tls.Succeeded() || !co_await Upgrade(*tls.Value(), state->origin, deadline)) {
      state->active_socket.reset();
      continue;
    }
    auto wire = std::make_shared<HostWebSocket>(std::move(tls).Value());
    auto received = co_await ReadBridgePacket(*wire, deadline);
    if (received.Succeeded() && !state->closed) {
      const auto& packet = received.Value();
      if (packet.front() == static_cast<std::byte>(BridgePacket::Authenticate) &&
          CheckBridgeGrant(state->grant, {reinterpret_cast<const char*>(packet.data() + 1), packet.size() - 1})) {
        state->grant.clear();
        state->listener.Close();
        co_return wire;
      }
    }
    state->active_socket.reset();
  }
  co_return nullptr;
}

Task<IoResult<void>> Forward(AsyncInputStream& input, AsyncOutputStream& output) {
  auto copied = co_await input.CopyToAsync(output, bridge_chunk);
  if (!copied.Succeeded()) co_return IoResult<void>::Failure(std::move(copied).Error());
  co_return co_await output.CloseAsync();
}

Task<void> ForwardToPeer(std::shared_ptr<HostWebSocket> wire, std::shared_ptr<WebBridgeConnection> browser,
                         std::shared_ptr<PairedConnection> peer,
                         std::shared_ptr<std::optional<IoResult<void>>> result) {
  result->emplace(co_await Forward(browser->Input(), peer->Output()));
  if (!result->value().Succeeded()) {
    browser->Close();
  } else {
    // A browser can abandon the session after ending its output while the native peer is still idle.
    while (wire->Poll()) co_await Delay(retry_interval);
  }
  peer->Close();
}

Task<NetworkResult<void>> Relay(std::shared_ptr<WebBridgeListenerState> state, PairedConnection peer, TaskScope tasks) {
  using Result = NetworkResult<void>;
  if (!state || state->closed) co_return Result::Failure({NetworkErrorCode::Closed, 0, "The WSS listener is closed."});
  if (state->active_peer) co_return Result::Failure({NetworkErrorCode::Busy, 0, "A WSS relay is already running."});
  state->active_peer = std::make_shared<PairedConnection>(std::move(peer));
  struct RelayGuard {
    std::shared_ptr<WebBridgeListenerState> state;
    TaskHandle inbound;
    ~RelayGuard() {
      inbound.Cancel();
      state->Close();
      state->active_peer.reset();
      state->active_socket.reset();
    }
  } relay{state, {}};

  auto wire = co_await WaitForBrowser(state);
  if (!wire) co_return Result::Failure({NetworkErrorCode::Closed, 0, "The WSS listener stopped accepting browsers."});
  const auto& id = state->active_peer->Peer();
  const auto deadline = BridgeClock::now() + 10s;
  auto ready = co_await SendBridgePacket(*wire, MakeBridgePacket(BridgePacket::Ready, std::as_bytes(std::span(id.digest))),
                                        deadline);
  if (!ready.Succeeded()) co_return ready;
  auto opened = co_await BridgeAccess::Open(wire, id, deadline);
  if (!opened.Succeeded()) co_return Result::Failure(opened.Error());

  // Both stream pumps run independently so a write cannot block the return path or its flow-control credits.
  auto browser = std::make_shared<WebBridgeConnection>(std::move(opened).Value());
  auto inbound = std::make_shared<std::optional<IoResult<void>>>();
  relay.inbound = tasks.Launch(ForwardToPeer(wire, browser, state->active_peer, inbound));
  auto outbound = co_await Forward(state->active_peer->Input(), browser->Output());
  while (outbound.Succeeded() && !inbound->has_value() && !state->closed) co_await Delay(retry_interval);
  if (inbound->has_value() && !inbound->value().Succeeded()) {
    co_return Result::Failure({NetworkErrorCode::ConnectionFailed, 0, inbound->value().Error().message});
  }
  if (!outbound.Succeeded()) co_return Result::Failure({NetworkErrorCode::ConnectionFailed, 0, outbound.Error().message});
  if (state->closed || !co_await wire->Finish()) {
    co_return Result::Failure({NetworkErrorCode::Closed, 0, "The WSS relay closed before completing."});
  }
  co_return Result::Success();
}

} // namespace
#endif
} // namespace detail

WebBridgeListener::WebBridgeListener(std::shared_ptr<detail::WebBridgeListenerState> state) : state_(std::move(state)) {}
WebBridgeListener::WebBridgeListener(WebBridgeListener&&) noexcept = default;
WebBridgeListener& WebBridgeListener::operator=(WebBridgeListener&& other) noexcept {
  if (this != &other) {
    Close();
    state_ = std::move(other.state_);
  }
  return *this;
}
WebBridgeListener::~WebBridgeListener() { Close(); }

const Endpoint& WebBridgeListener::LocalEndpoint() const noexcept {
  static const Endpoint empty;
  return state_ ? state_->endpoint : empty;
}
std::string_view WebBridgeListener::Grant() const noexcept { return state_ ? std::string_view(state_->grant) : ""; }
void WebBridgeListener::Close() noexcept {
#ifdef HUXERUI_LOCALNETWORK_WSLAY
  if (state_) state_->Close();
#endif
}

Task<NetworkResult<void>> WebBridgeListener::RelayAsync(PairedConnection peer, TaskScope tasks) {
#ifdef HUXERUI_LOCALNETWORK_WSLAY
  return detail::Relay(state_, std::move(peer), std::move(tasks));
#else
  co_return NetworkResult<void>::Failure({NetworkErrorCode::Unsupported, 0, "A desktop WSS bridge is unavailable."});
#endif
}

Task<NetworkResult<WebBridgeListener>> ListenWebBridgeAsync(WebBridgeListenOptions options) {
  using Result = NetworkResult<WebBridgeListener>;
#ifdef HUXERUI_LOCALNETWORK_WSLAY
  if (!detail::ValidOrigin(options.origin) || options.certificate_pem.empty() || options.private_key_pem.empty()) {
    co_return Result::Failure({NetworkErrorCode::InvalidEndpoint, 0, "A WSS origin, certificate, and key are required."});
  }
  auto credentials = co_await detail::PrepareBridgeCredentials(
      std::move(options.certificate_pem), std::move(options.private_key_pem));
  if (!credentials.Succeeded()) co_return Result::Failure(credentials.Error());
  auto listening = co_await ListenTcpAsync(options.endpoint);
  if (!listening.Succeeded()) co_return Result::Failure(listening.Error());
  auto endpoint = listening.Value().LocalEndpoint();
  co_return Result::Success(WebBridgeListener(std::make_shared<detail::WebBridgeListenerState>(
      detail::WebBridgeListenerState{std::move(endpoint), std::move(credentials.Value().grant), std::move(options.origin),
                                    std::move(listening).Value(), std::move(credentials.Value().certificate), {}, {}})));
#else
  co_return Result::Failure({NetworkErrorCode::Unsupported, 0, "A desktop WSS bridge is unavailable."});
#endif
}

} // namespace huxerui::localnetwork
