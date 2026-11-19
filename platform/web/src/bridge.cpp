#include "../../../src/bridge_control_protocol.h"

#include <algorithm>
#include <utility>

#include <emscripten/em_js.h>
#include <emscripten/websocket.h>

namespace huxerui::localnetwork::detail {
namespace {

using namespace std::chrono_literals;

// The browser URL parser also handles IPv6 literals and rejects malformed ports before WebSocket construction.
EM_JS(bool, ValidBrowserBridgeUrl, (const char* address, const char* bridge_endpoint), {
  try {
    const value = new URL(UTF8ToString(address));
    return value.protocol === 'wss:' && value.hostname && !value.username && !value.password &&
        !value.search && !value.hash && value.pathname === UTF8ToString(bridge_endpoint);
  } catch {
    return false;
  }
});

class BrowserWebSocket final : public BridgeTransport {
public:
  ~BrowserWebSocket() override { Close(); }

  bool Start(const std::string& url) {
    EmscriptenWebSocketCreateAttributes options{url.c_str(), bridge_protocol, true};
    socket_ = emscripten_websocket_new(&options);
    if (socket_ <= 0) return false;
    return emscripten_websocket_set_onopen_callback(socket_, this, OnOpen) == EMSCRIPTEN_RESULT_SUCCESS &&
        emscripten_websocket_set_onerror_callback(socket_, this, OnError) == EMSCRIPTEN_RESULT_SUCCESS &&
        emscripten_websocket_set_onclose_callback(socket_, this, OnClose) == EMSCRIPTEN_RESULT_SUCCESS &&
        emscripten_websocket_set_onmessage_callback(socket_, this, OnMessage) == EMSCRIPTEN_RESULT_SUCCESS;
  }

  bool Open() const noexcept { return open_; }
  bool Poll() override { return socket_ > 0 && !ended_; }

  IoResult<bool> TrySend(std::span<const std::byte> packet) override {
    size_t pending = 0;
    if (Open() && emscripten_websocket_get_buffered_amount(socket_, &pending) == EMSCRIPTEN_RESULT_SUCCESS) {
      if (pending > bridge_chunk + 1) return IoResult<bool>::Success(false);
      // The browser copies the packet before returning. Other writes wait for the peer's credit.
      if (emscripten_websocket_send_binary(socket_, const_cast<std::byte*>(packet.data()), packet.size()) ==
          EMSCRIPTEN_RESULT_SUCCESS) return IoResult<bool>::Success(true);
    }
    return IoResult<bool>::Failure({IoErrorCode::Io, "Could not send a browser WSS message."});
  }

  void Close() noexcept override {
    open_ = false;
    ended_ = true;
    if (const auto socket = std::exchange(socket_, 0); socket > 0) {
      emscripten_websocket_close(socket, 1000, nullptr);
      // Deleting the Emscripten handle detaches all callbacks before their user pointer expires.
      emscripten_websocket_delete(socket);
    }
  }

private:
  static bool OnOpen(int, const EmscriptenWebSocketOpenEvent*, void* user) {
    auto& self = *static_cast<BrowserWebSocket*>(user);
    char protocol[sizeof(bridge_protocol)]{};
    if (emscripten_websocket_get_protocol(self.socket_, protocol, sizeof(protocol)) != EMSCRIPTEN_RESULT_SUCCESS ||
        std::string_view(protocol) != bridge_protocol) self.Close();
    else self.open_ = true;
    return false;
  }

  static bool OnError(int, const EmscriptenWebSocketErrorEvent*, void* user) {
    static_cast<BrowserWebSocket*>(user)->Close();
    return false;
  }

  static bool OnClose(int, const EmscriptenWebSocketCloseEvent*, void* user) {
    auto& self = *static_cast<BrowserWebSocket*>(user);
    self.open_ = false;
    self.ended_ = true;
    return false;
  }

  static bool OnMessage(int, const EmscriptenWebSocketMessageEvent* message, void* user) {
    auto& self = *static_cast<BrowserWebSocket*>(user);
    try {
      if (!message->isText && self.ReceivePacket(std::as_bytes(std::span(message->data, message->numBytes))))
        return false;
    } catch (...) {
      // Reject the session without unwinding through the browser callback.
    }
    self.Close();
    return false;
  }

  EMSCRIPTEN_WEBSOCKET_T socket_ = 0;
  bool open_ = false;
  bool ended_ = false;
};

} // namespace

bool IsBrowserBridgeSupported() noexcept { return emscripten_websocket_is_supported(); }

Task<NetworkResult<std::shared_ptr<BridgeTransport>>> OpenBrowserBridge(std::string url) {
  using Result = NetworkResult<std::shared_ptr<BridgeTransport>>;
  if (url.find_first_of("?#@") != std::string::npos || url.find('\0') != std::string::npos ||
      !url.starts_with("wss://") || !ValidBrowserBridgeUrl(url.c_str(), bridge_path)) {
    co_return Result::Failure({NetworkErrorCode::InvalidEndpoint, 0, "A valid WSS URL is required."});
  }
  auto socket = std::make_shared<BrowserWebSocket>();
  if (!IsBrowserBridgeSupported()) {
    co_return Result::Failure({NetworkErrorCode::Unsupported, 0, "The browser does not support WebSocket."});
  }
  if (!socket->Start(url)) {
    co_return Result::Failure({NetworkErrorCode::ConnectionFailed, 0, "Could not start the browser WSS connection."});
  }

  const auto deadline = BridgeClock::now() + 15s;
  while (socket->Poll() && !socket->Open()) {
    if (BridgeClock::now() >= deadline) {
      co_return Result::Failure({NetworkErrorCode::TimedOut, 0, "The browser WSS connection timed out."});
    }
    co_await Delay(4ms);
  }
  if (!socket->Open())
    co_return Result::Failure({NetworkErrorCode::ConnectionFailed, 0, "The browser WSS connection was closed."});
  co_return Result::Success(std::move(socket));
}

namespace {

Task<NetworkResult<WebBridgeConnection>> ConnectData(WebBridgeDialOptions options, bool managed) {
  using Result = NetworkResult<WebBridgeConnection>;
  if (!ValidBridgeGrant(options.grant)) {
    co_return Result::Failure({NetworkErrorCode::InvalidEndpoint, 0, "A valid one-time WSS grant is required."});
  }
  auto opened = co_await OpenBrowserBridge(std::move(options.url));
  if (!opened.Succeeded()) co_return Result::Failure(opened.Error());
  auto socket = std::move(opened).Value();
  const auto deadline = BridgeClock::now() + 15s;
  auto authenticated = co_await SendBridgePacket(
      *socket, MakeBridgePacket(BridgePacket::Authenticate, std::as_bytes(std::span(options.grant))), deadline);
  if (!authenticated.Succeeded()) co_return Result::Failure(authenticated.Error());
  // A registered listener can wait for an incoming peer after the browser has opened its data socket.
  auto ready = co_await ReadBridgePacket(*socket, managed ? BridgeClock::time_point::max() : deadline);
  if (!ready.Succeeded()) co_return Result::Failure(ready.Error());

  PeerId peer;
  const auto& packet = ready.Value();
  if (managed && packet.front() == static_cast<std::byte>(BridgePacket::Failure))
    co_return Result::Failure(ReadBridgeFailure(std::span(packet).subspan(1)));
  if (packet.size() != peer.digest.size() + 1 || packet.front() != static_cast<std::byte>(BridgePacket::Ready)) {
    co_return Result::Failure({NetworkErrorCode::Protocol, 0, "The WSS bridge sent an invalid peer identity."});
  }
  std::ranges::copy(std::span(packet).subspan(1), std::as_writable_bytes(std::span(peer.digest)).begin());
  if (options.expected_peer && *options.expected_peer != peer) {
    co_return Result::Failure({NetworkErrorCode::Authentication, 0, "The WSS bridge reported an unexpected peer."});
  }
  co_return co_await BridgeAccess::Open(std::move(socket), peer, BridgeClock::now() + 15s);
}

} // namespace

Task<NetworkResult<WebBridgeConnection>> ConnectBrowserBridge(WebBridgeDialOptions options) {
  return ConnectData(std::move(options), false);
}

Task<NetworkResult<WebBridgeConnection>> ConnectBrowserData(WebBridgeDialOptions options) {
  return ConnectData(std::move(options), true);
}

} // namespace huxerui::localnetwork::detail
