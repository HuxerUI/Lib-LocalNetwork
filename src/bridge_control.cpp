#include "bridge_control_protocol.h"

#include <type_traits>
#include <utility>

namespace huxerui::localnetwork::detail {

struct BridgeControlState {
  std::shared_ptr<BridgeTransport> wire;
  std::string url;
  bool busy = false;
};

namespace {

using namespace std::chrono_literals;

template<class... Values>
Bytes Request(BridgeOperation operation, const Values&... values) {
  ControlWriter writer(BridgePacket::Request);
  writer.Write(static_cast<std::uint8_t>(operation));
  (writer.Write(values), ...);
  return std::move(writer).Take();
}

Task<NetworkResult<Bytes>> Exchange(std::shared_ptr<BridgeControlState> state, Bytes request) {
  using Result = NetworkResult<Bytes>;
  if (!state || !state->wire->Poll())
    co_return Result::Failure({NetworkErrorCode::Closed, 0, "The WSS control connection is closed."});
  if (state->busy)
    co_return Result::Failure({NetworkErrorCode::Busy, 0, "Another WSS control request is pending."});
  if (request.empty()) co_return Result::Failure(BridgeProtocolError());
  state->busy = true;
  struct ExchangeGuard {
    BridgeControlState& state;
    bool received = false;
    ~ExchangeGuard() {
      // An abandoned request can leave an unread reply. Closing preserves request order and releases host resources.
      if (!received) state.wire->Close();
      state.busy = false;
    }
  } guard{*state};
  const auto deadline = BridgeClock::now() + 30s;
  auto sent = co_await SendBridgePacket(*state->wire, std::move(request), deadline);
  if (!sent.Succeeded()) co_return Result::Failure(sent.Error());
  auto incoming = co_await ReadBridgePacket(*state->wire, deadline);
  if (!incoming.Succeeded()) co_return incoming;
  const auto& packet = incoming.Value();
  if (packet.front() == static_cast<std::byte>(BridgePacket::Failure)) {
    guard.received = true;
    co_return Result::Failure(ReadBridgeFailure(std::span(packet).subspan(1)));
  }
  if (packet.front() != static_cast<std::byte>(BridgePacket::Response))
    co_return Result::Failure(BridgeProtocolError());
  guard.received = true;
  co_return incoming;
}

template<class Decode>
Task<NetworkResult<std::invoke_result_t<Decode, ControlReader&>>> ReadReply(
    std::shared_ptr<BridgeControlState> state, Bytes request, Decode decode) {
  using Value = std::invoke_result_t<Decode, ControlReader&>;
  using Result = NetworkResult<Value>;
  auto reply = co_await Exchange(state, std::move(request));
  if (!reply.Succeeded()) co_return Result::Failure(reply.Error());
  ControlReader reader(std::span(reply.Value()).subspan(1));
  if constexpr (std::is_void_v<Value>) {
    decode(reader);
    if (reader.Done()) co_return Result::Success();
  } else {
    auto value = decode(reader);
    if (reader.Done()) co_return Result::Success(std::move(value));
  }
  state->wire->Close();
  co_return Result::Failure(BridgeProtocolError());
}

std::vector<DiscoveredService> ReadServices(ControlReader& reader) {
  auto count = reader.U32();
  std::vector<DiscoveredService> services;
  if (count > bridge_service_limit) {
    reader.Reject();
    return services;
  }
  services.reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) services.push_back(reader.ReadService());
  return services;
}

ResolvedService ReadResolution(ControlReader& reader) {
  const auto count = reader.U32();
  ResolvedService service;
  if (count > bridge_service_limit) {
    reader.Reject();
    return service;
  }
  service.endpoints.reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) service.endpoints.push_back(reader.ReadEndpoint());
  service.txt = reader.ReadTxt();
  return service;
}

Task<NetworkResult<WebBridgeConnection>> OpenData(std::shared_ptr<BridgeControlState> state, Bytes request,
                                                   std::optional<PeerId> expected) {
  using Result = NetworkResult<WebBridgeConnection>;
#ifdef __EMSCRIPTEN__
  auto grant = co_await ReadReply(state, std::move(request), [](ControlReader& reader) { return reader.String(); });
  if (!grant.Succeeded()) co_return Result::Failure(grant.Error());
  if (!ValidBridgeGrant(grant.Value())) {
    state->wire->Close();
    co_return Result::Failure(BridgeProtocolError());
  }
  co_return co_await ConnectBrowserData({state->url, std::move(grant).Value(), expected});
#else
  co_return Result::Failure({NetworkErrorCode::Unsupported, 0, "The WSS bridge client requires a Web build."});
#endif
}

} // namespace
} // namespace huxerui::localnetwork::detail

namespace huxerui::localnetwork {

WebBridgeControl::WebBridgeControl(std::shared_ptr<detail::BridgeControlState> state) : state_(std::move(state)) {}
WebBridgeControl::WebBridgeControl(WebBridgeControl&&) noexcept = default;

WebBridgeControl& WebBridgeControl::operator=(WebBridgeControl&& other) noexcept {
  if (this != &other) {
    Close();
    state_ = std::move(other.state_);
  }
  return *this;
}

WebBridgeControl::~WebBridgeControl() { Close(); }

void WebBridgeControl::Close() noexcept {
  if (state_) state_->wire->Close();
}

Task<NetworkResult<std::vector<DiscoveredService>>> WebBridgeControl::BrowseAsync(std::string type) {
  return detail::ReadReply(state_, detail::Request(detail::BridgeOperation::Browse, type), detail::ReadServices);
}

Task<NetworkResult<ResolvedService>> WebBridgeControl::ResolveAsync(DiscoveredService service) {
  return detail::ReadReply(state_, detail::Request(detail::BridgeOperation::Resolve, service), detail::ReadResolution);
}

Task<NetworkResult<WebBridgeConnection>> WebBridgeControl::DialAsync(Endpoint endpoint, PeerId peer,
                                                                     std::string pairing_code) {
  return detail::OpenData(state_, detail::Request(detail::BridgeOperation::Dial, endpoint, peer, pairing_code), peer);
}

Task<NetworkResult<WebBridgeRegistration>> WebBridgeControl::ListenAsync() {
  return detail::ReadReply(state_, detail::Request(detail::BridgeOperation::Listen), [](detail::ControlReader& reader) {
    const auto id = reader.U32();
    if (id == 0) reader.Reject();
    return WebBridgeRegistration{id, reader.ReadEndpoint()};
  });
}

Task<NetworkResult<void>> WebBridgeControl::PublishAsync(std::uint32_t listener, std::string name, std::string type,
                                                         ServiceTxt txt) {
  return detail::ReadReply(state_, detail::Request(detail::BridgeOperation::Publish, listener, name, type, txt),
                           [](detail::ControlReader&) {});
}

Task<NetworkResult<void>> WebBridgeControl::WithdrawAsync(std::uint32_t listener) {
  return detail::ReadReply(state_, detail::Request(detail::BridgeOperation::Withdraw, listener),
                           [](detail::ControlReader&) {});
}

Task<NetworkResult<WebBridgeConnection>> WebBridgeControl::AcceptAsync(std::uint32_t listener) {
  return detail::OpenData(state_, detail::Request(detail::BridgeOperation::Accept, listener), std::nullopt);
}

Task<NetworkResult<void>> WebBridgeControl::CloseListenerAsync(std::uint32_t listener) {
  return detail::ReadReply(state_, detail::Request(detail::BridgeOperation::CloseListener, listener),
                           [](detail::ControlReader&) {});
}

Task<NetworkResult<WebBridgeControl>> ConnectWebBridgeControlAsync(WebBridgeControlOptions options) {
  using Result = NetworkResult<WebBridgeControl>;
#ifdef __EMSCRIPTEN__
  using namespace std::chrono_literals;
  if (!detail::ValidBridgeGrant(options.grant))
    co_return Result::Failure({NetworkErrorCode::InvalidEndpoint, 0, "A valid WSS control grant is required."});
  auto opened = co_await detail::OpenBrowserBridge(options.url);
  if (!opened.Succeeded()) co_return Result::Failure(opened.Error());
  auto wire = std::move(opened).Value();
  const auto deadline = detail::BridgeClock::now() + 15s;
  auto sent = co_await detail::SendBridgePacket(*wire, detail::MakeBridgePacket(
      detail::BridgePacket::ControlAuthenticate, std::as_bytes(std::span(options.grant))), deadline);
  if (!sent.Succeeded()) co_return Result::Failure(sent.Error());
  auto ready = co_await detail::ReadBridgePacket(*wire, deadline);
  if (!ready.Succeeded()) co_return Result::Failure(ready.Error());
  if (ready.Value() != detail::MakeBridgePacket(detail::BridgePacket::ControlReady))
    co_return Result::Failure(detail::BridgeProtocolError());
  co_return Result::Success(WebBridgeControl(std::make_shared<detail::BridgeControlState>(
      detail::BridgeControlState{std::move(wire), std::move(options.url)})));
#else
  co_return Result::Failure({NetworkErrorCode::Unsupported, 0, "The WSS bridge client requires a Web build."});
#endif
}

} // namespace huxerui::localnetwork
