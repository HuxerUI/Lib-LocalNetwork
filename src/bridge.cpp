#include "bridge_backend.h"

#include <algorithm>
#include <utility>

namespace huxerui::localnetwork::detail {
namespace {

using namespace std::chrono_literals;

IoError BridgeIoError() { return {IoErrorCode::Io, "The WSS bridge connection was closed or sent an invalid packet."}; }
NetworkError BridgeTimeout() { return {NetworkErrorCode::TimedOut, 0, "The WSS bridge handshake timed out."}; }
NetworkError BridgeClosed() { return {NetworkErrorCode::ConnectionFailed, 0, "The WSS bridge connection was closed."}; }

} // namespace

std::optional<Bytes> BridgeTransport::TakePacket() {
  if (incoming_.empty()) return std::nullopt;
  auto packet = std::move(incoming_.front());
  incoming_.pop_front();
  return packet;
}

bool BridgeTransport::ReceivePacket(std::span<const std::byte> packet) {
  if (packet.empty() || packet.size() > bridge_chunk + 1 || incoming_.size() == 4) return false;
  incoming_.emplace_back(packet.begin(), packet.end());
  return true;
}

Bytes MakeBridgePacket(BridgePacket type, std::span<const std::byte> body) {
  Bytes packet;
  packet.reserve(body.size() + 1);
  packet.push_back(static_cast<std::byte>(type));
  packet.insert(packet.end(), body.begin(), body.end());
  return packet;
}

bool ValidBridgeGrant(std::string_view grant) {
  return grant.size() == bridge_grant_size && std::ranges::all_of(grant, [](char ch) {
    return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
  });
}

Task<NetworkResult<void>> SendBridgePacket(BridgeTransport& transport, Bytes packet, BridgeClock::time_point deadline) {
  using Result = NetworkResult<void>;
  while (BridgeClock::now() < deadline) {
    if (!transport.Poll()) co_return Result::Failure(BridgeClosed());
    auto sent = transport.TrySend(packet);
    if (!sent.Succeeded()) co_return Result::Failure(BridgeClosed());
    if (sent.Value()) co_return Result::Success();
    co_await Delay(4ms);
  }
  co_return Result::Failure(BridgeTimeout());
}

Task<NetworkResult<Bytes>> ReadBridgePacket(BridgeTransport& transport, BridgeClock::time_point deadline) {
  using Result = NetworkResult<Bytes>;
  while (BridgeClock::now() < deadline) {
    const bool open = transport.Poll();
    if (auto packet = transport.TakePacket()) co_return Result::Success(std::move(*packet));
    if (!open) co_return Result::Failure(BridgeClosed());
    co_await Delay(4ms);
  }
  co_return Result::Failure(BridgeTimeout());
}

class BridgeSession final {
public:
  explicit BridgeSession(std::shared_ptr<BridgeTransport> transport) : transport_(std::move(transport)) {}
  ~BridgeSession() { Close(); }

  Task<IoResult<void>> InitialCredit(BridgeClock::time_point deadline) { return GrantCredit(deadline); }

  Task<IoResult<Bytes>> Read(std::stop_token stop, std::size_t maximum) {
    using Result = IoResult<Bytes>;
    std::stop_callback canceled(stop, [this] { Close(); });
    while (Pump()) {
      if (!received_.empty()) {
        const auto available = std::span(received_).subspan(offset_);
        const auto chunk = available.first(std::min(maximum, available.size()));
        Bytes bytes(chunk.begin(), chunk.end());
        offset_ += bytes.size();
        if (offset_ == received_.size()) {
          received_.clear();
          offset_ = 0;
          auto granted = co_await GrantCredit(BridgeClock::time_point::max());
          if (!granted.Succeeded()) co_return Result::Failure(std::move(granted).Error());
        }
        co_return Result::Success(std::move(bytes));
      }
      if (input_ended_) co_return Result::Success({});
      co_await Delay(4ms);
    }
    co_return Result::Failure(BridgeIoError());
  }

  Task<IoResult<void>> Write(std::stop_token stop, Bytes bytes) {
    using Result = IoResult<void>;
    std::stop_callback canceled(stop, [this] { Close(); });
    std::span<const std::byte> remaining(bytes);
    while (!remaining.empty()) {
      if (!Pump()) co_return Result::Failure(BridgeIoError());
      if (!send_credit_) {
        co_await Delay(4ms);
        continue;
      }
      const auto chunk = remaining.first(std::min(remaining.size(), bridge_chunk));
      const auto packet = MakeBridgePacket(BridgePacket::Data, chunk);
      auto sent = transport_->TrySend(packet);
      if (!sent.Succeeded()) { Close(); co_return Result::Failure(BridgeIoError()); }
      if (!sent.Value()) { co_await Delay(4ms); continue; }
      send_credit_ = false;
      remaining = remaining.subspan(chunk.size());
    }
    co_return Result::Success();
  }

  Task<IoResult<void>> Finish(std::stop_token stop) {
    using Result = IoResult<void>;
    std::stop_callback canceled(stop, [this] { Close(); });
    const auto packet = MakeBridgePacket(BridgePacket::End);
    while (Pump()) {
      auto sent = transport_->TrySend(packet);
      if (!sent.Succeeded()) break;
      if (sent.Value()) {
        output_ended_ = true;
        co_return Result::Success();
      }
      co_await Delay(4ms);
    }
    Close();
    co_return Result::Failure(BridgeIoError());
  }

  void Close() noexcept {
    if (std::exchange(closed_, true)) return;
    transport_->Close();
  }

private:
  bool Pump() {
    if (closed_) return false;
    const auto open = transport_->Poll();
    while (auto packet = transport_->TakePacket()) {
      const auto type = static_cast<BridgePacket>(packet->front());
      if (type == BridgePacket::Credit && packet->size() == 1 && (!send_credit_ || output_ended_)) {
        send_credit_ = true;
      } else if (type == BridgePacket::Data && packet->size() > 1 && receive_credit_ && !input_ended_) {
        receive_credit_ = false;
        received_ = std::move(*packet);
        offset_ = 1;
      } else if (type == BridgePacket::End && packet->size() == 1 && !input_ended_) {
        input_ended_ = true;
      } else {
        Close();
        return false;
      }
    }
    if (open || (input_ended_ && output_ended_)) return true;
    Close();
    return false;
  }

  Task<IoResult<void>> GrantCredit(BridgeClock::time_point deadline) {
    using Result = IoResult<void>;
    const auto packet = MakeBridgePacket(BridgePacket::Credit);
    // The peer may send one data packet per credit. Refill only after the reader consumes that packet.
    while (BridgeClock::now() < deadline && Pump()) {
      if (input_ended_) co_return Result::Success();
      auto sent = transport_->TrySend(packet);
      if (!sent.Succeeded()) break;
      if (sent.Value()) {
        receive_credit_ = true;
        co_return Result::Success();
      }
      co_await Delay(4ms);
    }
    Close();
    co_return Result::Failure(BridgeIoError());
  }

  std::shared_ptr<BridgeTransport> transport_;
  Bytes received_;
  std::size_t offset_ = 0;
  bool receive_credit_ = false;
  bool send_credit_ = false;
  bool input_ended_ = false;
  bool output_ended_ = false;
  bool closed_ = false;
};

Task<NetworkResult<WebBridgeConnection>> BridgeAccess::Open(
    std::shared_ptr<BridgeTransport> transport, PeerId peer, BridgeClock::time_point deadline) {
  using Result = NetworkResult<WebBridgeConnection>;
  auto session = std::make_shared<BridgeSession>(std::move(transport));
  auto credit = co_await session->InitialCredit(deadline);
  if (!credit.Succeeded()) co_return Result::Failure(BridgeClosed());
  co_return Result::Success(WebBridgeConnection(std::move(session), peer));
}

} // namespace huxerui::localnetwork::detail

namespace huxerui::localnetwork {

WebBridgeConnection::WebBridgeConnection(std::shared_ptr<detail::BridgeSession> session, PeerId peer)
    : session_(std::move(session)), peer_(peer),
      input_(AsyncInputStream::FromReader([session = session_](std::stop_token stop, std::size_t maximum) {
        return session->Read(stop, maximum);
      })),
      output_(AsyncOutputStream::FromWriter(
          [session = session_](std::stop_token stop, Bytes bytes) { return session->Write(stop, std::move(bytes)); },
          [session = session_](std::stop_token stop) { return session->Finish(stop); })) {}

WebBridgeConnection::WebBridgeConnection(WebBridgeConnection&&) noexcept = default;

WebBridgeConnection& WebBridgeConnection::operator=(WebBridgeConnection&& other) noexcept {
  if (this != &other) {
    Close();
    session_ = std::move(other.session_);
    peer_ = other.peer_;
    input_ = std::move(other.input_);
    output_ = std::move(other.output_);
  }
  return *this;
}

WebBridgeConnection::~WebBridgeConnection() { Close(); }
AsyncInputStream& WebBridgeConnection::Input() noexcept { return input_; }
AsyncOutputStream& WebBridgeConnection::Output() noexcept { return output_; }
const PeerId& WebBridgeConnection::Peer() const noexcept { return peer_; }
void WebBridgeConnection::Close() noexcept { if (session_) session_->Close(); }

Task<NetworkResult<WebBridgeConnection>> ConnectWebBridgeAsync(WebBridgeDialOptions options) {
#ifdef __EMSCRIPTEN__
  return detail::ConnectBrowserBridge(std::move(options));
#else
  co_return NetworkResult<WebBridgeConnection>::Failure(
      {NetworkErrorCode::Unsupported, 0, "The WSS bridge client requires a Web build."});
#endif
}

} // namespace huxerui::localnetwork
