#include "bridge_control_protocol.h"

namespace huxerui::localnetwork::detail {

void ControlWriter::Write(std::string_view value) {
  if (bytes_.empty()) return;
  const auto capacity = bridge_chunk + 1 - bytes_.size();
  if (capacity < sizeof(std::uint32_t) || value.size() > capacity - sizeof(std::uint32_t)) {
    bytes_.clear();
    return;
  }
  Write(static_cast<std::uint32_t>(value.size()));
  const auto bytes = std::as_bytes(std::span(value));
  bytes_.insert(bytes_.end(), bytes.begin(), bytes.end());
}

void ControlWriter::Write(const Endpoint& value) {
  Write(value.host);
  Write(value.port);
}

void ControlWriter::Write(const PeerId& value) {
  for (auto byte : value.digest) Write(byte);
}

void ControlWriter::Write(const DiscoveredService& value) {
  Write(value.display_name);
  Write(value.type);
  Write(value.instance_id);
  Write(value.scope);
}

void ControlWriter::Write(const ServiceTxt& value) {
  if (value.size() > bridge_txt_limit) {
    bytes_.clear();
    return;
  }
  Write(static_cast<std::uint32_t>(value.size()));
  for (const auto& [key, text] : value) {
    Write(key);
    Write(text);
  }
}

std::span<const std::byte> ControlReader::Read(std::size_t size) {
  if (!valid_ || size > body_.size()) {
    valid_ = false;
    return {};
  }
  const auto bytes = body_.first(size);
  body_ = body_.subspan(size);
  return bytes;
}

std::string ControlReader::String() {
  const auto bytes = Read(U32());
  if (bytes.empty()) return {};
  return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

Endpoint ControlReader::ReadEndpoint() { return {String(), U16()}; }

PeerId ControlReader::ReadPeer() {
  PeerId peer;
  for (auto& byte : peer.digest) byte = U8();
  return peer;
}

DiscoveredService ControlReader::ReadService() { return {String(), String(), String(), U64()}; }

ServiceTxt ControlReader::ReadTxt() {
  ServiceTxt txt;
  const auto count = U32();
  if (count > bridge_txt_limit) valid_ = false;
  for (std::uint32_t i = 0; valid_ && i < count; ++i) {
    auto key = String();
    auto value = String();
    if (!txt.emplace(std::move(key), std::move(value)).second) valid_ = false;
  }
  return txt;
}

NetworkError BridgeProtocolError() { return {NetworkErrorCode::Protocol, 0, "Invalid WSS control message."}; }

Bytes BridgeFailure(const NetworkError& error) {
  ControlWriter reply(BridgePacket::Failure);
  reply.Write(static_cast<std::uint32_t>(error.code));
  reply.Write(static_cast<std::uint32_t>(error.diagnostic_code));
  reply.Write(std::string_view(error.message).substr(0, 512));
  return std::move(reply).Take();
}

NetworkError ReadBridgeFailure(std::span<const std::byte> body) {
  ControlReader reader(body);
  const auto code = reader.U32();
  const auto diagnostic = static_cast<std::int32_t>(reader.U32());
  auto message = reader.String();
  if (!reader.Done() || code > static_cast<std::uint32_t>(NetworkErrorCode::WifiJoinFailed)) return BridgeProtocolError();
  return {static_cast<NetworkErrorCode>(code), diagnostic, std::move(message)};
}

} // namespace huxerui::localnetwork::detail
