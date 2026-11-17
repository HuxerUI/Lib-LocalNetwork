#pragma once

#include <utility>

#include "bridge_backend.h"

namespace huxerui::localnetwork::detail {

// Each control frame carries one request or reply. The sender bounds it to the existing WSS message limit.
enum class BridgeOperation : std::uint8_t {
  Browse = 1, Resolve = 2, Dial = 3, Listen = 4, Publish = 5, Withdraw = 6, Accept = 7, CloseListener = 8
};

inline constexpr std::uint32_t bridge_service_limit = 64;
inline constexpr std::uint32_t bridge_txt_limit = 256;

class ControlWriter {
public:
  explicit ControlWriter(BridgePacket type) : bytes_{static_cast<std::byte>(type)} {}
  void Write(std::uint8_t value) { Number(value); }
  void Write(std::uint16_t value) { Number(value); }
  void Write(std::uint32_t value) { Number(value); }
  void Write(std::uint64_t value) { Number(value); }
  void Write(std::string_view value);
  void Write(const Endpoint& value);
  void Write(const PeerId& value);
  void Write(const DiscoveredService& value);
  void Write(const ServiceTxt& value);
  Bytes Take() && { return std::move(bytes_); }

private:
  template<class T> void Number(T value) {
    if (bytes_.empty()) return;
    if (bytes_.size() + sizeof(T) > bridge_chunk + 1) {
      bytes_.clear();
      return;
    }
    for (auto shift = sizeof(T) * 8; shift != 0; shift -= 8)
      bytes_.push_back(static_cast<std::byte>(value >> (shift - 8)));
  }

  Bytes bytes_;
};

class ControlReader {
public:
  explicit ControlReader(std::span<const std::byte> body) : body_(body) {}
  std::uint8_t U8() { return Number<std::uint8_t>(); }
  std::uint16_t U16() { return Number<std::uint16_t>(); }
  std::uint32_t U32() { return Number<std::uint32_t>(); }
  std::uint64_t U64() { return Number<std::uint64_t>(); }
  std::string String();
  Endpoint ReadEndpoint();
  PeerId ReadPeer();
  DiscoveredService ReadService();
  ServiceTxt ReadTxt();
  bool Done() const { return valid_ && body_.empty(); }
  void Reject() { valid_ = false; }

private:
  template<class T> T Number() {
    auto bytes = Read(sizeof(T));
    T value = 0;
    for (auto byte : bytes) value = static_cast<T>((value << 8) | std::to_integer<unsigned int>(byte));
    return value;
  }

  std::span<const std::byte> Read(std::size_t size);
  std::span<const std::byte> body_;
  bool valid_ = true;
};

NetworkError BridgeProtocolError();
Bytes BridgeFailure(const NetworkError& error);
NetworkError ReadBridgeFailure(std::span<const std::byte> body);

} // namespace huxerui::localnetwork::detail
