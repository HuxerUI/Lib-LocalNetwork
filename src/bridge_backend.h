#pragma once

#include <huxerui/local_network_bridge.h>

#include <deque>
#include <span>

namespace huxerui::localnetwork::detail {

inline constexpr char bridge_path[] = "/huxer-lan/v1";
inline constexpr char bridge_protocol[] = "huxer-lan.v1";
inline constexpr std::size_t bridge_chunk = 32 * 1024;
inline constexpr std::size_t bridge_grant_size = 64;

// The first five tags form the paired data protocol. Control requests use the remaining tags on separate sockets.
enum class BridgePacket : std::uint8_t {
  Authenticate = 1, Ready = 2, Credit = 3, Data = 4, End = 5,
  ControlAuthenticate = 6, ControlReady = 7, Request = 8, Response = 9, Failure = 10
};

/// Owns the WebSocket transport and its small, bounded queue of incoming messages.
class BridgeTransport {
public:
  virtual ~BridgeTransport() = default;
  /// Drives incoming callbacks and pending writes. Returns false when the transport is no longer usable.
  virtual bool Poll() = 0;
  /// Copies one complete binary packet into the transport, or reports that the sender must retry.
  virtual IoResult<bool> TrySend(std::span<const std::byte> packet) = 0;
  virtual void Close() noexcept = 0;

  std::optional<Bytes> TakePacket();

protected:
  /// Called by the platform backend during packet delivery. Rejects oversized or excessive traffic.
  bool ReceivePacket(std::span<const std::byte> packet);

private:
  std::deque<Bytes> incoming_;
};

using BridgeClock = std::chrono::steady_clock;

Bytes MakeBridgePacket(BridgePacket type, std::span<const std::byte> body = {});
bool ValidBridgeGrant(std::string_view grant);
Task<NetworkResult<void>> SendBridgePacket(BridgeTransport& transport, Bytes packet, BridgeClock::time_point deadline);
Task<NetworkResult<Bytes>> ReadBridgePacket(BridgeTransport& transport, BridgeClock::time_point deadline);

struct BridgeAccess {
  /// Starts a byte stream after the grant and native peer have already been verified.
  static Task<NetworkResult<WebBridgeConnection>> Open(
      std::shared_ptr<BridgeTransport> transport, PeerId peer, BridgeClock::time_point deadline);
};

#ifdef __EMSCRIPTEN__
bool IsBrowserBridgeSupported() noexcept;
Task<NetworkResult<std::shared_ptr<BridgeTransport>>> OpenBrowserBridge(std::string url);
Task<NetworkResult<WebBridgeConnection>> ConnectBrowserBridge(WebBridgeDialOptions options);
Task<NetworkResult<WebBridgeConnection>> ConnectBrowserData(WebBridgeDialOptions options);
#endif

} // namespace huxerui::localnetwork::detail
