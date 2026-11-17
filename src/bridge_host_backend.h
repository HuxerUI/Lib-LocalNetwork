#pragma once

#include "bridge_backend.h"
#include "bridge_tls.h"

namespace huxerui::localnetwork::detail {

class HostBridgeTransport : public BridgeTransport {
public:
  /// Flushes queued messages before closing the WebSocket.
  virtual Task<bool> Finish() = 0;
};

struct WebBridgeListenerState {
  Endpoint endpoint;
  std::string grant;
  std::string origin;
  TcpListener listener;
  std::shared_ptr<IdentityState> certificate;
  std::shared_ptr<SocketIo> active_socket;
  std::shared_ptr<PairedConnection> active_peer;
  std::function<void()> stop_control;
  bool closed = false;

  void Close() noexcept;
};

Task<std::shared_ptr<HostBridgeTransport>> AcceptBridgeWebSocket(
    std::shared_ptr<SocketIo> socket, std::shared_ptr<IdentityState> certificate, std::string_view origin,
    BridgeClock::time_point deadline);
Task<NetworkResult<void>> RelayBridgeConnection(std::shared_ptr<HostBridgeTransport> wire,
                                               std::shared_ptr<PairedConnection> peer, TaskScope tasks);
Task<NetworkResult<void>> ServeBridgeControl(std::shared_ptr<WebBridgeListenerState> listener,
                                            WebBridgePolicy policy, TaskScope tasks);

} // namespace huxerui::localnetwork::detail
