#pragma once

#include "socket_io.h"

namespace huxerui::localnetwork::detail {

struct IdentityState;

struct BridgeCredentials {
  std::shared_ptr<IdentityState> certificate;
  std::string grant;
};

/// Uses the same Mbed TLS backend as the paired transport with a browser-trusted certificate.
Task<NetworkResult<BridgeCredentials>> PrepareBridgeCredentials(std::string certificate_pem, std::string private_key_pem);
NetworkResult<std::string> GenerateBridgeGrant();
Task<NetworkResult<std::shared_ptr<SocketIo>>> AcceptBridgeTls(
    std::shared_ptr<SocketIo> connection, std::shared_ptr<IdentityState> credentials,
    std::chrono::steady_clock::time_point deadline);
bool CheckBridgeGrant(std::string_view expected, std::string_view received);

} // namespace huxerui::localnetwork::detail
