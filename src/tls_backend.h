#pragma once

#include <array>
#include <vector>

#include <huxerui/local_network_tls.h>

namespace huxerui::localnetwork::detail {

struct TlsServerName {
  std::string host;
  std::array<unsigned char, 16> address{};
  std::size_t address_size = 0;
};

Task<NetworkResult<std::shared_ptr<TlsSocket>>> ConnectSystemTls(TcpConnection connection, TlsServerName server);

/// After the TLS layer checks the leaf SAN, verify the certificate chain using platform trust.
Task<NetworkResult<void>> VerifyPlatformTlsChain(std::vector<Bytes> certificates, std::string server_name);

// Linux verifies against the distribution's CA bundle using the same Mbed TLS configuration.
NetworkResult<void> VerifyTlsBundle(std::vector<Bytes> certificates, Bytes roots);

AsyncInputStream MakeTlsInput(const std::shared_ptr<TlsSocket>& socket);
AsyncOutputStream MakeTlsOutput(const std::shared_ptr<TlsSocket>& socket);
void CloseTlsSocket(const std::shared_ptr<TlsSocket>& socket) noexcept;

#ifdef __ANDROID__
void InstallPlatformTlsTrust(ApplicationContext& context);
#endif

} // namespace huxerui::localnetwork::detail
