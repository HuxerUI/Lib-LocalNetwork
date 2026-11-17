#include "../../../src/tls_backend.h"

#include <fstream>
#include <utility>

namespace huxerui::localnetwork::detail {
namespace {

NetworkResult<void> VerifyLinuxChain(std::vector<Bytes> certificates) {
  // Distributions maintain one of these PEM bundles for TLS client trust.
  constexpr const char* bundle_paths[] = {
      "/etc/ssl/certs/ca-certificates.crt",
      "/etc/pki/tls/certs/ca-bundle.crt",
      "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
      "/var/lib/ca-certificates/ca-bundle.pem",
      "/etc/ssl/ca-bundle.pem",
      "/etc/ssl/cert.pem",
  };
  for (const auto* path : bundle_paths) {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) continue;
    const auto size = stream.tellg();
    if (size <= 0 || size > 8 * 1024 * 1024) break;
    Bytes roots(static_cast<std::size_t>(size) + 1, std::byte{});
    if (!stream.seekg(0).read(reinterpret_cast<char*>(roots.data()), static_cast<std::streamsize>(size))) break;
    return VerifyTlsBundle(std::move(certificates), std::move(roots));
  }
  return NetworkResult<void>::Failure(
      {NetworkErrorCode::Authentication, 0, "Could not load the system TLS CA bundle."});
}

} // namespace

Task<NetworkResult<void>> VerifyPlatformTlsChain(std::vector<Bytes> certificates, std::string) {
  return RunWorker(VerifyLinuxChain, std::move(certificates));
}

} // namespace huxerui::localnetwork::detail
