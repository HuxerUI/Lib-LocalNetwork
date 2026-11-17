#include <windows.h>
#include <wincrypt.h>

#include "../../../src/tls_backend.h"

#include <utility>

namespace huxerui::localnetwork::detail {
namespace {

NetworkResult<void> VerifyWindowsChain(std::vector<Bytes> certificates, std::string server_name) {
  using Result = NetworkResult<void>;
  const auto reject = [](DWORD code) {
    return Result::Failure({NetworkErrorCode::Authentication, static_cast<int>(code),
                            "Windows did not trust the TLS server certificate chain."});
  };
  const auto close_store = [](HCERTSTORE store) { CertCloseStore(store, 0); };
  const std::unique_ptr<void, decltype(close_store)> store(
      CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr), close_store);
  if (!store) return reject(GetLastError());
  PCCERT_CONTEXT leaf = nullptr;
  // The handshake supplies intermediates in a separate store. Only Windows can supply trust anchors.
  for (const auto& der : certificates) {
    if (!CertAddEncodedCertificateToStore(store.get(), X509_ASN_ENCODING,
        reinterpret_cast<const BYTE*>(der.data()), static_cast<DWORD>(der.size()), CERT_STORE_ADD_ALWAYS,
        leaf ? nullptr : &leaf)) {
      const auto error = GetLastError();
      if (leaf) CertFreeCertificateContext(leaf);
      return reject(error);
    }
  }
  const std::unique_ptr<const CERT_CONTEXT, decltype(&CertFreeCertificateContext)> certificate(
      leaf, CertFreeCertificateContext);
  if (!certificate) return reject(ERROR_INVALID_DATA);

  char server_auth[] = szOID_PKIX_KP_SERVER_AUTH;
  char* usages[] = {server_auth};
  CERT_CHAIN_PARA parameters{};
  parameters.cbSize = sizeof(parameters);
  parameters.RequestedUsage = {USAGE_MATCH_TYPE_AND, {1, usages}};
  PCCERT_CHAIN_CONTEXT context = nullptr;
  if (!CertGetCertificateChain(nullptr, certificate.get(), nullptr, store.get(), &parameters,
                               CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL, nullptr, &context)) return reject(GetLastError());
  const std::unique_ptr<const CERT_CHAIN_CONTEXT, decltype(&CertFreeCertificateChain)> chain(
      context, CertFreeCertificateChain);

  std::wstring hostname(server_name.begin(), server_name.end());
  SSL_EXTRA_CERT_CHAIN_POLICY_PARA ssl{};
  ssl.cbSize = sizeof(ssl);
  ssl.dwAuthType = AUTHTYPE_SERVER;
  ssl.pwszServerName = hostname.data();
  CERT_CHAIN_POLICY_PARA policy{sizeof(policy), 0, &ssl};
  CERT_CHAIN_POLICY_STATUS status{};
  status.cbSize = sizeof(status);
  if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain.get(), &policy, &status))
    return reject(GetLastError());
  if (status.dwError != ERROR_SUCCESS) return reject(status.dwError);
  return Result::Success();
}

} // namespace

Task<NetworkResult<void>> VerifyPlatformTlsChain(std::vector<Bytes> certificates, std::string server_name) {
  return RunWorker(VerifyWindowsChain, std::move(certificates), std::move(server_name));
}

} // namespace huxerui::localnetwork::detail
