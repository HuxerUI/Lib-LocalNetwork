#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include "../../../src/tls_backend.h"

#include <type_traits>
#include <utility>

namespace huxerui::localnetwork::detail {
namespace {

template<class Ref>
using ScopedCF = std::unique_ptr<std::remove_pointer_t<Ref>, decltype(&CFRelease)>;

NetworkResult<void> VerifyAppleChain(std::vector<Bytes> certificates, std::string server_name) {
  using Result = NetworkResult<void>;
  const auto reject = [](int code) {
    return Result::Failure({NetworkErrorCode::Authentication, code,
                            "The system did not trust the TLS server certificate chain."});
  };
  ScopedCF<CFMutableArrayRef> chain(CFArrayCreateMutable(nullptr, 0, &kCFTypeArrayCallBacks), CFRelease);
  if (!chain) return reject(errSecAllocate);
  for (const auto& der : certificates) {
    ScopedCF<CFDataRef> data(CFDataCreate(nullptr, reinterpret_cast<const UInt8*>(der.data()),
                                         static_cast<CFIndex>(der.size())), CFRelease);
    if (!data) return reject(errSecAllocate);
    ScopedCF<SecCertificateRef> certificate(SecCertificateCreateWithData(nullptr, data.get()), CFRelease);
    if (!certificate) return reject(errSecDecode);
    CFArrayAppendValue(chain.get(), certificate.get());
  }
  ScopedCF<CFStringRef> host(CFStringCreateWithCString(nullptr, server_name.c_str(), kCFStringEncodingASCII), CFRelease);
  if (!host) return reject(errSecParam);
  ScopedCF<SecPolicyRef> policy(SecPolicyCreateSSL(true, host.get()), CFRelease);
  if (!policy) return reject(errSecAllocate);
  SecTrustRef handle = nullptr;
  const auto status = SecTrustCreateWithCertificates(chain.get(), policy.get(), &handle);
  ScopedCF<SecTrustRef> trust(handle, CFRelease);
  if (status != errSecSuccess) return reject(status);
  // Validate the supplied chain against system trust without fetching issuers over the network.
  const auto offline = SecTrustSetNetworkFetchAllowed(trust.get(), false);
  if (offline != errSecSuccess) return reject(offline);
  CFErrorRef reason = nullptr;
  const auto trusted = SecTrustEvaluateWithError(trust.get(), &reason);
  ScopedCF<CFErrorRef> error(reason, CFRelease);
  if (!trusted) return reject(error ? static_cast<int>(CFErrorGetCode(error.get())) : errSecNotTrusted);
  return Result::Success();
}

} // namespace

Task<NetworkResult<void>> VerifyPlatformTlsChain(std::vector<Bytes> certificates, std::string server_name) {
  return RunWorker(VerifyAppleChain, std::move(certificates), std::move(server_name));
}

} // namespace huxerui::localnetwork::detail
