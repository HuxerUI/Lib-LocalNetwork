#include <huxerui/android/platform_registry.h>
#include <huxerui/app.h>

#include "../../../../../src/tls_backend.h"

#include <utility>

namespace huxerui::localnetwork::detail {
namespace {

constexpr char module_name[] = "localnetwork/TlsTrust";

class TlsTrustModule final {
public:
  explicit TlsTrustModule(PlatformChannel channel) : channel_(std::move(channel)) {}
  ~TlsTrustModule() { channel_.Close(); }

  Task<PlatformResult<PlatformPayload>> Verify(PlatformPayload payload) {
    return AwaitCallback<PlatformResult<PlatformPayload>>(
        [channel = channel_, payload = std::move(payload)](auto completion) mutable {
          const auto request = channel.Invoke("verify", std::move(payload),
              [completion](PlatformResult<PlatformPayload> result) { completion.Complete(std::move(result)); });
          return [channel, request] { (void)channel.Cancel(request); };
        });
  }

private:
  PlatformChannel channel_;
};

} // namespace

void InstallPlatformTlsTrust(ApplicationContext& context) {
  android::JavaPlatformModuleFactory<std::shared_ptr<TlsTrustModule>> factory;
  factory.class_name = "org.huxerui.lib.localnetwork.TlsTrustModule";
  factory.create = [](PlatformChannel channel) { return std::make_shared<TlsTrustModule>(std::move(channel)); };
  context.RegisterPlatformModule<std::shared_ptr<TlsTrustModule>>(module_name, std::move(factory));
}

Task<NetworkResult<void>> VerifyPlatformTlsChain(std::vector<Bytes> certificates, std::string server_name) {
  using Result = NetworkResult<void>;
  PlatformPayload::List chain;
  chain.reserve(certificates.size());
  for (auto& certificate : certificates) chain.emplace_back(std::move(certificate));
  PlatformPayload request = PlatformPayload::Object{{"host", std::move(server_name)}, {"chain", std::move(chain)}};
  auto module = OpenPlatformModule<std::shared_ptr<TlsTrustModule>>(module_name);
  auto verified = co_await module->Verify(std::move(request));
  if (const auto* error = std::get_if<PlatformError>(&verified)) {
    const auto code = error->code == "localnetwork/tls-busy" ? NetworkErrorCode::Busy : NetworkErrorCode::Authentication;
    co_return Result::Failure({code, 0, error->message});
  }
  co_return Result::Success();
}

} // namespace huxerui::localnetwork::detail
