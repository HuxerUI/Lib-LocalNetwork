#include "local_network_permissions.h"

#ifdef __ANDROID__
#include <android/api-level.h>
#include <huxerui/android/platform_registry.h>

#include <utility>
#endif

namespace local_network_preview {

using namespace huxerui;

#ifdef __ANDROID__
namespace {

constexpr char module_name[] = "localnetwork/LocalNetworkPermissions";

class LocalNetworkPermissions final {
public:
  explicit LocalNetworkPermissions(PlatformChannel channel) : channel_(std::move(channel)) {}
  ~LocalNetworkPermissions() { channel_.Close(); }

  Task<PlatformResult<PlatformPayload>> Call(std::string method) {
    return AwaitCallback<PlatformResult<PlatformPayload>>(
        [channel = channel_, method = std::move(method)](auto completion) mutable {
          const auto request = channel.Invoke(std::move(method), {},
              [completion](PlatformResult<PlatformPayload> result) { completion.Complete(std::move(result)); });
          return [channel, request] { (void)channel.Cancel(request); };
        });
  }

private:
  PlatformChannel channel_;
};

} // namespace

void InstallLocalNetworkPermissions(ApplicationContext& context) {
  android::JavaWindowPlatformModuleFactory<std::shared_ptr<LocalNetworkPermissions>> factory;
  factory.class_name = "org.huxerui.lib.localnetwork.preview.LocalNetworkPermissionsModule";
  factory.create = [](PlatformChannel channel) {
    return std::make_shared<LocalNetworkPermissions>(std::move(channel));
  };
  context.RegisterPlatformModule<std::shared_ptr<LocalNetworkPermissions>>(module_name, std::move(factory));
}
#else
void InstallLocalNetworkPermissions(ApplicationContext&) {}
#endif

Task<PermissionStatus> RequestLocalNetworkAccess() {
#ifdef __ANDROID__
  if (android_get_device_api_level() >= 37) {
    auto module = OpenPlatformModule<std::shared_ptr<LocalNetworkPermissions>>(module_name);
    auto requested = co_await module->Call("request");
    const auto* payload = std::get_if<PlatformPayload>(&requested);
    if (!payload) co_return PermissionStatus::Unavailable;
    if (payload->AsString() == "granted") co_return PermissionStatus::Granted;
    if (payload->AsString() == "denied") co_return PermissionStatus::Denied;
    co_return PermissionStatus::Unavailable;
  }
#endif
  co_return PermissionStatus::Granted;
}

Task<bool> OpenLocalNetworkPermissionSettings() {
#ifdef __ANDROID__
  auto module = OpenPlatformModule<std::shared_ptr<LocalNetworkPermissions>>(module_name);
  auto opened = co_await module->Call("settings");
  const auto* payload = std::get_if<PlatformPayload>(&opened);
  co_return payload && payload->AsBoolean();
#else
  co_return false;
#endif
}

} // namespace local_network_preview
