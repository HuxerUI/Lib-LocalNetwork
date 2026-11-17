#if defined(_WIN32)
#include <windows.h>
#include <shellapi.h>
#elif defined(__ANDROID__)
#include <huxerui/android/platform_registry.h>
#elif defined(__APPLE__)
#include <TargetConditionals.h>
#elif defined(HUXERUI_LOCALNETWORK_PREVIEW_LINUX_SETTINGS)
#include <glib.h>
#endif

#include "wifi_platform.h"

#include <string>
#include <string_view>
#include <utility>

namespace local_network_preview {

using namespace huxerui;

#ifdef __ANDROID__
namespace {

constexpr char module_name[] = "localnetwork/WifiControls";

class WifiControls final {
public:
  explicit WifiControls(PlatformChannel channel) : channel_(std::move(channel)) {}
  ~WifiControls() { channel_.Close(); }

  Task<PlatformResult<PlatformPayload>> Call(std::string method) {
    return AwaitCallback<PlatformResult<PlatformPayload>>([channel = channel_, method = std::move(method)](auto completion) mutable {
      const auto request = channel.Invoke(std::move(method), {},
          [completion](PlatformResult<PlatformPayload> result) { completion.Complete(std::move(result)); });
      return [channel, request] { (void)channel.Cancel(request); };
    });
  }

private:
  PlatformChannel channel_;
};

} // namespace

void InstallWifiControls(ApplicationContext& context) {
  android::JavaWindowPlatformModuleFactory<std::shared_ptr<WifiControls>> factory;
  factory.class_name = "org.huxerui.lib.localnetwork.preview.WifiControlsModule";
  factory.create = [](PlatformChannel channel) { return std::make_shared<WifiControls>(std::move(channel)); };
  context.RegisterPlatformModule<std::shared_ptr<WifiControls>>(module_name, std::move(factory));
}

Task<PermissionStatus> RequestAndroidWifiJoinPermission(ApplicationHandle app) {
  auto module = OpenPlatformModule<std::shared_ptr<WifiControls>>(module_name);
  auto result = co_await module->Call("joinPermission");
  const auto* payload = std::get_if<PlatformPayload>(&result);
  if (!payload) co_return PermissionStatus::Unavailable;
  const auto status = payload->AsString();
  if (status == "location") co_return co_await app.RequestPermissionAsync(Permission::PreciseLocation);
  if (status == "granted") co_return PermissionStatus::Granted;
  if (status == "denied") co_return PermissionStatus::Denied;
  co_return PermissionStatus::Unavailable;
}

Task<bool> OpenWifiSettings() {
  auto module = OpenPlatformModule<std::shared_ptr<WifiControls>>(module_name);
  auto result = co_await module->Call("wifiSettings");
  const auto* payload = std::get_if<PlatformPayload>(&result);
  co_return payload && payload->AsBoolean();
}

#else

void InstallWifiControls(ApplicationContext&) {}

#if !(defined(__APPLE__) && TARGET_OS_OSX)
Task<bool> OpenWifiSettings() {
#ifdef _WIN32
  co_return reinterpret_cast<INT_PTR>(
      ShellExecuteW(nullptr, L"open", L"ms-settings:network-wifi", nullptr, nullptr, SW_SHOWNORMAL)) > 32;
#elif defined(HUXERUI_LOCALNETWORK_PREVIEW_LINUX_SETTINGS)
  co_return co_await RunWorker([] {
    auto launch = [](std::string command, std::string panel) {
      // GLib starts the desktop settings application directly and reaps the child.
      gchar* args[] = {command.data(), panel.data(), nullptr};
      return g_spawn_async(nullptr, args, nullptr, G_SPAWN_SEARCH_PATH,
                           nullptr, nullptr, nullptr, nullptr) != FALSE;
    };
    const char* desktop = g_getenv("XDG_CURRENT_DESKTOP");
    if (!desktop) return false;
    const std::string_view name(desktop);
    if (name.find("GNOME") != std::string_view::npos) return launch("gnome-control-center", "wifi");
    if (name.find("KDE") != std::string_view::npos) return launch("systemsettings", "kcm_networkmanagement");
    return false;
  });
#else
  co_return false;
#endif
}
#endif
#endif

} // namespace local_network_preview
