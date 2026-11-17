#ifdef HUXERUI_LOCALNETWORK_GIO
#include <gio/gio.h>

#include "../../../src/wifi_backend.h"

#include <thread>

namespace huxerui::localnetwork::detail {
namespace {

using namespace std::chrono_literals;
using Clock = std::chrono::steady_clock;
using Variant = std::unique_ptr<GVariant, decltype(&g_variant_unref)>;
constexpr char manager[] = "org.freedesktop.NetworkManager";
constexpr char manager_path[] = "/org/freedesktop/NetworkManager";
constexpr char device[] = "org.freedesktop.NetworkManager.Device";
constexpr char wireless[] = "org.freedesktop.NetworkManager.Device.Wireless";
constexpr char access_point[] = "org.freedesktop.NetworkManager.AccessPoint";
constexpr char active_connection[] = "org.freedesktop.NetworkManager.Connection.Active";
constexpr char settings_interface[] = "org.freedesktop.NetworkManager.Settings";
constexpr char settings_path[] = "/org/freedesktop/NetworkManager/Settings";
constexpr char profile_interface[] = "org.freedesktop.NetworkManager.Settings.Connection";
constexpr auto interactive = static_cast<GDBusCallFlags>(
    G_DBUS_CALL_FLAGS_NO_AUTO_START | G_DBUS_CALL_FLAGS_ALLOW_INTERACTIVE_AUTHORIZATION);

class NetworkManager final {
public:
  bool Open() { bus_.reset(g_bus_get_sync(G_BUS_TYPE_SYSTEM, nullptr, nullptr)); return static_cast<bool>(bus_); }

  Variant Call(const char* path, const char* interface, const char* method, GVariant* args = nullptr,
               int timeout = 5000, GDBusCallFlags flags = G_DBUS_CALL_FLAGS_NO_AUTO_START) {
    error_.reset();
    GError* error = nullptr;
    auto* reply = g_dbus_connection_call_sync(bus_.get(), manager, path, interface, method, args, nullptr,
                                              flags, timeout, nullptr, &error);
    error_.reset(error);
    return {reply, g_variant_unref};
  }

  Variant Property(const char* path, const char* interface, const char* name) {
    auto reply = Call(path, "org.freedesktop.DBus.Properties", "Get", g_variant_new("(ss)", interface, name));
    GVariant* value = nullptr;
    if (reply) g_variant_get(reply.get(), "(v)", &value);
    return {value, g_variant_unref};
  }

  NetworkError Failure(NetworkErrorCode fallback, std::string message) const {
    if (!error_) return {fallback, 0, std::move(message)};
    const std::unique_ptr<gchar, decltype(&g_free)> remote(g_dbus_error_get_remote_error(error_.get()), g_free);
    const std::string_view name = remote ? remote.get() : "";
    if (name.ends_with(".PermissionDenied") || name.ends_with(".AccessDenied") ||
        name.ends_with(".NotAuthorized")) fallback = NetworkErrorCode::PermissionDenied;
    if (name.ends_with(".ServiceUnknown") || name.ends_with(".NameHasNoOwner")) fallback = NetworkErrorCode::Unsupported;
    if (g_error_matches(error_.get(), G_IO_ERROR, G_IO_ERROR_TIMED_OUT)) fallback = NetworkErrorCode::TimedOut;
    // System messages can contain configuration details. Keep the error code and use our operation message.
    return {fallback, error_->code, std::move(message)};
  }

private:
  std::unique_ptr<GDBusConnection, decltype(&g_object_unref)> bus_{nullptr, g_object_unref};
  std::unique_ptr<GError, decltype(&g_error_free)> error_{nullptr, g_error_free};
};

std::uint32_t UInt(Variant value) { return value ? g_variant_get_uint32(value.get()) : 0; }

std::vector<std::string> ObjectPaths(Variant result) {
  std::vector<std::string> paths;
  if (!result) return paths;
  const Variant children(g_variant_get_child_value(result.get(), 0), g_variant_unref);
  GVariantIter iter;
  g_variant_iter_init(&iter, children.get());
  const gchar* path = nullptr;
  while (g_variant_iter_next(&iter, "&o", &path)) paths.emplace_back(path);
  return paths;
}

std::string WifiDevice(NetworkManager& client) {
  auto result = client.Call(manager_path, manager, "GetDevices");
  for (const auto& path : ObjectPaths(std::move(result))) {
    if (UInt(client.Property(path.c_str(), device, "DeviceType")) != 2) continue;
    auto managed = client.Property(path.c_str(), device, "Managed");
    if (managed && g_variant_get_boolean(managed.get())) return path;
  }
  return {};
}

gint64 LastScan(NetworkManager& client, const char* path) {
  auto value = client.Property(path, wireless, "LastScan");
  return value ? g_variant_get_int64(value.get()) : -1;
}

struct AccessPoint {
  std::string path;
  WifiNetwork network;
  bool sae;
};

std::vector<AccessPoint> AccessPoints(NetworkManager& client, const char* path) {
  std::vector<AccessPoint> found;
  for (const auto& entry : ObjectPaths(client.Call(path, wireless, "GetAccessPoints"))) {
    const auto* object = entry.c_str();
    auto ssid = client.Property(object, access_point, "Ssid");
    auto mode = UInt(client.Property(object, access_point, "Mode"));
    if (!ssid || mode != 2) continue; // Infrastructure networks can be joined using this API.
    gsize size = 0;
    const auto* bytes = static_cast<const char*>(g_variant_get_fixed_array(ssid.get(), &size, 1));
    if (!bytes || size == 0) continue;
    // NetworkManager exposes the privacy flag and authentication key-management bits separately.
    constexpr std::uint32_t privacy = 0x1;
    constexpr std::uint32_t psk = 0x100;
    constexpr std::uint32_t sae = 0x400;
    auto rsn = UInt(client.Property(object, access_point, "RsnFlags"));
    auto flags = UInt(client.Property(object, access_point, "Flags"));
    auto security = (rsn & psk) ? WifiSecurity::Wpa2Personal :
        (rsn & sae) ? WifiSecurity::Wpa3Personal : (flags & privacy) || rsn ? WifiSecurity::Other : WifiSecurity::Open;
    found.push_back({entry, {std::string(bytes, size), security}, (rsn & sae) != 0});
  }
  return found;
}

bool Refresh(NetworkManager& client, const char* path) {
  const auto before = LastScan(client, path);
  if (!client.Call(path, wireless, "RequestScan", g_variant_new("(a{sv})", nullptr))) return false;
  const auto deadline = Clock::now() + 6s;
  do {
    std::this_thread::sleep_for(150ms);
    if (LastScan(client, path) > before) return true;
  } while (Clock::now() < deadline);
  return false;
}

NetworkResult<WifiScanResult> Scan() {
  using Result = NetworkResult<WifiScanResult>;
  NetworkManager client;
  if (!client.Open()) {
    return Result::Failure({NetworkErrorCode::Unsupported, 0, "The system NetworkManager bus is unavailable."});
  }
  const auto adapter = WifiDevice(client);
  if (adapter.empty()) {
    return Result::Failure(client.Failure(NetworkErrorCode::Unsupported, "No managed Wi-Fi adapter is available."));
  }
  WifiScanResult result;
  result.refreshed = Refresh(client, adapter.c_str());
  auto failure = client.Failure(NetworkErrorCode::WifiScanFailed, "NetworkManager could not scan for Wi-Fi networks.");
  for (auto& point : AccessPoints(client, adapter.c_str())) result.networks.push_back(std::move(point.network));
  if (result.networks.empty() && !result.refreshed && failure.system_code != 0) {
    return Result::Failure(std::move(failure));
  }
  return Result::Success(std::move(result));
}

GVariant* Configuration(const WifiJoinRequest& request) {
  GVariantBuilder settings;
  GVariantBuilder fields;
  g_variant_builder_init(&settings, G_VARIANT_TYPE("a{sa{sv}}"));
  g_variant_builder_init(&fields, G_VARIANT_TYPE_VARDICT);
  g_variant_builder_add(&fields, "{sv}", "id", g_variant_new_string(request.ssid.c_str()));
  g_variant_builder_add(&fields, "{sv}", "type", g_variant_new_string("802-11-wireless"));
  g_variant_builder_add(&fields, "{sv}", "autoconnect", g_variant_new_boolean(false));
  g_variant_builder_add(&settings, "{s@a{sv}}", "connection", g_variant_builder_end(&fields));
  g_variant_builder_init(&fields, G_VARIANT_TYPE_VARDICT);
  g_variant_builder_add(&fields, "{sv}", "ssid",
      g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, request.ssid.data(), request.ssid.size(), 1));
  g_variant_builder_add(&fields, "{sv}", "mode", g_variant_new_string("infrastructure"));
  g_variant_builder_add(&settings, "{s@a{sv}}", "802-11-wireless", g_variant_builder_end(&fields));
  if (request.security != WifiSecurity::Open) {
    g_variant_builder_init(&fields, G_VARIANT_TYPE_VARDICT);
    const char* security = request.security == WifiSecurity::Wpa3Personal ? "sae" : "wpa-psk";
    g_variant_builder_add(&fields, "{sv}", "key-mgmt", g_variant_new_string(security));
    g_variant_builder_add(&fields, "{sv}", "psk", g_variant_new_string(request.passphrase.c_str()));
    g_variant_builder_add(&settings, "{s@a{sv}}", "802-11-wireless-security", g_variant_builder_end(&fields));
  }
  return g_variant_builder_end(&settings);
}

NetworkResult<WifiJoinResult> WaitForActivation(NetworkManager& client, const char* active) {
  using Result = NetworkResult<WifiJoinResult>;
  // State 2 confirms that activation completed, including the system's address configuration.
  const auto deadline = Clock::now() + 25s;
  do {
    const auto state = UInt(client.Property(active, active_connection, "State"));
    if (state == 2) return Result::Success({WifiJoinStatus::Associated, {}});
    if (state == 0 || state >= 3) {
      return Result::Failure({NetworkErrorCode::WifiJoinFailed, 0, "NetworkManager could not activate the hotspot."});
    }
    std::this_thread::sleep_for(200ms);
  } while (Clock::now() < deadline);
  return Result::Failure({NetworkErrorCode::TimedOut, 0, "NetworkManager did not confirm Wi-Fi activation."});
}

NetworkResult<WifiJoinResult> Join(WifiJoinRequest request) {
  using Result = NetworkResult<WifiJoinResult>;
  NetworkManager client;
  if (!client.Open()) {
    return Result::Failure({NetworkErrorCode::Unsupported, 0, "The system NetworkManager bus is unavailable."});
  }
  const auto adapter = WifiDevice(client);
  if (adapter.empty()) {
    return Result::Failure(client.Failure(NetworkErrorCode::Unsupported, "No managed Wi-Fi adapter is available."));
  }
  auto find = [&] {
    for (const auto& point : AccessPoints(client, adapter.c_str())) {
      if (point.network.ssid == request.ssid && (point.network.security == request.security ||
          (point.sae && request.security == WifiSecurity::Wpa3Personal))) {
        return point.path;
      }
    }
    return std::string{};
  };
  auto point = find();
  if (point.empty()) {
    if (!Refresh(client, adapter.c_str())) {
      auto failure = client.Failure(NetworkErrorCode::WifiJoinFailed, "NetworkManager could not scan for the hotspot.");
      if (failure.code == NetworkErrorCode::PermissionDenied) return Result::Failure(std::move(failure));
    }
    point = find();
  }
  if (point.empty()) {
    return Result::Failure({NetworkErrorCode::WifiJoinFailed, 0, "NetworkManager did not find the requested hotspot."});
  }
  GVariantBuilder options;
  g_variant_builder_init(&options, G_VARIANT_TYPE_VARDICT);
  g_variant_builder_add(&options, "{sv}", "persist",
      g_variant_new_string(request.mode == WifiJoinMode::Persistent ? "disk" : "volatile"));
  auto reply = client.Call(manager_path, manager, "AddAndActivateConnection2",
      g_variant_new("(@a{sa{sv}}oo@a{sv})", Configuration(request), adapter.c_str(), point.c_str(),
                    g_variant_builder_end(&options)), 30000, interactive);
  if (!reply) {
    return Result::Failure(client.Failure(NetworkErrorCode::WifiJoinFailed, "NetworkManager rejected the Wi-Fi request."));
  }
  const gchar* active = nullptr;
  g_variant_get_child(reply.get(), 1, "&o", &active);
  return WaitForActivation(client, active);
}

NetworkResult<WifiJoinResult> JoinProfile(std::string uuid) {
  using Result = NetworkResult<WifiJoinResult>;
  if (!g_uuid_string_is_valid(uuid.c_str())) {
    return Result::Failure({NetworkErrorCode::InvalidWifiConfiguration, 0, "Expected a NetworkManager profile UUID."});
  }
  NetworkManager client;
  if (!client.Open()) {
    return Result::Failure({NetworkErrorCode::Unsupported, 0, "The system NetworkManager bus is unavailable."});
  }
  const auto adapter = WifiDevice(client);
  if (adapter.empty()) {
    return Result::Failure(client.Failure(NetworkErrorCode::Unsupported, "No managed Wi-Fi adapter is available."));
  }
  const auto profile = client.Call(settings_path, settings_interface, "GetConnectionByUuid",
                                   g_variant_new("(s)", uuid.c_str()));
  if (!profile) {
    return Result::Failure(client.Failure(NetworkErrorCode::WifiJoinFailed, "The Wi-Fi profile is unavailable."));
  }
  const gchar* path = nullptr;
  g_variant_get(profile.get(), "(&o)", &path);
  // GetSettings describes the connection without retrieving its stored secrets.
  const auto reply = client.Call(path, profile_interface, "GetSettings");
  if (!reply) return Result::Failure(client.Failure(NetworkErrorCode::WifiJoinFailed, "Could not inspect the Wi-Fi profile."));
  const Variant settings(g_variant_get_child_value(reply.get(), 0), g_variant_unref);
  const Variant connection(g_variant_lookup_value(settings.get(), "connection", G_VARIANT_TYPE_VARDICT), g_variant_unref);
  const gchar* type = nullptr;
  if (!connection || !g_variant_lookup(connection.get(), "type", "&s", &type) ||
      std::string_view(type) != "802-11-wireless") {
    return Result::Failure({NetworkErrorCode::InvalidWifiConfiguration, 0, "The selected profile is not a Wi-Fi profile."});
  }
  const auto activated = client.Call(manager_path, manager, "ActivateConnection",
      g_variant_new("(ooo)", path, adapter.c_str(), "/"), 30000, interactive);
  if (!activated) {
    return Result::Failure(client.Failure(NetworkErrorCode::WifiJoinFailed, "NetworkManager rejected the Wi-Fi profile."));
  }
  const gchar* active = nullptr;
  g_variant_get(activated.get(), "(&o)", &active);
  return WaitForActivation(client, active);
}

} // namespace

Task<NetworkResult<WifiScanResult>> ScanPlatformWifi() { return RunWorker(Scan); }
Task<NetworkResult<WifiJoinResult>> JoinPlatformWifi(WifiJoinRequest request) {
  return RunWorker(Join, std::move(request));
}
Task<NetworkResult<WifiJoinResult>> JoinPlatformWifiProfile(std::string profile) {
  return RunWorker(JoinProfile, std::move(profile));
}

} // namespace huxerui::localnetwork::detail
#endif
