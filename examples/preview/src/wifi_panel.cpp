#if defined(__APPLE__)
#include <TargetConditionals.h>
#endif

#include "wifi_panel.h"
#include "wifi_platform.h"

#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace local_network_preview {
namespace {

using namespace huxerui;
using namespace huxerui::localnetwork;

struct WifiPanelState {
  std::vector<WifiNetwork> networks;
  std::string status;
  std::optional<PermissionSettingsTarget> permission_settings;
};

constexpr bool can_open_wifi_settings =
#if defined(_WIN32) || defined(__ANDROID__) || defined(HUXERUI_LOCALNETWORK_PREVIEW_LINUX_SETTINGS) || \
    (defined(__APPLE__) && TARGET_OS_OSX)
    true;
#else
    false;
#endif

#if defined(__APPLE__) && TARGET_OS_OSX
constexpr char wifi_settings_label[] = "Open System Settings";
#else
constexpr char wifi_settings_label[] = "Open Wi-Fi settings";
#endif

#if defined(__APPLE__) && TARGET_OS_IOS
constexpr bool can_open_app_settings = true;
constexpr bool can_join_wpa3 = false;
constexpr char wifi_settings_hint[] = "Open Settings > Wi-Fi to view nearby networks or join there.";
#else
constexpr bool can_open_app_settings = false;
constexpr bool can_join_wpa3 = true;
constexpr char wifi_settings_hint[] = "Open your device's Wi-Fi settings to view or join networks.";
#endif

const char* SecurityName(WifiSecurity security) {
  switch (security) {
    case WifiSecurity::Open: return "Open";
    case WifiSecurity::Wpa2Personal: return "WPA2-Personal";
    case WifiSecurity::Wpa3Personal: return "WPA3-Personal";
    case WifiSecurity::Other: return "System configuration required";
  }
  return "";
}

Task<PermissionStatus> RequestWifiPermission(ApplicationHandle app, bool scan) {
#if defined(__ANDROID__)
  if (scan) co_return co_await app.RequestPermissionAsync(Permission::PreciseLocation);
  co_return co_await RequestAndroidWifiJoinPermission(app);
#elif defined(__APPLE__) && TARGET_OS_OSX
  (void)scan;
  co_return co_await app.RequestPermissionAsync(Permission::Location);
#else
  (void)app;
  (void)scan;
  // Native Wi-Fi and NetworkManager handle any Windows, iOS, or Linux system approval.
  co_return PermissionStatus::Granted;
#endif
}

std::optional<PermissionSettingsTarget> WifiPermissionSettings() {
#if defined(_WIN32) || (defined(__APPLE__) && TARGET_OS_OSX)
  return PermissionSettingsTarget::System;
#elif defined(__ANDROID__)
  return PermissionSettingsTarget::Application;
#else
  return std::nullopt;
#endif
}

void FinishWifi(const State<PreviewWifiRoute>& route, const State<WifiPanelState>& state, std::string status,
                std::optional<PermissionSettingsTarget> settings = {}) {
  state.Update([&](WifiPanelState& value) {
    value.status = std::move(status);
    value.permission_settings = settings;
  });
  route.Update([](PreviewWifiRoute& value) { value.busy = false; });
}

void PermissionDenied(const State<PreviewWifiRoute>& route, const State<WifiPanelState>& state,
                      PermissionStatus permission, bool scan) {
  if (permission == PermissionStatus::SystemDisabled) {
    FinishWifi(route, state, "Enable Location in system settings and try again.", PermissionSettingsTarget::System);
    return;
  }
  const char* message = scan ? "Allow Location access to scan for Wi-Fi." : "Allow Wi-Fi access to join the hotspot.";
#ifdef __ANDROID__
  if (scan || permission == PermissionStatus::Limited) message = "Allow precise Location access and try again.";
#endif
  FinishWifi(route, state, message, WifiPermissionSettings());
}

} // namespace

[[huxerui::composable]] View WifiPanel(State<PreviewWifiRoute> route, bool transfer_busy) {
  const auto expanded = UseState(false);
  const auto ssid = UseState(TextEditingValue{});
  const auto passphrase = UseState(TextEditingValue{});
  const auto security = UseState(WifiSecurity::Wpa2Personal);
  const auto state = UseState(WifiPanelState{});
  const auto running = UseState(TaskHandle{});
  const auto app = UseApplication();
  const auto tasks = UseTaskScope();
  const bool showing = expanded;
  const bool available = !route->busy && !transfer_busy;
  const bool can_scan = IsWifiScanSupported();
  const bool can_join = IsWifiJoinSupported();
  const WifiSecurity selected_security = security;

  View toggle = Button(showing ? "Hide Wi-Fi setup" : "Wi-Fi setup").OnClick([expanded, showing] {
    expanded = !showing;
  });
  if (!showing) return toggle;

  const auto begin = [=](std::string status) {
    route.Update([](PreviewWifiRoute& value) { value.busy = true; });
    state.Update([&](WifiPanelState& value) {
      value.status = std::move(status);
      value.permission_settings.reset();
    });
  };

  const auto scan = [=] {
    begin("Scanning for Wi-Fi...");
    running = tasks.Launch([=]() -> Task<void> {
      const auto permission = co_await RequestWifiPermission(app, true);
      if (permission != PermissionStatus::Granted) {
        PermissionDenied(route, state, permission, true);
        co_return;
      }
      auto scanned = co_await ScanWifiAsync();
      if (!scanned.Succeeded()) {
        const auto& error = scanned.Error();
        FinishWifi(route, state, error.message,
                   error.code == NetworkErrorCode::PermissionDenied ? WifiPermissionSettings() : std::nullopt);
        co_return;
      }
      auto snapshot = std::move(scanned).Value();
      const bool empty = snapshot.networks.empty();
      state.Update([&](WifiPanelState& value) { value.networks = std::move(snapshot.networks); });
      FinishWifi(route, state, snapshot.refreshed
          ? (empty ? "No nearby Wi-Fi networks found." : "Select a network or enter its SSID.")
          : (empty ? "No cached Wi-Fi networks found." : "Showing cached Wi-Fi networks."));
    });
  };

  const auto join = [=] {
    const WifiSecurity selected = security;
    WifiJoinRequest request{.ssid = ssid->text, .security = selected,
                            .passphrase = selected == WifiSecurity::Open ? std::string{} : passphrase->text};
    passphrase = TextEditingValue{};
    begin("Joining the hotspot...");
    running = tasks.Launch([=, request = std::move(request)]() mutable -> Task<void> {
      const auto permission = co_await RequestWifiPermission(app, false);
      if (permission != PermissionStatus::Granted) {
        PermissionDenied(route, state, permission, false);
        co_return;
      }
      auto joined = co_await JoinWifiAsync(std::move(request));
      if (!joined.Succeeded()) {
        const auto& error = joined.Error();
        FinishWifi(route, state, error.message,
                   error.code == NetworkErrorCode::PermissionDenied ? WifiPermissionSettings() : std::nullopt);
        co_return;
      }
      auto joined_wifi = std::move(joined).Value();
      const bool bound = static_cast<bool>(joined_wifi.network);
      route.Update([&](PreviewWifiRoute& value) { value.network = std::move(joined_wifi.network); });
      if (joined_wifi.status == WifiJoinStatus::ConfigurationAccepted) {
        FinishWifi(route, state, "Configuration accepted. Confirm the association in Wi-Fi settings.");
      } else {
        FinishWifi(route, state, bound ? "Hotspot joined. Outgoing connections use this Wi-Fi route." : "Hotspot joined.");
      }
    });
  };

  std::vector<View> networks;
  for (const auto& row : state->networks) {
    const auto label = row.ssid + " · " + SecurityName(row.security);
    const auto key = row.ssid + "#" + std::to_string(static_cast<int>(row.security));
    if (!can_join || row.security == WifiSecurity::Other || (row.security == WifiSecurity::Wpa3Personal && !can_join_wpa3)) {
      networks.push_back(Text(label).Key(key));
      continue;
    }
    networks.push_back(Button(label).With(Enabled(available))
        .OnClick([ssid, security, passphrase, row] {
          ssid = TextEditingValue::FromText(row.ssid);
          security = row.security;
          passphrase = TextEditingValue{};
        }).Key(key));
  }

  const auto security_choice = [=](WifiSecurity choice) {
    return Chip(SecurityName(choice), selected_security == choice).With(Enabled(available))
        .OnChanged([security, passphrase, choice](bool selected) {
          if (!selected) return;
          security = choice;
          if (choice == WifiSecurity::Open) passphrase = TextEditingValue{};
        });
  };

  return Column {
    toggle,
    Flow {
      can_scan ? Button("Scan Wi-Fi").With(Enabled(available)).OnClick(scan) : View{},
      can_open_wifi_settings ? Button(wifi_settings_label).With(Enabled(available)).OnClick([=] {
        tasks.Launch([state]() -> Task<void> {
          const bool opened = co_await OpenWifiSettings();
          state.Update([&](WifiPanelState& value) {
            value.status = opened ? "Select Wi-Fi in system settings." : wifi_settings_hint;
          });
        });
      }) : View{},
      can_open_app_settings ? Button("Open app settings").With(Enabled(available)).OnClick([=] {
        tasks.Launch([app, state]() -> Task<void> {
          if (!co_await app.OpenPermissionSettingsAsync(Permission::Location)) {
            state.Update([](WifiPanelState& value) { value.status = "Open Settings to review app permissions."; });
          }
        });
      }) : View{},
      state->permission_settings ? Button("Permission settings").With(Enabled(available)).OnClick([=] {
        tasks.Launch([app, state, target = *state->permission_settings]() -> Task<void> {
          if (!co_await app.OpenPermissionSettingsAsync(Permission::Location, target)) {
            state.Update([](WifiPanelState& value) { value.status = "Open system settings to review app permissions."; });
          }
        });
      }) : View{},
      route->busy ? Button("Cancel Wi-Fi operation").OnClick([=] {
        running->Cancel();
        FinishWifi(route, state, "Wi-Fi operation canceled.");
      }) : View{},
    }.With(Spacing(8.0F)),
    !can_open_wifi_settings ? Text(wifi_settings_hint) : View{},
    Column(std::move(networks)).With(Spacing(6.0F)),
    can_join ? Column {
      Text("Wi-Fi network name (SSID)"),
      TextField(ssid).InputConfiguration({.autocorrect = false}).With(Enabled(available))
          .OnChanged([ssid](const TextEditingValue& value) { ssid = value; }),
      Flow {
        security_choice(WifiSecurity::Open),
        security_choice(WifiSecurity::Wpa2Personal),
        can_join_wpa3 ? security_choice(WifiSecurity::Wpa3Personal) : View{},
      }.With(Spacing(8.0F)),
      selected_security != WifiSecurity::Open ? Column {
        Text("Wi-Fi password"),
        TextField(passphrase).InputConfiguration({.secure = true, .autocorrect = false}).With(Enabled(available))
            .OnChanged([passphrase](const TextEditingValue& value) { passphrase = value; }),
      }.With(Spacing(6.0F), CrossAlign(CrossAxisAlignment::Stretch)) : View{},
      Flow {
        Button("Join hotspot").With(Enabled(available && !ssid->text.empty() &&
            (selected_security == WifiSecurity::Open || !passphrase->text.empty()))).OnClick(join),
        route->network ? Button("Release Wi-Fi route").With(Enabled(available)).OnClick([=] {
          route.Update([](PreviewWifiRoute& value) { value.network.reset(); });
          FinishWifi(route, state, "Wi-Fi route released. Outgoing connections use system routing.");
        }) : View{},
      }.With(Spacing(8.0F)),
    }.With(Spacing(6.0F), CrossAlign(CrossAxisAlignment::Stretch)) : View{},
    !state->status.empty() ? Text(state->status) : View{},
  }.With(Spacing(8.0F), CrossAlign(CrossAxisAlignment::Stretch));
}

} // namespace local_network_preview
