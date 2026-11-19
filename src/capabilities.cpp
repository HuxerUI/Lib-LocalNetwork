#if defined(__ANDROID__) && !defined(__ANDROID_UNAVAILABLE_SYMBOLS_ARE_WEAK__)
// The target SDK query is guarded at runtime. Keep this translation unit loadable on API 23.
#define __ANDROID_UNAVAILABLE_SYMBOLS_ARE_WEAK__
#endif

#include <huxerui/local_network.h>

#include "bridge_backend.h"
#include "wifi_backend.h"

#if defined(__ANDROID__)
#include <android/api-level.h>
#elif defined(__APPLE__)
#include <TargetConditionals.h>
#endif

namespace huxerui::localnetwork {
namespace {

using Status = CapabilityStatus;

Status IfSupported(bool supported, Status status = Status::Available) noexcept {
  return supported ? status : Status::Unsupported;
}

} // namespace

Capabilities GetCapabilities() noexcept {
  auto inbound = Status::Available;
  auto outbound = Status::Available;
  auto discovery = Status::Available;
  auto wifi_join = Status::RequiresUserAction;
  bool wifi_supported_version = true;

  Capabilities result;
#if defined(__ANDROID__)
  const int api_level = android_get_device_api_level();
  wifi_supported_version = api_level >= 29;
  if (__builtin_available(android 37, *)) {
    if (android_get_application_target_sdk_version() >= 37) {
      inbound = outbound = discovery = Status::RequiresPermission;
    }
  }
  result.wifi_route_selection = IfSupported(api_level >= 31, Status::RequiresPermission);
  result.android_network_binding = IfSupported(api_level >= 23, outbound);
  result.wifi_bound_http = IfSupported(wifi_supported_version, outbound);
#elif defined(__APPLE__) && TARGET_OS_IOS
  outbound = discovery = Status::RequiresPermission;
#elif defined(__APPLE__) && TARGET_OS_OSX
  if (__builtin_available(macOS 15.0, *)) outbound = discovery = Status::RequiresPermission;
  wifi_join = Status::RequiresPermission;
#elif defined(_WIN32)
  wifi_join = Status::RequiresPermission;
#endif

  const bool tcp = IsTcpSupported();
  const bool tls = IsTlsClientSupported();
  const bool pairing = IsPairingSupported();
  result.tcp_dial = IfSupported(tcp, outbound);
  result.tcp_listen = IfSupported(tcp, inbound);
  result.tls_dial = IfSupported(tls, outbound);
  result.tls_listen = IfSupported(tls, inbound);
  result.paired_tls_dial = IfSupported(pairing, outbound);
  result.paired_tls_listen = IfSupported(pairing, inbound);
  result.dns_sd = IfSupported(IsDiscoverySupported(), discovery);
  result.dns_sd_picker = IfSupported(IsServicePickerSupported(), Status::RequiresUserAction);
  // A fresh scan may require Location access or system authorization such as NetworkManager's scan policy.
  result.wifi_scan = IfSupported(wifi_supported_version && IsWifiScanSupported(), Status::RequiresPermission);
  result.wifi_join = IfSupported(wifi_supported_version && IsWifiJoinSupported(), wifi_join);
  result.wifi_join_saved_profile = IfSupported(detail::wifi_profile_supported, wifi_join);
#ifdef HUXERUI_LOCALNETWORK_WSLAY
  result.web_bridge_host = Status::RequiresUserAction;
#endif
#ifdef __EMSCRIPTEN__
  result.web_bridge_client = IfSupported(detail::IsBrowserBridgeSupported(), Status::RequiresUserAction);
#endif
  return result;
}

} // namespace huxerui::localnetwork
