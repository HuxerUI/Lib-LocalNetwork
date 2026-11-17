#pragma once

#include <huxerui/app.h>

namespace local_network_preview {

/// Registers Preview's platform integration for Wi-Fi settings and permission requests.
void InstallWifiControls(huxerui::ApplicationContext& context);

#ifdef __ANDROID__
/// Android 13 and later use Nearby Devices for joining. Earlier releases request precise location.
huxerui::Task<huxerui::PermissionStatus> RequestAndroidWifiJoinPermission(huxerui::ApplicationHandle app);
#endif

/// Opens the system desktop or mobile Wi-Fi settings where a public platform entry exists.
huxerui::Task<bool> OpenWifiSettings();

} // namespace local_network_preview
