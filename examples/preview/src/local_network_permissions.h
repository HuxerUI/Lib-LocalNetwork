#pragma once

#include <huxerui/app.h>

namespace local_network_preview {

/// Registers Preview's platform integration for local network permission and app settings.
void InstallLocalNetworkPermissions(huxerui::ApplicationContext& context);

/// Requests broad local network access where Android requires it. Other builds report Granted.
huxerui::Task<huxerui::PermissionStatus> RequestLocalNetworkAccess();

/// Opens Preview's system application settings for permission recovery.
huxerui::Task<bool> OpenLocalNetworkPermissionSettings();

} // namespace local_network_preview
