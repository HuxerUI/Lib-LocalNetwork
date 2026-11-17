#pragma once

#include <huxerui/huxerui.h>
#include <huxerui/local_network_wifi.h>

namespace local_network_preview {

/// Wi-Fi work and the Android route shared with Preview's pairing controls.
struct PreviewWifiRoute {
  bool busy = false;
  std::shared_ptr<const huxerui::localnetwork::WifiNetworkLease> network;
};

/// Displays Wi-Fi setup and keeps its credentials and scan results local to the panel.
huxerui::View WifiPanel(huxerui::State<PreviewWifiRoute> route, bool transfer_busy);

} // namespace local_network_preview
