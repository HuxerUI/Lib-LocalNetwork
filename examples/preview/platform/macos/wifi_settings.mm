#import <AppKit/AppKit.h>

#include "../../src/wifi_platform.h"

namespace local_network_preview {

huxerui::Task<bool> OpenWifiSettings() {
  NSWorkspace* workspace = [NSWorkspace sharedWorkspace];
  // Use the system application entry. The user selects Wi-Fi in System Settings.
  NSURL* url = [workspace URLForApplicationWithBundleIdentifier:@"com.apple.systempreferences"];
  co_return url && [workspace openURL:url];
}

} // namespace local_network_preview
