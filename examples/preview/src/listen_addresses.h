#pragma once

#include <string>
#include <vector>

#include <huxerui/local_network_common.h>
#include <huxerui/task.h>

namespace local_network_preview {

/// A numeric bind address found on an active local network interface.
struct ListenAddress {
  /// Address to copy into the Preview's bind field.
  std::string host;
  /// System display name or interface name.
  std::string interface_name;
};

/// Checks whether a numeric address can be shared with another device in a pairing invitation.
bool IsInvitationAddress(const std::string& host);

/// Collects a snapshot of the native addresses suitable for the Preview's listener and pairing QR.
/// The application may still enter a concrete bind address manually.
huxerui::Task<huxerui::localnetwork::NetworkResult<std::vector<ListenAddress>>> ListListenAddressesAsync();

} // namespace local_network_preview
