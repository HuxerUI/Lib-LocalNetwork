#pragma once

#include <huxerui/bitmap.h>
#include <huxerui/file.h>
#include <huxerui/local_network_pairing.h>

namespace local_network_preview {

struct ScannedInvitation {
  huxerui::localnetwork::Endpoint endpoint;
  /// Secret-bearing pairing text to pass to PairingCode::Parse().
  std::string code;
};

/// Encodes a concrete LAN endpoint and pairing code. Returns an empty bitmap if unavailable.
huxerui::Bitmap MakeInvitationQr(const huxerui::localnetwork::Endpoint& endpoint, std::string_view code);
/// Reads a pairing invitation from an image selected through the system picker.
huxerui::Task<huxerui::IoResult<ScannedInvitation>> ReadInvitationQr(huxerui::FileReference image);
/// Reads a pairing invitation from an app-accessible image file.
huxerui::Task<huxerui::IoResult<ScannedInvitation>> ReadInvitationQr(huxerui::File image);
/// Registers the Preview's system camera integration on Android and iOS.
void InstallQrCamera(huxerui::ApplicationContext& context);
/// Captures a QR photo to the app's temporary directory. A successful false means no photo was returned.
huxerui::Task<huxerui::IoResult<bool>> CaptureQrPhoto(huxerui::File destination);

} // namespace local_network_preview
