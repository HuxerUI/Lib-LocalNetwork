#pragma once

#include <huxerui/file.h>
#include <huxerui/local_network_pairing.h>

namespace local_network_preview {

/// Loads the Preview's saved identity or creates one if the key file is missing.
/// Use a separate app-private staging path for a new key before moving it into place.
huxerui::Task<huxerui::localnetwork::NetworkResult<huxerui::localnetwork::DeviceIdentity>> LoadIdentity(
    huxerui::File key, huxerui::File staging);

} // namespace local_network_preview
