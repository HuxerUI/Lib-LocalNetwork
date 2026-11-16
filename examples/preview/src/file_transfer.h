#pragma once

#include <variant>

#include <huxerui/file.h>
#include <huxerui/local_network_pairing.h>

namespace local_network_preview {

using Source = std::variant<huxerui::File, huxerui::FileReference>;

struct TransferResult {
  std::uint64_t sent;
  std::uint64_t received;
  std::string received_digest;
};

/// Writes the Preview's deterministic 64 MiB sample.
huxerui::Task<huxerui::IoResult<void>> CreateSample(huxerui::File file);
/// Exchanges one file in each direction and verifies the received SHA-256 before moving partial to destination.
/// Supply distinct scratch and destination paths owned by this transfer. Failure may remove both paths.
huxerui::Task<huxerui::IoResult<TransferResult>> ExchangeFiles(
    huxerui::TaskScope tasks, huxerui::localnetwork::PairedConnection connection,
    Source source, huxerui::File partial, huxerui::File destination);

} // namespace local_network_preview
