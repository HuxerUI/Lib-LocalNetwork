#include "file_transfer.h"

#include <algorithm>
#include <array>
#include <memory>
#include <span>

#ifdef HUXERUI_LOCALNETWORK_PREVIEW_TLS
#include <mbedtls/sha256.h>
#endif

namespace local_network_preview {
namespace {

using namespace huxerui;
using namespace huxerui::localnetwork;
using namespace std::chrono_literals;

#ifdef HUXERUI_LOCALNETWORK_PREVIEW_TLS
constexpr std::size_t chunk_size = 64 * 1024;
constexpr std::uint64_t file_limit = 1024ull * 1024 * 1024;
constexpr std::uint64_t sample_size = 64ull * 1024 * 1024;
constexpr std::array file_version{std::byte{'H'}, std::byte{'L'}, std::byte{'F'}, std::byte{1}};
constexpr std::byte receipt{1};

struct Hash {
  mbedtls_sha256_context context;

  Hash() { mbedtls_sha256_init(&context); }
  ~Hash() { mbedtls_sha256_free(&context); }

  bool Start() { return mbedtls_sha256_starts(&context, 0) == 0; }
  bool Update(std::span<const std::byte> bytes) {
    return mbedtls_sha256_update(&context, reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size()) == 0;
  }
  bool Finish(PeerId& digest) { return mbedtls_sha256_finish(&context, digest.digest.data()) == 0; }
};

struct FileHeader {
  std::uint64_t length = 0;
  PeerId digest;
};

constexpr std::size_t header_size = file_version.size() + sizeof(std::uint64_t) + sizeof(decltype(PeerId::digest));

IoError IoFailure(std::string message) { return {IoErrorCode::Io, std::move(message)}; }

Task<IoResult<AsyncInputStream>> OpenSource(const Source& source) {
  return std::visit([](const auto& file) { return file.OpenReadAsync(); }, source);
}

Task<IoResult<FileHeader>> InspectFile(const Source& source) {
  auto opened = co_await OpenSource(source);
  if (!opened.Succeeded()) co_return IoResult<FileHeader>::Failure(std::move(opened).Error());
  auto stream = std::move(opened).Value();
  FileHeader header;
  Hash hash;
  if (!hash.Start()) co_return IoResult<FileHeader>::Failure(IoFailure("Could not start SHA-256."));
  for (;;) {
    auto read = co_await stream.ReadAsync(chunk_size);
    if (!read.Succeeded()) co_return IoResult<FileHeader>::Failure(std::move(read).Error());
    const auto& bytes = read.Value();
    if (bytes.empty()) break;
    if (bytes.size() > file_limit - header.length) {
      co_return IoResult<FileHeader>::Failure({IoErrorCode::TooLarge, "Preview accepts files up to 1 GiB."});
    }
    header.length += bytes.size();
    if (!hash.Update(bytes)) co_return IoResult<FileHeader>::Failure(IoFailure("Could not hash the source file."));
  }
  if (!hash.Finish(header.digest)) co_return IoResult<FileHeader>::Failure(IoFailure("Could not finish SHA-256."));
  co_return IoResult<FileHeader>::Success(header);
}

Bytes EncodeHeader(const FileHeader& header) {
  Bytes bytes;
  bytes.reserve(header_size);
  bytes.insert(bytes.end(), file_version.begin(), file_version.end());
  for (int shift = 56; shift >= 0; shift -= 8) bytes.push_back(static_cast<std::byte>(header.length >> shift));
  for (const auto value : header.digest.digest) bytes.push_back(static_cast<std::byte>(value));
  return bytes;
}

Task<IoResult<Bytes>> ReadExact(AsyncInputStream& stream, std::size_t amount) {
  Bytes bytes;
  bytes.reserve(amount);
  while (bytes.size() < amount) {
    auto part = co_await stream.ReadAsync(amount - bytes.size());
    if (!part.Succeeded()) co_return IoResult<Bytes>::Failure(std::move(part).Error());
    if (part.Value().empty()) co_return IoResult<Bytes>::Failure(IoFailure("The peer closed the file stream early."));
    bytes.insert(bytes.end(), part.Value().begin(), part.Value().end());
  }
  co_return IoResult<Bytes>::Success(std::move(bytes));
}

Task<IoResult<std::uint64_t>> SendFile(AsyncOutputStream& stream, const Source& source) {
  auto inspected = co_await InspectFile(source);
  if (!inspected.Succeeded()) co_return IoResult<std::uint64_t>::Failure(std::move(inspected).Error());
  auto opened = co_await OpenSource(source);
  if (!opened.Succeeded()) co_return IoResult<std::uint64_t>::Failure(std::move(opened).Error());
  auto input = std::move(opened).Value();
  const auto& header = inspected.Value();
  auto written = co_await stream.WriteAsync(EncodeHeader(header));
  if (!written.Succeeded()) co_return IoResult<std::uint64_t>::Failure(std::move(written).Error());
  for (std::uint64_t remaining = header.length; remaining != 0;) {
    auto read = co_await input.ReadAsync(static_cast<std::size_t>((std::min<std::uint64_t>)(chunk_size, remaining)));
    if (!read.Succeeded()) co_return IoResult<std::uint64_t>::Failure(std::move(read).Error());
    if (read.Value().empty()) {
      co_return IoResult<std::uint64_t>::Failure(IoFailure("The source file changed during transfer."));
    }
    remaining -= read.Value().size();
    written = co_await stream.WriteAsync(std::move(read).Value());
    if (!written.Succeeded()) co_return IoResult<std::uint64_t>::Failure(std::move(written).Error());
  }
  auto tail = co_await input.ReadAsync(1);
  if (!tail.Succeeded()) co_return IoResult<std::uint64_t>::Failure(std::move(tail).Error());
  if (!tail.Value().empty()) {
    co_return IoResult<std::uint64_t>::Failure(IoFailure("The source file grew during transfer."));
  }
  co_return IoResult<std::uint64_t>::Success(header.length);
}

Task<IoResult<FileHeader>> ReceiveFile(AsyncInputStream& stream, const File& partial) {
  using Result = IoResult<FileHeader>;
  auto received = co_await ReadExact(stream, header_size);
  if (!received.Succeeded()) co_return Result::Failure(std::move(received).Error());
  const auto bytes = std::span<const std::byte>(received.Value());
  if (!std::ranges::equal(file_version, bytes.first(file_version.size()))) {
    co_return Result::Failure(IoFailure("The peer sent an unsupported file header."));
  }
  FileHeader header;
  for (const auto byte : bytes.subspan(file_version.size(), sizeof(header.length))) {
    header.length = (header.length << 8) | std::to_integer<std::uint8_t>(byte);
  }
  if (header.length > file_limit) {
    co_return Result::Failure({IoErrorCode::TooLarge, "The incoming file exceeds the 1 GiB Preview limit."});
  }
  std::ranges::transform(bytes.last(header.digest.digest.size()), header.digest.digest.begin(),
                         [](std::byte value) { return std::to_integer<std::uint8_t>(value); });
  auto opened = co_await partial.OpenWriteAsync();
  if (!opened.Succeeded()) co_return Result::Failure(std::move(opened).Error());
  auto output = std::move(opened).Value();
  Hash hash;
  if (!hash.Start()) co_return Result::Failure(IoFailure("Could not start SHA-256."));
  for (std::uint64_t remaining = header.length; remaining != 0;) {
    auto read = co_await stream.ReadAsync(static_cast<std::size_t>((std::min<std::uint64_t>)(chunk_size, remaining)));
    if (!read.Succeeded()) co_return Result::Failure(std::move(read).Error());
    if (read.Value().empty()) co_return Result::Failure(IoFailure("The peer closed before the file was received."));
    remaining -= read.Value().size();
    if (!hash.Update(read.Value())) co_return Result::Failure(IoFailure("Could not hash incoming data."));
    auto written = co_await output.WriteAsync(std::move(read).Value());
    if (!written.Succeeded()) co_return Result::Failure(std::move(written).Error());
  }
  PeerId digest;
  if (!hash.Finish(digest) || digest != header.digest) {
    co_return Result::Failure(IoFailure("The incoming file's SHA-256 did not match."));
  }
  auto closed = co_await output.CloseAsync();
  if (!closed.Succeeded()) co_return Result::Failure(std::move(closed).Error());
  co_return Result::Success(header);
}
#endif

} // namespace

Task<IoResult<void>> CreateSample(File file) {
#ifdef HUXERUI_LOCALNETWORK_PREVIEW_TLS
  auto opened = co_await file.OpenWriteAsync();
  if (!opened.Succeeded()) co_return IoResult<void>::Failure(std::move(opened).Error());
  auto output = std::move(opened).Value();
#ifdef __ANDROID__
  constexpr unsigned seed = 137;
#elif defined(_WIN32)
  constexpr unsigned seed = 73;
#else
  // Distinct sample bytes expose direction mix-ups when testing against Windows.
  constexpr unsigned seed = 191;
#endif
  Bytes chunk(chunk_size);
  for (std::size_t index = 0; index < chunk.size(); ++index) {
    chunk[index] = static_cast<std::byte>((seed + index) % 251);
  }
  for (std::uint64_t offset = 0; offset < sample_size; offset += chunk.size()) {
    auto written = co_await output.WriteAsync(chunk);
    if (!written.Succeeded()) co_return written;
  }
  co_return co_await output.CloseAsync();
#else
  co_return IoResult<void>::Failure({IoErrorCode::Unsupported, "File transfer is unavailable."});
#endif
}

Task<IoResult<TransferResult>> ExchangeFiles(TaskScope tasks, PairedConnection connection,
                                            Source source, File partial, File destination) {
  using Result = IoResult<TransferResult>;
#ifdef HUXERUI_LOCALNETWORK_PREVIEW_TLS
  auto peer = std::make_shared<PairedConnection>(std::move(connection));
  auto result = std::make_shared<std::optional<IoResult<std::uint64_t>>>();
  // Cancel the sibling writer and remove incomplete output if the receive task is canceled or fails.
  struct Exchange {
    std::shared_ptr<PairedConnection> peer;
    TaskHandle sending;
    File partial;
    File destination;
    bool completed = false;
    ~Exchange() {
      sending.Cancel();
      peer->Close();
      (void)partial.Delete();
      if (!completed) (void)destination.Delete();
    }
  } exchange{
      peer,
      tasks.Launch([peer, result, source = std::move(source)]() -> Task<void> {
        result->emplace(co_await SendFile(peer->Output(), source));
        if (!result->value().Succeeded()) peer->Close();
      }),
      partial, destination,
  };

  auto incoming = co_await ReceiveFile(peer->Input(), partial);
  if (result->has_value() && !result->value().Succeeded()) {
    co_return Result::Failure(std::move(result->value()).Error());
  }
  if (!incoming.Succeeded()) co_return Result::Failure(std::move(incoming).Error());
  while (!result->has_value()) co_await Delay(4ms);
  if (!result->value().Succeeded()) co_return Result::Failure(std::move(result->value()).Error());
  if (!co_await partial.MoveToAsync(destination)) {
    co_return Result::Failure(IoFailure("Could not finalize the received file."));
  }
  // Both writers have sent their complete file before either side waits for a receipt.
  Bytes acknowledgement(1, receipt);
  auto replied = co_await peer->Output().WriteAsync(std::move(acknowledgement));
  if (!replied.Succeeded()) co_return Result::Failure(std::move(replied).Error());
  auto confirmed = co_await ReadExact(peer->Input(), 1);
  if (!confirmed.Succeeded()) co_return Result::Failure(std::move(confirmed).Error());
  if (confirmed.Value().front() != receipt) co_return Result::Failure(IoFailure("The peer rejected the file."));
  auto closed = co_await peer->Output().CloseAsync();
  if (!closed.Succeeded()) co_return Result::Failure(std::move(closed).Error());
  auto eof = co_await peer->Input().ReadAsync(1);
  if (!eof.Succeeded()) co_return Result::Failure(std::move(eof).Error());
  if (!eof.Value().empty()) co_return Result::Failure(IoFailure("The peer sent data after its receipt."));
  exchange.completed = true;
  co_return Result::Success({result->value().Value(), incoming.Value().length, incoming.Value().digest.ToString()});
#else
  co_return Result::Failure({IoErrorCode::Unsupported, "File transfer is unavailable."});
#endif
}

} // namespace local_network_preview
