#ifdef __APPLE__
#include <TargetConditionals.h>
#endif

#include "pairing_qr.h"
#include "listen_addresses.h"

#include <huxerui/resource.h>

#ifdef __ANDROID__
#include <huxerui/android/platform_registry.h>
#include <huxerui/app.h>
#endif

#include <charconv>
#include <utility>

#ifdef HUXERUI_LOCALNETWORK_PREVIEW_QR
#include <CreateBarcode.h>
#include <ReadBarcode.h>
#include <WriteBarcode.h>
#endif

namespace local_network_preview {
namespace {

using namespace huxerui;
using namespace huxerui::localnetwork;

#ifdef HUXERUI_LOCALNETWORK_PREVIEW_QR
// The QR envelope version is independent of the invitation version carried inside it.
constexpr std::string_view prefix = "huxer-lan/1\n";
constexpr std::size_t max_image_bytes = 24 * 1024 * 1024;
constexpr std::uint64_t max_image_pixels = 24000000;

IoResult<ScannedInvitation> Parse(std::string_view text) {
  using Result = IoResult<ScannedInvitation>;
  const IoError invalid{IoErrorCode::Io, "No LocalNetwork pairing QR code was found."};
  if (!text.starts_with(prefix) || text.size() > 256) return Result::Failure(invalid);
  text.remove_prefix(prefix.size());
  const auto host_end = text.find('\n');
  if (host_end == std::string_view::npos) return Result::Failure(invalid);
  const std::string host(text.substr(0, host_end));
  text.remove_prefix(host_end + 1);
  const auto port_end = text.find('\n');
  if (port_end == std::string_view::npos || !IsInvitationAddress(host)) return Result::Failure(invalid);
  std::uint16_t port{};
  const auto end = text.data() + port_end;
  const auto parsed = std::from_chars(text.data(), end, port);
  if (parsed.ptr != end || parsed.ec != std::errc{} || port == 0) return Result::Failure(invalid);
  text.remove_prefix(port_end + 1);
  const auto code = PairingCode::Decode(text);
  if (!code.Succeeded()) {
    if (code.Error().code == NetworkErrorCode::IncompatibleVersion)
      return Result::Failure({IoErrorCode::Unsupported, code.Error().message});
    return Result::Failure(invalid);
  }
  return Result::Success(ScannedInvitation{{host, port}, std::string(text)});
}

IoResult<ScannedInvitation> Decode(Bitmap bitmap) {
  const auto pixels = bitmap.Pixels();
  const auto width = static_cast<int>(bitmap.PixelWidth());
  const auto height = static_cast<int>(bitmap.PixelHeight());
  const ZXing::ImageView image(reinterpret_cast<const std::uint8_t*>(pixels.data()), width, height,
                              ZXing::ImageFormat::RGBA);
  const auto found = ZXing::ReadBarcode(image, ZXing::ReaderOptions().setFormats(ZXing::BarcodeFormat::QRCode));
  if (found.isValid()) return Parse(found.text());
  return IoResult<ScannedInvitation>::Failure({IoErrorCode::Io, "No LocalNetwork pairing QR code was found."});
}

template <class ImageFile> Task<IoResult<ScannedInvitation>> ReadImage(ImageFile image) {
  using Result = IoResult<ScannedInvitation>;
  auto opened = co_await image.OpenReadAsync();
  if (!opened.Succeeded()) co_return Result::Failure(std::move(opened).Error());
  auto stream = std::move(opened).Value();
  Bytes encoded;
  for (;;) {
    auto read = co_await stream.ReadAsync(64 * 1024);
    if (!read.Succeeded()) co_return Result::Failure(std::move(read).Error());
    if (read.Value().empty()) break;
    if (read.Value().size() > max_image_bytes - encoded.size()) {
      co_return Result::Failure({IoErrorCode::TooLarge, "The QR image exceeds 24 MiB."});
    }
    encoded.insert(encoded.end(), read.Value().begin(), read.Value().end());
  }
  try {
    const auto asset = ImageAsset::FromEncoded(std::move(encoded));
    if (static_cast<std::uint64_t>(asset.PixelWidth()) * asset.PixelHeight() > max_image_pixels) {
      co_return Result::Failure({IoErrorCode::TooLarge, "The QR image exceeds 24 megapixels."});
    }
    auto bitmap = co_await asset.DecodeAsync();
    co_return co_await RunWorker(Decode, std::move(bitmap));
  } catch (const std::exception&) {
    co_return Result::Failure({IoErrorCode::Io, "Could not decode the QR image."});
  }
}
#endif

#ifdef __ANDROID__
constexpr char camera_name[] = "localnetwork/QrCamera";

class QrCamera final {
public:
  explicit QrCamera(PlatformChannel channel) : channel_(std::move(channel)) {}
  ~QrCamera() { channel_.Close(); }

  Task<PlatformResult<bool>> Capture(std::string path) {
    return AwaitCallback<PlatformResult<bool>>([channel = channel_, path = std::move(path)](auto completion) {
      const auto request = channel.Invoke<bool>("capture", path,
          [completion](PlatformResult<bool> result) { completion.Complete(std::move(result)); });
      return [channel, request] { (void)channel.Cancel(request); };
    });
  }

private:
  PlatformChannel channel_;
};
#endif

} // namespace

Bitmap MakeInvitationQr(const Endpoint& endpoint, std::string_view code) {
#ifdef HUXERUI_LOCALNETWORK_PREVIEW_QR
  if (!IsInvitationAddress(endpoint.host) || endpoint.port == 0 || !PairingCode::Parse(code)) return {};
  const auto text = std::string(prefix) + endpoint.host + '\n' + std::to_string(endpoint.port) + '\n' + std::string(code);
  const auto barcode = ZXing::CreateBarcodeFromText(text, ZXing::CreatorOptions(ZXing::BarcodeFormat::QRCode));
  const auto image = ZXing::WriteBarcodeToImage(barcode, ZXing::WriterOptions().scale(6).addQuietZones(true));
  if (image.width() <= 0 || image.height() <= 0) return {};
  Bytes rgba(static_cast<std::size_t>(image.width()) * static_cast<std::size_t>(image.height()) * 4);
  for (int y = 0; y < image.height(); ++y) {
    for (int x = 0; x < image.width(); ++x) {
      const auto color = static_cast<std::byte>(*image.data(x, y));
      const auto first = (static_cast<std::size_t>(y) * image.width() + x) * 4;
      rgba[first] = rgba[first + 1] = rgba[first + 2] = color;
      rgba[first + 3] = std::byte{255};
    }
  }
  return Bitmap::FromRgba8(image.width(), image.height(), std::move(rgba));
#else
  return {};
#endif
}

Task<IoResult<ScannedInvitation>> ReadInvitationQr(FileReference image) {
#ifdef HUXERUI_LOCALNETWORK_PREVIEW_QR
  return ReadImage(std::move(image));
#else
  co_return IoResult<ScannedInvitation>::Failure({IoErrorCode::Unsupported, "QR scanning is unavailable."});
#endif
}

Task<IoResult<ScannedInvitation>> ReadInvitationQr(File image) {
#ifdef HUXERUI_LOCALNETWORK_PREVIEW_QR
  return ReadImage(std::move(image));
#else
  co_return IoResult<ScannedInvitation>::Failure({IoErrorCode::Unsupported, "QR scanning is unavailable."});
#endif
}

#if !(defined(__APPLE__) && TARGET_OS_IOS)
#ifdef __ANDROID__
void InstallQrCamera(ApplicationContext& context) {
  android::JavaWindowPlatformModuleFactory<std::shared_ptr<QrCamera>> factory;
  factory.class_name = "org.huxerui.lib.localnetwork.preview.QrCameraModule";
  factory.create = [](PlatformChannel channel) { return std::make_shared<QrCamera>(std::move(channel)); };
  context.RegisterPlatformModule<std::shared_ptr<QrCamera>>(camera_name, std::move(factory));
}
#else
void InstallQrCamera(ApplicationContext&) {}
#endif

Task<IoResult<bool>> CaptureQrPhoto(File destination) {
#ifdef __ANDROID__
  auto module = OpenPlatformModule<std::shared_ptr<QrCamera>>(camera_name);
  auto captured = co_await module->Capture(destination.Path());
  if (const auto* error = std::get_if<PlatformError>(&captured)) {
    co_return IoResult<bool>::Failure({IoErrorCode::Io, error->message});
  }
  co_return IoResult<bool>::Success(std::get<bool>(captured));
#else
  co_return IoResult<bool>::Failure({IoErrorCode::Unsupported, "Camera capture is unavailable."});
#endif
}
#endif

} // namespace local_network_preview
