#ifdef _WIN32
#include <windows.h>
#include <dpapi.h>
#endif

#include "identity_store.h"

#include <utility>

namespace local_network_preview {
namespace {

using namespace huxerui;
using namespace huxerui::localnetwork;

NetworkError StorageError(std::string message, int code = 0) {
  return {NetworkErrorCode::System, code, std::move(message)};
}

NetworkResult<Bytes> TransformKey(Bytes key, bool protect) {
#ifdef _WIN32
  // DPAPI scopes the saved key to the Windows user. The Android preview uses its app-private data directory.
  DATA_BLOB input{static_cast<DWORD>(key.size()), reinterpret_cast<BYTE*>(key.data())};
  DATA_BLOB output{};
  const bool succeeded = protect
      ? CryptProtectData(&input, L"HuxerUI LocalNetwork", nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output)
      : CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output);
  const auto error = succeeded ? 0 : static_cast<int>(GetLastError());
  if (!key.empty()) SecureZeroMemory(key.data(), key.size());
  if (!succeeded) return NetworkResult<Bytes>::Failure(StorageError("Could not access the local device key.", error));
  struct Buffer {
    DATA_BLOB value;
    ~Buffer() {
      SecureZeroMemory(value.pbData, value.cbData);
      LocalFree(value.pbData);
    }
  } buffer{output};
  const auto* begin = reinterpret_cast<const std::byte*>(buffer.value.pbData);
  return NetworkResult<Bytes>::Success(Bytes(begin, begin + buffer.value.cbData));
#else
  static_cast<void>(protect);
  return NetworkResult<Bytes>::Success(std::move(key));
#endif
}

} // namespace

Task<NetworkResult<DeviceIdentity>> LoadIdentity(File key, File staging) {
  using Result = NetworkResult<DeviceIdentity>;
  auto saved = co_await key.OpenReadAsync();
  if (saved.Succeeded()) {
    auto input = std::move(saved).Value();
    Bytes blob;
    for (;;) {
      auto part = co_await input.ReadAsync(4096);
      if (!part.Succeeded()) co_return Result::Failure(StorageError(part.Error().message));
      if (part.Value().empty()) break;
      if (part.Value().size() > 4096 - blob.size()) {
        co_return Result::Failure(StorageError("The saved device key is too large."));
      }
      blob.insert(blob.end(), part.Value().begin(), part.Value().end());
    }
    auto restored = co_await RunWorker(TransformKey, std::move(blob), false);
    if (!restored.Succeeded()) co_return Result::Failure(std::move(restored).Error());
    co_return co_await DeviceIdentity::ImportAsync(std::move(restored).Value());
  }
  if (saved.Error().code != IoErrorCode::NotFound) co_return Result::Failure(StorageError(saved.Error().message));
  auto generated = co_await DeviceIdentity::GenerateAsync();
  if (!generated.Succeeded()) co_return generated;
  auto encoded = co_await generated.Value().ExportPrivateKeyAsync();
  if (!encoded.Succeeded()) co_return Result::Failure(std::move(encoded).Error());
  auto protected_key = co_await RunWorker(TransformKey, std::move(encoded).Value(), true);
  if (!protected_key.Succeeded()) co_return Result::Failure(std::move(protected_key).Error());
  if (!co_await staging.WriteBytesAsync(std::move(protected_key).Value()) || !co_await staging.MoveToAsync(key)) {
    (void)co_await staging.DeleteAsync();
    co_return Result::Failure(StorageError("Could not save the device identity."));
  }
  co_return generated;
}

} // namespace local_network_preview
