#include <huxerui/android/platform_registry.h>
#include <huxerui/app.h>

#include "../../../../../src/wifi_backend.h"

#include <atomic>

namespace huxerui::localnetwork::detail {
namespace {

constexpr char module_name[] = "localnetwork/Wifi";

class WifiModule final : public WifiNetworkState {
public:
  explicit WifiModule(PlatformChannel channel) : channel_(std::move(channel)), lost_(std::make_shared<std::atomic_bool>()) {
    channel_.On("lost", [lost = lost_](const PlatformPayload&) { *lost = true; });
  }
  ~WifiModule() override { channel_.Close(); }

  Task<PlatformResult<PlatformPayload>> Call(std::string method, PlatformPayload payload) {
    return AwaitCallback<PlatformResult<PlatformPayload>>(
        [channel = channel_, method = std::move(method), payload = std::move(payload)](auto completion) mutable {
          const auto request = channel.Invoke(std::move(method), std::move(payload),
              [completion](PlatformResult<PlatformPayload> result) { completion.Complete(std::move(result)); });
          return [channel, request] { (void)channel.Cancel(request); };
        });
  }

  void SetNetwork(std::uint64_t handle) noexcept { network_ = handle; }

  std::optional<std::uint64_t> AndroidNetwork() const noexcept override {
    if (*lost_ || !channel_.IsOpen() || network_ == 0) return std::nullopt;
    return network_;
  }

private:
  PlatformChannel channel_;
  std::shared_ptr<std::atomic_bool> lost_;
  std::uint64_t network_ = 0;
};

NetworkError WifiFailure(const PlatformError& error, NetworkErrorCode fallback) {
  auto code = fallback;
  if (error.code == "localnetwork/wifi-permission") code = NetworkErrorCode::PermissionDenied;
  else if (error.code == "localnetwork/wifi-unsupported") code = NetworkErrorCode::Unsupported;
  else if (error.code == "localnetwork/wifi-lost") code = NetworkErrorCode::NetworkLost;
  else if (error.code == "localnetwork/wifi-timeout") code = NetworkErrorCode::TimedOut;
  return {code, 0, error.message};
}

WifiSecurity DecodeSecurity(std::string_view value) {
  if (value == "open") return WifiSecurity::Open;
  if (value == "wpa2") return WifiSecurity::Wpa2Personal;
  if (value == "wpa3") return WifiSecurity::Wpa3Personal;
  return WifiSecurity::Other;
}

} // namespace

void InstallPlatformWifi(ApplicationContext& context) {
  android::JavaPlatformModuleFactory<std::shared_ptr<WifiModule>> factory;
  factory.class_name = "org.huxerui.lib.localnetwork.WifiModule";
  factory.create = [](PlatformChannel channel) { return std::make_shared<WifiModule>(std::move(channel)); };
  context.RegisterPlatformModule<std::shared_ptr<WifiModule>>(module_name, std::move(factory));
}

Task<NetworkResult<WifiScanResult>> ScanPlatformWifi() {
  using Result = NetworkResult<WifiScanResult>;
  auto module = OpenPlatformModule<std::shared_ptr<WifiModule>>(module_name);
  auto scanned = co_await module->Call("scan", {});
  if (const auto* error = std::get_if<PlatformError>(&scanned)) {
    co_return Result::Failure(WifiFailure(*error, NetworkErrorCode::WifiScanFailed));
  }
  const auto& fields = std::get<PlatformPayload>(scanned).AsObject();
  WifiScanResult result{.refreshed = fields.at("refreshed").AsBoolean()};
  for (const auto& entry : fields.at("networks").AsList()) {
    const auto& network = entry.AsObject();
    result.networks.push_back({std::string(network.at("ssid").AsString()), DecodeSecurity(network.at("security").AsString())});
  }
  co_return Result::Success(std::move(result));
}

Task<NetworkResult<WifiJoinResult>> JoinPlatformWifi(WifiJoinRequest request) {
  using Result = NetworkResult<WifiJoinResult>;
  if (request.mode == WifiJoinMode::Persistent) {
    co_return Result::Failure({NetworkErrorCode::Unsupported, 0, "Use system Wi-Fi settings to save the network."});
  }
  auto module = OpenPlatformModule<std::shared_ptr<WifiModule>>(module_name);
  const char* security = request.security == WifiSecurity::Open ? "open" :
      request.security == WifiSecurity::Wpa2Personal ? "wpa2" : "wpa3";
  PlatformPayload arguments = PlatformPayload::Object{
      {"ssid", std::move(request.ssid)}, {"security", security}, {"passphrase", std::move(request.passphrase)}};
  auto joined = co_await module->Call("join", std::move(arguments));
  if (const auto* error = std::get_if<PlatformError>(&joined)) {
    co_return Result::Failure(WifiFailure(*error, NetworkErrorCode::WifiJoinFailed));
  }
  module->SetNetwork(static_cast<std::uint64_t>(std::get<PlatformPayload>(joined).AsInteger()));
  if (!module->AndroidNetwork()) {
    co_return Result::Failure({NetworkErrorCode::NetworkLost, 0, "The requested Wi-Fi network was lost."});
  }
  co_return Result::Success({WifiJoinStatus::Associated, WifiNetworkAccess::Create(std::move(module))});
}

} // namespace huxerui::localnetwork::detail
