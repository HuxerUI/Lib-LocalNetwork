#include <huxerui/android/platform_registry.h>
#include <huxerui/app.h>

#include "../../../../../src/wifi_backend.h"

namespace huxerui::localnetwork::detail {
namespace {

constexpr char module_name[] = "localnetwork/Wifi";

class WifiModule final : public WifiNetworkState {
public:
  explicit WifiModule(PlatformChannel channel) : channel_(std::move(channel)) {
    channel_.On("lost", [lost = lost_](const PlatformPayload&) {
      // Closing a socket can release the last owner of this module during notification.
      auto signal = lost;
      signal.request_stop();
    });
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
    if (lost_.stop_requested() || !channel_.IsOpen() || network_ == 0) return std::nullopt;
    return network_;
  }

  std::stop_token LossToken() const noexcept override { return lost_.get_token(); }

private:
  PlatformChannel channel_;
  std::stop_source lost_;
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

NetworkResult<std::shared_ptr<const WifiNetworkLease>> RetainRoute(
    std::shared_ptr<WifiModule> module, PlatformResult<PlatformPayload> result) {
  using Result = NetworkResult<std::shared_ptr<const WifiNetworkLease>>;
  if (const auto* error = std::get_if<PlatformError>(&result)) {
    return Result::Failure(WifiFailure(*error, NetworkErrorCode::WifiJoinFailed));
  }
  module->SetNetwork(static_cast<std::uint64_t>(std::get<PlatformPayload>(result).AsInteger()));
  if (!module->AndroidNetwork()) {
    return Result::Failure({NetworkErrorCode::NetworkLost, 0, "The requested Wi-Fi network was lost."});
  }
  return Result::Success(WifiNetworkAccess::Create(std::move(module)));
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
  auto joined = RetainRoute(module, co_await module->Call("join", std::move(arguments)));
  if (!joined.Succeeded()) co_return Result::Failure(std::move(joined).Error());
  co_return Result::Success({WifiJoinStatus::Associated, std::move(joined).Value()});
}

Task<NetworkResult<std::shared_ptr<const WifiNetworkLease>>> SelectPlatformWifiRoute(std::string ssid) {
  auto module = OpenPlatformModule<std::shared_ptr<WifiModule>>(module_name);
  auto observed = co_await module->Call("selectRoute", std::move(ssid));
  co_return RetainRoute(std::move(module), std::move(observed));
}

Task<NetworkResult<HttpResponse>> SendPlatformWifiHttp(
    HttpRequest request, std::shared_ptr<const WifiNetworkLease> network) {
  using Result = NetworkResult<HttpResponse>;
  const char* method = nullptr;
  switch (request.method) {
    case HttpMethod::Get: method = "GET"; break;
    case HttpMethod::Head: method = "HEAD"; break;
    case HttpMethod::Post: method = "POST"; break;
    case HttpMethod::Put: method = "PUT"; break;
    case HttpMethod::Delete: method = "DELETE"; break;
    case HttpMethod::Options: method = "OPTIONS"; break;
    case HttpMethod::Patch: break;
  }
  if (!method) co_return Result::Failure({NetworkErrorCode::Unsupported, 0, "Unsupported Android HTTP method."});
  const auto module = std::dynamic_pointer_cast<WifiModule>(WifiNetworkAccess::State(*network));
  if (!module) co_return Result::Failure({NetworkErrorCode::Unsupported, 0, "This Wi-Fi lease cannot send HTTP."});
  PlatformPayload::List headers;
  for (auto& header : request.headers) {
    headers.emplace_back(PlatformPayload::Object{{"name", std::move(header.name)}, {"value", std::move(header.value)}});
  }
  PlatformPayload arguments = PlatformPayload::Object{
      {"url", request.url}, {"method", method}, {"headers", std::move(headers)},
      {"body", std::move(request.body)}, {"timeout", request.timeout->count()}};
  auto received = co_await module->Call("http", std::move(arguments));
  if (!network->AndroidNetwork()) {
    co_return Result::Failure({NetworkErrorCode::NetworkLost, 0, "The selected Wi-Fi network was lost."});
  }
  if (const auto* error = std::get_if<PlatformError>(&received)) {
    co_return Result::Failure(WifiFailure(*error, NetworkErrorCode::ConnectionFailed));
  }
  const auto& fields = std::get<PlatformPayload>(received).AsObject();
  HttpResponse response{.url = std::move(request.url), .status_code = static_cast<int>(fields.at("status").AsInteger())};
  for (const auto& header : fields.at("headers").AsList()) {
    const auto& values = header.AsObject();
    response.headers.push_back({std::string(values.at("name").AsString()), std::string(values.at("value").AsString())});
  }
  const auto body = fields.at("body").AsBytes();
  response.body.assign(body.begin(), body.end());
  co_return Result::Success(std::move(response));
}

} // namespace huxerui::localnetwork::detail
