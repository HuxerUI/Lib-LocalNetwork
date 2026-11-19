#include <android/api-level.h>

#include <huxerui/android/platform_registry.h>
#include <huxerui/app.h>

#include "../../../../../src/discovery_backend.h"

#include <utility>

namespace huxerui::localnetwork::detail {
namespace {

constexpr char module_name[] = "localnetwork/Discovery";

class DiscoveryModule final : public PublicationState {
public:
  explicit DiscoveryModule(PlatformChannel channel) : channel_(std::move(channel)) {}
  ~DiscoveryModule() override { Close(); }

  Task<PlatformResult<PlatformPayload>> Call(std::string method, PlatformPayload payload) {
    return AwaitCallback<PlatformResult<PlatformPayload>>(
        [channel = channel_, method = std::move(method), payload = std::move(payload)](auto completion) mutable {
          const auto request = channel.Invoke(std::move(method), std::move(payload),
              [completion](PlatformResult<PlatformPayload> result) { completion.Complete(std::move(result)); });
          return [channel, request] { (void)channel.Cancel(request); };
        });
  }

  void Close() noexcept override { channel_.Close(); }

private:
  PlatformChannel channel_;
};

NetworkError Failure(const PlatformError& error) {
  auto code = NetworkErrorCode::DiscoveryFailed;
  if (error.code == "localnetwork/permission") code = NetworkErrorCode::PermissionDenied;
  if (error.code == "localnetwork/discovery-unsupported") code = NetworkErrorCode::Unsupported;
  return {code, 0, error.message};
}

std::shared_ptr<DiscoveryModule> Open() {
  return OpenPlatformModule<std::shared_ptr<DiscoveryModule>>(module_name);
}

NetworkResult<ResolvedService> DecodeResolution(const PlatformPayload& payload, std::uint64_t fallback_scope = 0) {
  using Result = NetworkResult<ResolvedService>;
  const auto& fields = payload.AsObject();
  const auto port = fields.at("port").AsInteger();
  if (port <= 0 || port > 65535) return Result::Failure({NetworkErrorCode::ResolveFailed, 0, "Invalid DNS-SD port."});
  ResolvedService value;
  const auto network = fields.at("network").AsInteger();
  if (network != 0) value.android_network_handle = static_cast<std::uint64_t>(network);
  else if (fallback_scope != 0) value.android_network_handle = fallback_scope;
  for (const auto& address : fields.at("addresses").AsList()) {
    value.endpoints.push_back({std::string(address.AsString()), static_cast<std::uint16_t>(port)});
  }
  for (const auto& [key, text] : fields.at("txt").AsObject()) {
    const auto bytes = text.AsBytes();
    const auto chars = bytes.empty() ? std::string_view{} :
        std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    InsertServiceTxt(value.txt, key, chars);
  }
  if (value.endpoints.empty()) {
    return Result::Failure({NetworkErrorCode::ResolveFailed, 0, "The service has no usable addresses."});
  }
  return Result::Success(std::move(value));
}

} // namespace

void InstallPlatformDiscovery(ApplicationContext& context) {
  android::JavaPlatformModuleFactory<std::shared_ptr<DiscoveryModule>> factory;
  factory.class_name = "org.huxerui.lib.localnetwork.DiscoveryModule";
  factory.create = [](PlatformChannel channel) { return std::make_shared<DiscoveryModule>(std::move(channel)); };
  context.RegisterPlatformModule<std::shared_ptr<DiscoveryModule>>(module_name, std::move(factory));
}

Task<NetworkResult<std::vector<DiscoveredService>>> BrowsePlatformServices(
    std::string type, ServiceBrowseOptions options) {
  using Result = NetworkResult<std::vector<DiscoveredService>>;
  auto module = Open();
  PlatformPayload request = PlatformPayload::Object{{"type", type}, {"milliseconds", options.observation.count()},
      {"network", static_cast<std::int64_t>(options.scope.value_or(0))}};
  auto browsed = co_await module->Call("browse", std::move(request));
  if (const auto* error = std::get_if<PlatformError>(&browsed)) co_return Result::Failure(Failure(*error));
  std::vector<DiscoveredService> services;
  for (const auto& entry : std::get<PlatformPayload>(browsed).AsList()) {
    const auto& fields = entry.AsObject();
    const auto name = std::string(fields.at("name").AsString());
    services.push_back({name, type, name, static_cast<std::uint64_t>(fields.at("network").AsInteger())});
  }
  co_return Result::Success(std::move(services));
}

Task<NetworkResult<ResolvedService>> ResolvePlatformService(DiscoveredService service) {
  using Result = NetworkResult<ResolvedService>;
  auto module = Open();
  PlatformPayload request = PlatformPayload::Object{
      {"name", service.instance_id}, {"type", service.type},
      {"network", static_cast<std::int64_t>(service.scope)}};
  auto resolved = co_await module->Call("resolve", std::move(request));
  if (const auto* error = std::get_if<PlatformError>(&resolved)) co_return Result::Failure(Failure(*error));
  co_return DecodeResolution(std::get<PlatformPayload>(resolved), service.scope);
}

bool IsPlatformServicePickerSupported() noexcept { return android_get_device_api_level() >= 37; }

Task<NetworkResult<std::optional<ResolvedService>>> PickPlatformService(
    std::string type, std::optional<std::uint64_t> android_network_handle) {
  using Result = NetworkResult<std::optional<ResolvedService>>;
  auto module = Open();
  PlatformPayload request = PlatformPayload::Object{{"type", std::move(type)},
      {"network", static_cast<std::int64_t>(android_network_handle.value_or(0))}};
  auto picked = co_await module->Call("pick", std::move(request));
  if (const auto* error = std::get_if<PlatformError>(&picked)) co_return Result::Failure(Failure(*error));
  const auto& payload = std::get<PlatformPayload>(picked);
  if (payload.IsNull()) co_return Result::Success(std::nullopt);

  // Use only the network and addresses delivered by the picker. A discovery scope alone does not grant access.
  auto resolved = DecodeResolution(payload);
  if (!resolved.Succeeded()) co_return Result::Failure(std::move(resolved).Error());
  const auto network = resolved.Value().android_network_handle;
  if (!network || (android_network_handle && network != android_network_handle)) {
    co_return Result::Failure({NetworkErrorCode::ResolveFailed, 0, "The selected service has no matching Android network."});
  }
  co_return Result::Success(std::move(resolved).Value());
}

Task<NetworkResult<std::shared_ptr<PublicationState>>> PublishPlatformService(ServiceAnnouncement announcement) {
  using Result = NetworkResult<std::shared_ptr<PublicationState>>;
  auto module = Open();
  PlatformPayload::Object txt;
  for (auto& [key, value] : announcement.txt) txt.emplace(key, std::move(value));
  PlatformPayload request = PlatformPayload::Object{
      {"name", announcement.name}, {"type", announcement.type},
      {"host", announcement.endpoint.host}, {"port", announcement.endpoint.port}, {"txt", std::move(txt)}};
  auto registered = co_await module->Call("publish", std::move(request));
  if (const auto* error = std::get_if<PlatformError>(&registered)) co_return Result::Failure(Failure(*error));
  co_return Result::Success(std::move(module));
}

} // namespace huxerui::localnetwork::detail
