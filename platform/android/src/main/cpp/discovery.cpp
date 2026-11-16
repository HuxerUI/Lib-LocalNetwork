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
  return {error.code == "localnetwork/permission" ? NetworkErrorCode::PermissionDenied : NetworkErrorCode::DiscoveryFailed,
          0, error.message};
}

std::shared_ptr<DiscoveryModule> Open() {
  return OpenPlatformModule<std::shared_ptr<DiscoveryModule>>(module_name);
}

} // namespace

void InstallPlatformDiscovery(ApplicationContext& context) {
  android::JavaPlatformModuleFactory<std::shared_ptr<DiscoveryModule>> factory;
  factory.class_name = "org.huxerui.lib.localnetwork.DiscoveryModule";
  factory.create = [](PlatformChannel channel) { return std::make_shared<DiscoveryModule>(std::move(channel)); };
  context.RegisterPlatformModule<std::shared_ptr<DiscoveryModule>>(module_name, std::move(factory));
}

Task<NetworkResult<std::vector<DiscoveredService>>> BrowsePlatformServices(
    std::string type, std::chrono::milliseconds observation) {
  using Result = NetworkResult<std::vector<DiscoveredService>>;
  auto module = Open();
  PlatformPayload request = PlatformPayload::Object{{"type", type}, {"milliseconds", observation.count()}};
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
      {"name", service.instance}, {"type", service.type}, {"network", static_cast<std::int64_t>(service.scope)}};
  auto resolved = co_await module->Call("resolve", std::move(request));
  if (const auto* error = std::get_if<PlatformError>(&resolved)) co_return Result::Failure(Failure(*error));
  const auto& fields = std::get<PlatformPayload>(resolved).AsObject();
  auto port = fields.at("port").AsInteger();
  if (port <= 0 || port > 65535) co_return Result::Failure({NetworkErrorCode::ResolveFailed, 0, "Invalid DNS-SD port."});
  ResolvedService value;
  const auto network = fields.at("network").AsInteger();
  if (network != 0) value.android_network = static_cast<std::uint64_t>(network);
  else if (service.scope != 0) value.android_network = service.scope;
  for (const auto& address : fields.at("addresses").AsList()) {
    value.endpoints.push_back({std::string(address.AsString()), static_cast<std::uint16_t>(port)});
  }
  if (value.endpoints.empty()) {
    co_return Result::Failure({NetworkErrorCode::ResolveFailed, 0, "The service has no usable addresses."});
  }
  co_return Result::Success(std::move(value));
}

Task<NetworkResult<std::shared_ptr<PublicationState>>> PublishPlatformService(ServiceAnnouncement announcement) {
  using Result = NetworkResult<std::shared_ptr<PublicationState>>;
  auto module = Open();
  PlatformPayload request = PlatformPayload::Object{
      {"name", announcement.name}, {"type", announcement.type},
      {"host", announcement.endpoint.host}, {"port", announcement.endpoint.port}};
  auto registered = co_await module->Call("publish", std::move(request));
  if (const auto* error = std::get_if<PlatformError>(&registered)) co_return Result::Failure(Failure(*error));
  co_return Result::Success(std::move(module));
}

} // namespace huxerui::localnetwork::detail
