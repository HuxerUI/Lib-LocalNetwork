#include <huxerui/local_network_connection.h>
#include <huxerui/local_network_wifi.h>

#include <span>
#include <utility>

namespace huxerui::localnetwork {
namespace {

NetworkError LostRoute() {
  return {NetworkErrorCode::NetworkLost, 0, "The selected Wi-Fi network was lost."};
}

NetworkError WrongServiceNetwork() {
  return {NetworkErrorCode::ResolveFailed, 0, "The DNS-SD service could not be verified on the selected network."};
}

Task<NetworkResult<Connection>> InvalidDial(std::string message) {
  co_return NetworkResult<Connection>::Failure({NetworkErrorCode::InvalidEndpoint, 0, std::move(message)});
}

Task<NetworkResult<std::vector<Endpoint>>> ResolveTarget(DiscoveredService service, TcpDialOptions& options) {
  using Result = NetworkResult<std::vector<Endpoint>>;
  if (options.android_network == 0 || (options.android_network && options.wifi_network) ||
      options.timeout <= std::chrono::milliseconds::zero()) {
    co_return Result::Failure({NetworkErrorCode::InvalidEndpoint, 0, "Invalid TCP dial options."});
  }
#ifndef __ANDROID__
  if (options.android_network || options.wifi_network) {
    co_return Result::Failure(
        {NetworkErrorCode::Unsupported, 0, "Android network binding is unavailable on this platform."});
  }
#endif
  const auto selected = options.wifi_network ? options.wifi_network->AndroidNetwork() : options.android_network;
  if (options.wifi_network && !selected) co_return Result::Failure(LostRoute());

  const auto scope = service.scope;
  // Android reports an actual Network handle as the service scope. An explicit route requires that scope.
  if (selected && scope != *selected) co_return Result::Failure(WrongServiceNetwork());
  auto resolved = co_await ResolveServiceAsync(std::move(service));
  if (options.wifi_network && !options.wifi_network->AndroidNetwork()) co_return Result::Failure(LostRoute());
  if (!resolved.Succeeded()) co_return Result::Failure(resolved.Error());

  const auto network = resolved.Value().android_network;
  if ((selected && selected != network) || (network && scope != 0 && scope != *network))
    co_return Result::Failure(WrongServiceNetwork());
  if (!selected) options.android_network = network;
  if (resolved.Value().endpoints.empty())
    co_return Result::Failure({NetworkErrorCode::ResolveFailed, 0, "The DNS-SD service has no usable endpoints."});
  co_return Result::Success(std::move(resolved).Value().endpoints);
}

template<class Dial>
Task<NetworkResult<Connection>> DialTarget(Target target, TcpDialOptions options, Dial dial) {
  using Result = NetworkResult<Connection>;
  std::vector<Endpoint> resolved;
  std::span<const Endpoint> endpoints;
  if (const auto* endpoint = std::get_if<Endpoint>(&target)) {
    endpoints = std::span(endpoint, 1);
  } else {
    auto candidates = co_await ResolveTarget(std::get<DiscoveredService>(std::move(target)), options);
    if (!candidates.Succeeded()) co_return Result::Failure(candidates.Error());
    resolved = std::move(candidates).Value();
    endpoints = resolved;
  }

  NetworkError failure{NetworkErrorCode::ConnectionFailed, 0, "No connection could be established."};
  for (const auto& endpoint : endpoints) {
    auto connected = co_await dial(endpoint, options);
    if (options.wifi_network && !options.wifi_network->AndroidNetwork()) co_return Result::Failure(LostRoute());
    if (connected.Succeeded()) co_return Result::Success(Connection(std::move(connected).Value()));
    failure = std::move(connected).Error();
    // Try other addresses for reachability failures. Authentication and route failures end the operation.
    if (failure.code != NetworkErrorCode::ConnectionFailed && failure.code != NetworkErrorCode::TimedOut) break;
  }
  co_return Result::Failure(std::move(failure));
}

} // namespace

Connection::Connection(TcpConnection connection) : transport_(std::move(connection)) {}
Connection::Connection(TlsConnection connection) : transport_(std::move(connection)) {}
Connection::Connection(PairedConnection connection) : transport_(std::move(connection)) {}
Connection::Connection(Connection&&) noexcept = default;
Connection& Connection::operator=(Connection&&) noexcept = default;
Connection::~Connection() = default;

AsyncInputStream& Connection::Input() noexcept {
  return std::visit([](auto& connection) -> AsyncInputStream& { return connection.Input(); }, transport_);
}

AsyncOutputStream& Connection::Output() noexcept {
  return std::visit([](auto& connection) -> AsyncOutputStream& { return connection.Output(); }, transport_);
}

const ConnectionPath& Connection::Path() const noexcept {
  return std::visit([](const auto& connection) -> const ConnectionPath& { return connection.Path(); }, transport_);
}

SecurityInfo Connection::Security() const noexcept {
  if (const auto* paired = std::get_if<PairedConnection>(&transport_))
    return {ConnectionSecurity::PairedTls, paired->Peer()};
  if (std::holds_alternative<TlsConnection>(transport_)) return {ConnectionSecurity::PlatformTls, {}};
  return {ConnectionSecurity::PlainTcp, {}};
}

Task<IoResult<void>> Connection::ShutdownWriteAsync() { return Output().CloseAsync(); }

Task<NetworkResult<void>> Connection::CloseAsync() {
  Close();
  co_return NetworkResult<void>::Success();
}

void Connection::Close() noexcept {
  std::visit([](auto& connection) { connection.Close(); }, transport_);
}

Task<NetworkResult<Connection>> ConnectAsync(
    Target target, DeviceIdentity identity, PeerCredential credential, TcpDialOptions options) {
  return DialTarget(std::move(target), std::move(options),
      [identity = std::move(identity), credential = std::move(credential)](Endpoint endpoint, TcpDialOptions tcp) {
        return ConnectPairedAsync(std::move(endpoint), identity, credential, std::move(tcp));
      });
}

Task<NetworkResult<Connection>> DialAsync(Target target, DialOptions options) {
  switch (options.mode) {
    case DialMode::Tcp:
      if (!options.server_name.empty())
        return InvalidDial("Plain TCP does not use a certificate name.");
      return DialTarget(std::move(target), std::move(options.tcp), DialTcpAsync);
    case DialMode::Tls:
      // DNS-SD supplies addresses. The expected certificate identity must come from the caller.
      if (std::holds_alternative<DiscoveredService>(target) && options.server_name.empty())
        return InvalidDial("A DNS-SD TLS dial requires a server name.");
      return DialTarget(std::move(target), std::move(options.tcp),
          [name = std::move(options.server_name)](Endpoint endpoint, TcpDialOptions tcp) {
            return DialTlsAsync(std::move(endpoint), {std::move(tcp), name});
          });
  }
  return InvalidDial("Invalid accessory transport mode.");
}

} // namespace huxerui::localnetwork
