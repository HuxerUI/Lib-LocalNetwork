#ifdef HUXERUI_LOCALNETWORK_WSLAY
#include "bridge_control_protocol.h"
#include "bridge_host_backend.h"

#include <algorithm>
#include <map>
#include <utility>

namespace huxerui::localnetwork::detail {
namespace {

using namespace std::chrono_literals;
constexpr std::size_t listener_limit = 8;
constexpr std::size_t connection_limit = 12;
constexpr std::size_t ticket_limit = 8;

NetworkError Denied() { return {NetworkErrorCode::PermissionDenied, 0, "The WSS control grant does not allow this operation."}; }
NetworkError Closed() { return {NetworkErrorCode::Closed, 0, "The WSS control session or registered listener is closed."}; }
NetworkError Busy() { return {NetworkErrorCode::Busy, 0, "The WSS control session has reached an operation limit."}; }
NetworkError Oversized() { return {NetworkErrorCode::Protocol, 0, "The DNS-SD result exceeds the WSS control message limit."}; }

struct Registration {
  TcpListener listener;
  std::optional<ServicePublication> publication;
  bool closed = false;
  bool accepting = false;

  void Close() noexcept {
    closed = true;
    publication.reset();
    listener.Close();
  }
};

struct DialIntent {
  Endpoint endpoint;
  PeerCredential credential;
};

using DataIntent = std::variant<DialIntent, std::shared_ptr<Registration>>;

struct DataTicket {
  DataIntent intent;
  BridgeClock::time_point expiry;
};

struct HostSession {
  struct Job {
    std::shared_ptr<SocketIo> socket;
    TaskHandle task;
  };

  std::shared_ptr<WebBridgeListenerState> owner;
  WebBridgePolicy policy;
  TaskScope tasks;
  std::shared_ptr<HostBridgeTransport> control;
  std::map<std::string, std::vector<DiscoveredService>, std::less<>> snapshots;
  std::map<std::uint32_t, std::shared_ptr<Registration>> registrations;
  std::map<std::string, DataTicket, std::less<>> tickets;
  std::map<std::uint64_t, Job> jobs;
  std::uint32_t next_registration = 1;
  std::uint64_t next_job = 1;
  bool closed = false;

  void Stop() noexcept {
    if (std::exchange(closed, true)) return;
    owner->listener.Close();
    owner->grant.clear();
    if (control) control->Close();
    for (auto& [id, registration] : registrations) registration->Close();
    tickets.clear();
    // Cancel can destroy a suspended task immediately. Its cleanup erases the job from the session.
    auto pending = std::exchange(jobs, {});
    for (auto& [id, job] : pending) {
      job.socket->Close();
      job.task.Cancel();
    }
  }

  std::shared_ptr<Registration> Find(std::uint32_t id) {
    const auto found = registrations.find(id);
    return found != registrations.end() ? found->second : nullptr;
  }

  void ExpireTickets() {
    const auto now = BridgeClock::now();
    std::erase_if(tickets, [&](const auto& entry) {
      if (entry.second.expiry <= now) return true;
      const auto* registration = std::get_if<std::shared_ptr<Registration>>(&entry.second.intent);
      return registration && (*registration)->closed;
    });
  }

  Bytes Issue(DataIntent intent) {
    ExpireTickets();
    if (tickets.size() == ticket_limit) return BridgeFailure(Busy());
    auto grant = GenerateBridgeGrant();
    if (!grant.Succeeded()) return BridgeFailure(grant.Error());
    if (!tickets.emplace(grant.Value(), DataTicket{std::move(intent), BridgeClock::now() + 20s}).second)
      return BridgeFailure(Busy());
    ControlWriter reply(BridgePacket::Response);
    reply.Write(grant.Value());
    return std::move(reply).Take();
  }
};

bool SameService(const DiscoveredService& left, const DiscoveredService& right) {
  return left.name == right.name && left.type == right.type && left.instance == right.instance &&
         left.scope == right.scope;
}

Task<Bytes> Browse(HostSession& host, ControlReader& request) {
  auto type = request.String();
  if (!request.Done()) co_return BridgeFailure(BridgeProtocolError());
  if (std::ranges::find(host.policy.browse_types, type) == host.policy.browse_types.end())
    co_return BridgeFailure(Denied());
  auto browsed = co_await BrowseServicesAsync(type, 2500ms, host.policy.browse_interface);
  if (!browsed.Succeeded()) co_return BridgeFailure(browsed.Error());
  auto services = std::move(browsed).Value();
  if (services.size() > bridge_service_limit) co_return BridgeFailure(Oversized());
  ControlWriter reply(BridgePacket::Response);
  reply.Write(static_cast<std::uint32_t>(services.size()));
  for (const auto& service : services) reply.Write(service);
  auto packet = std::move(reply).Take();
  if (packet.empty()) co_return BridgeFailure(Oversized());
  host.snapshots.insert_or_assign(std::move(type), std::move(services));
  co_return packet;
}

Task<Bytes> Resolve(HostSession& host, ControlReader& request) {
  auto service = request.ReadService();
  if (!request.Done()) co_return BridgeFailure(BridgeProtocolError());
  const auto snapshot = host.snapshots.find(service.type);
  if (snapshot == host.snapshots.end()) co_return BridgeFailure(Denied());
  const auto found = std::ranges::find_if(snapshot->second, [&](const auto& candidate) {
    return SameService(candidate, service);
  });
  if (found == snapshot->second.end()) co_return BridgeFailure(Denied());
  auto resolved = co_await ResolveServiceAsync(*found);
  if (!resolved.Succeeded()) co_return BridgeFailure(resolved.Error());
  const auto& result = resolved.Value();
  if (result.endpoints.size() > bridge_service_limit) co_return BridgeFailure(Oversized());
  ControlWriter reply(BridgePacket::Response);
  reply.Write(static_cast<std::uint32_t>(result.endpoints.size()));
  for (const auto& endpoint : result.endpoints) reply.Write(endpoint);
  reply.Write(result.txt);
  auto packet = std::move(reply).Take();
  co_return packet.empty() ? BridgeFailure(Oversized()) : std::move(packet);
}

Bytes AuthorizeDial(HostSession& host, ControlReader& request) {
  auto endpoint = request.ReadEndpoint();
  const auto peer = request.ReadPeer();
  const auto code = request.String();
  if (!request.Done()) return BridgeFailure(BridgeProtocolError());
  const auto target = std::ranges::find_if(host.policy.dial_targets, [&](const auto& allowed) {
    return allowed.endpoint.host == endpoint.host && allowed.endpoint.port == endpoint.port && allowed.peer == peer;
  });
  if (target == host.policy.dial_targets.end()) return BridgeFailure(Denied());
  PeerCredential credential = peer;
  if (!code.empty()) {
    const auto parsed = PairingCode::Parse(code);
    if (!parsed || parsed->Host() != peer)
      return BridgeFailure({NetworkErrorCode::Authentication, 0, "The pairing code does not match the approved peer."});
    credential = *parsed;
  }
  return host.Issue(DialIntent{std::move(endpoint), std::move(credential)});
}

Task<Bytes> RegisterListener(HostSession& host, ControlReader& request) {
  if (!request.Done()) co_return BridgeFailure(BridgeProtocolError());
  if (!host.policy.listen_address) co_return BridgeFailure(Denied());
  if (host.registrations.size() == listener_limit || host.next_registration == 0) co_return BridgeFailure(Busy());
  auto opened = co_await ListenTcpAsync({*host.policy.listen_address, 0});
  if (!opened.Succeeded()) co_return BridgeFailure(opened.Error());
  const auto id = host.next_registration++;
  ControlWriter reply(BridgePacket::Response);
  reply.Write(id);
  reply.Write(opened.Value().LocalEndpoint());
  host.registrations.emplace(id,
      std::make_shared<Registration>(Registration{std::move(opened).Value(), {}}));
  co_return std::move(reply).Take();
}

Task<Bytes> Publish(HostSession& host, ControlReader& request) {
  const auto id = request.U32();
  auto name = request.String();
  auto type = request.String();
  auto txt = request.ReadTxt();
  if (!request.Done()) co_return BridgeFailure(BridgeProtocolError());
  if (std::ranges::find(host.policy.publish_types, type) == host.policy.publish_types.end())
    co_return BridgeFailure(Denied());
  auto registration = host.Find(id);
  if (!registration) co_return BridgeFailure(Closed());
  if (registration->publication) co_return BridgeFailure(Busy());
  // Advertise the actual bound address and port. A page cannot publish an unrelated endpoint.
  auto published = co_await PublishServiceAsync(
      {std::move(name), std::move(type), registration->listener.LocalEndpoint(), std::move(txt)});
  if (!published.Succeeded()) co_return BridgeFailure(published.Error());
  registration->publication.emplace(std::move(published).Value());
  co_return MakeBridgePacket(BridgePacket::Response);
}

Task<Bytes> HandleRequest(HostSession& host, std::span<const std::byte> packet) {
  if (packet.front() != static_cast<std::byte>(BridgePacket::Request)) co_return Bytes{};
  ControlReader request(packet.subspan(1));
  const auto operation = static_cast<BridgeOperation>(request.U8());
  switch (operation) {
    case BridgeOperation::Browse: co_return co_await Browse(host, request);
    case BridgeOperation::Resolve: co_return co_await Resolve(host, request);
    case BridgeOperation::Dial: co_return AuthorizeDial(host, request);
    case BridgeOperation::Listen: co_return co_await RegisterListener(host, request);
    case BridgeOperation::Publish: co_return co_await Publish(host, request);
    case BridgeOperation::Withdraw:
    case BridgeOperation::Accept:
    case BridgeOperation::CloseListener: {
      const auto id = request.U32();
      if (!request.Done()) co_return BridgeFailure(BridgeProtocolError());
      auto registration = host.Find(id);
      if (!registration) co_return BridgeFailure(Closed());
      if (operation == BridgeOperation::Accept) co_return host.Issue(std::move(registration));
      if (operation == BridgeOperation::Withdraw) registration->publication.reset();
      else {
        registration->Close();
        host.registrations.erase(id);
      }
      co_return MakeBridgePacket(BridgePacket::Response);
    }
  }
  co_return BridgeFailure(BridgeProtocolError());
}

Task<void> WatchControlChannel(std::shared_ptr<HostSession> host) {
  // A platform discovery or publication task can suspend the request handler. Keep observing the control socket.
  while (!host->closed && host->control->Poll()) co_await Delay(10ms);
  host->Stop();
}

Task<void> RunControlChannel(std::shared_ptr<HostSession> host) {
  struct StopOnDisconnect {
    HostSession& host;
    TaskHandle watch;
    ~StopOnDisconnect() {
      watch.Cancel();
      host.Stop();
    }
  } stop{*host, host->tasks.Launch(WatchControlChannel(host))};
  auto ready = co_await SendBridgePacket(*host->control, MakeBridgePacket(BridgePacket::ControlReady),
                                         BridgeClock::now() + 10s);
  if (!ready.Succeeded()) co_return;
  while (!host->closed) {
    auto packet = co_await ReadBridgePacket(*host->control, BridgeClock::time_point::max());
    if (!packet.Succeeded()) co_return;
    auto reply = co_await HandleRequest(*host, packet.Value());
    if (reply.empty() || host->closed) co_return;
    auto sent = co_await SendBridgePacket(*host->control, std::move(reply), BridgeClock::now() + 10s);
    if (!sent.Succeeded()) co_return;
  }
}

Task<NetworkResult<PairedConnection>> ConnectPeer(const WebBridgePolicy& policy, DataIntent intent) {
  using Result = NetworkResult<PairedConnection>;
  if (auto* dial = std::get_if<DialIntent>(&intent))
    co_return co_await ConnectPairedAsync(std::move(dial->endpoint), policy.identity, std::move(dial->credential));
  const auto registration = std::get<std::shared_ptr<Registration>>(std::move(intent));
  if (registration->closed) co_return Result::Failure(Closed());
  if (registration->accepting) co_return Result::Failure(Busy());
  registration->accepting = true;
  struct AcceptGuard {
    Registration& registration;
    ~AcceptGuard() { registration.accepting = false; }
  } accept{*registration};
  auto accepted = co_await registration->listener.AcceptAsync();
  if (!accepted.Succeeded()) co_return Result::Failure(accepted.Error());
  co_return co_await AcceptPairedAsync(std::move(accepted).Value(), policy.identity, policy.incoming);
}

Task<void> ConnectPeerTask(std::shared_ptr<HostSession> host, DataIntent intent,
                           std::shared_ptr<std::optional<NetworkResult<PairedConnection>>> result) {
  try {
    result->emplace(co_await ConnectPeer(host->policy, std::move(intent)));
  } catch (...) {
    result->emplace(NetworkResult<PairedConnection>::Failure(
        {NetworkErrorCode::System, 0, "Could not complete the WSS peer connection."}));
  }
}

Task<void> SendDataFailure(HostBridgeTransport& wire, const NetworkError& error) {
  auto sent = co_await SendBridgePacket(wire, BridgeFailure(error), BridgeClock::now() + 2s);
  if (sent.Succeeded()) (void)co_await wire.Finish();
}

Task<void> RunDataChannel(std::shared_ptr<HostSession> host, std::shared_ptr<HostBridgeTransport> wire,
                          DataIntent intent) {
  std::shared_ptr<Registration> registration;
  if (const auto* accept = std::get_if<std::shared_ptr<Registration>>(&intent)) registration = *accept;
  auto paired = std::make_shared<std::optional<NetworkResult<PairedConnection>>>();
  struct CancelPairing {
    TaskHandle task;
    ~CancelPairing() { task.Cancel(); }
  } pairing{host->tasks.Launch(ConnectPeerTask(host, std::move(intent), paired))};
  // Observe the data socket while a platform connection or the desktop's pairing approval is pending.
  while (!paired->has_value() && !host->closed && (!registration || !registration->closed)) {
    if (!wire->Poll() || wire->TakePacket()) co_return;
    co_await Delay(4ms);
  }
  if (host->closed || !wire->Poll() || wire->TakePacket()) co_return;
  if (registration && registration->closed) {
    pairing.task.Cancel();
    co_await SendDataFailure(*wire, Closed());
    co_return;
  }
  if (!paired->value().Succeeded()) {
    co_await SendDataFailure(*wire, paired->value().Error());
    co_return;
  }
  auto peer = std::make_shared<PairedConnection>(std::move(paired->value()).Value());
  (void)co_await RelayBridgeConnection(wire, std::move(peer), host->tasks);
}

Task<void> HandleSocket(std::shared_ptr<HostSession> host, std::uint64_t id) {
  struct RemoveJob {
    HostSession& host;
    std::uint64_t id;
    ~RemoveJob() { host.jobs.erase(id); }
  } remove{*host, id};
  const auto deadline = BridgeClock::now() + 10s;
  auto wire = co_await AcceptBridgeWebSocket(host->jobs.at(id).socket, host->owner->certificate,
                                             host->owner->origin, deadline);
  if (!wire || host->closed) co_return;
  auto received = co_await ReadBridgePacket(*wire, deadline);
  if (!received.Succeeded() || host->closed) co_return;
  const auto& packet = received.Value();
  const std::string_view grant(reinterpret_cast<const char*>(packet.data() + 1), packet.size() - 1);
  if (!ValidBridgeGrant(grant)) co_return;
  if (packet.front() == static_cast<std::byte>(BridgePacket::ControlAuthenticate)) {
    if (host->control || !CheckBridgeGrant(host->owner->grant, grant)) co_return;
    host->owner->grant.clear();
    host->control = std::move(wire);
    co_await RunControlChannel(host);
  } else if (packet.front() == static_cast<std::byte>(BridgePacket::Authenticate) && host->control &&
             host->control->Poll()) {
    host->ExpireTickets();
    const auto ticket = host->tickets.find(grant);
    if (ticket == host->tickets.end()) co_return;
    auto intent = std::move(ticket->second.intent);
    host->tickets.erase(ticket);
    co_await RunDataChannel(host, wire, std::move(intent));
  }
}

bool ValidPolicy(const WebBridgePolicy& policy) {
  return policy.browse_interface != 0 && policy.browse_types.size() <= bridge_service_limit &&
         (!policy.listen_address || TcpConnectionAccess::IsConcreteAddress(*policy.listen_address)) &&
         std::ranges::all_of(policy.dial_targets, [](const auto& target) {
           return target.endpoint.port != 0 && TcpConnectionAccess::IsConcreteAddress(target.endpoint.host);
         });
}

} // namespace

Task<NetworkResult<void>> ServeBridgeControl(std::shared_ptr<WebBridgeListenerState> listener,
                                            WebBridgePolicy policy, TaskScope tasks) {
  using Result = NetworkResult<void>;
  if (!listener || listener->closed) co_return Result::Failure(Closed());
  if (listener->active_peer || listener->stop_control) co_return Result::Failure(Busy());
  if (!ValidPolicy(policy))
    co_return Result::Failure({NetworkErrorCode::InvalidEndpoint, 0, "Invalid WSS bridge address or discovery scope."});
  auto host = std::make_shared<HostSession>(HostSession{listener, std::move(policy), std::move(tasks)});
  listener->stop_control = [weak = std::weak_ptr<HostSession>(host)] {
    if (auto active = weak.lock()) active->Stop();
  };
  struct ServeGuard {
    WebBridgeListenerState& listener;
    ~ServeGuard() {
      listener.Close();
      listener.stop_control = {};
    }
  } close{*listener};
  while (!host->closed) {
    auto accepted = co_await listener->listener.AcceptAsync();
    if (host->closed || listener->closed) break;
    if (!accepted.Succeeded()) co_return Result::Failure(accepted.Error());
    // Bound simultaneous WSS handshakes, data waits, and established sessions.
    if (host->jobs.size() >= connection_limit) continue;
    const auto id = host->next_job++;
    auto& job = host->jobs.emplace(id, HostSession::Job{TcpConnectionAccess::TakeSocket(accepted.Value()), {}})
                    .first->second;
    job.task = host->tasks.Launch(HandleSocket(host, id));
  }
  co_return Result::Success();
}

} // namespace huxerui::localnetwork::detail
#endif
