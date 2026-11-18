#include <huxerui/local_network_connection.h>

#include <mutex>
#include <utility>

namespace huxerui::localnetwork {

namespace detail {

struct ListenerState {
  using Transport = std::variant<TcpListener, TlsListener>;

  struct PendingPairing {
    CallbackCompletion<NetworkResult<PairedConnection>> completion;
    TaskHandle task;
  };

  ListenerState(Transport transport, std::optional<PairedListenOptions> pairing = {})
      : transport(std::move(transport)), pairing(std::move(pairing)) {}

  Transport transport;
  std::optional<PairedListenOptions> pairing;
  std::mutex mutex;
  std::vector<ServicePublication> publications;
  std::optional<PendingPairing> pending_pairing;
  bool closed = false;
  bool accepting = false;
};

} // namespace detail

namespace {

NetworkError ClosedListener() { return {NetworkErrorCode::Closed, 0, "The listener is closed."}; }

Task<void> AuthenticatePeer(TcpConnection client, PairedListenOptions pairing,
                            CallbackCompletion<NetworkResult<PairedConnection>> completion) {
  try {
    completion.Complete(co_await AcceptPairedAsync(std::move(client), std::move(pairing.identity),
                                                   std::move(pairing.policy)));
  } catch (...) {
    completion.Fail(std::current_exception());
  }
}

} // namespace

Listener::Listener(std::shared_ptr<detail::ListenerState> state) : state_(std::move(state)) {}
Listener::Listener(Listener&&) noexcept = default;

Listener& Listener::operator=(Listener&& other) noexcept {
  if (this != &other) {
    Close();
    state_ = std::move(other.state_);
  }
  return *this;
}

Listener::~Listener() { Close(); }

const Endpoint& Listener::LocalEndpoint() const noexcept {
  static const Endpoint empty;
  if (!state_) return empty;
  return std::visit([](const auto& transport) -> const Endpoint& { return transport.LocalEndpoint(); },
                    state_->transport);
}

Task<NetworkResult<void>> Listener::AdvertiseAsync(std::string name, std::string type, ServiceTxt txt) {
  return Advertise(state_, {std::move(name), std::move(type), LocalEndpoint(), std::move(txt)});
}

Task<NetworkResult<void>> Listener::Advertise(std::shared_ptr<detail::ListenerState> state,
                                              ServiceAnnouncement service) {
  using Result = NetworkResult<void>;
  if (!state) co_return Result::Failure(ClosedListener());
  {
    std::scoped_lock lock(state->mutex);
    if (state->closed) co_return Result::Failure(ClosedListener());
  }
  if (service.endpoint.host == "0.0.0.0" || service.endpoint.host == "::")
    co_return Result::Failure({NetworkErrorCode::InvalidEndpoint, 0, "DNS-SD requires a concrete bind address."});

  auto published = co_await PublishServiceAsync(std::move(service));
  std::scoped_lock lock(state->mutex);
  // If a platform registration finishes after Close(), its local handle withdraws it on exit.
  if (state->closed) co_return Result::Failure(ClosedListener());
  if (!published.Succeeded()) co_return Result::Failure(std::move(published).Error());
  state->publications.push_back(std::move(published).Value());
  co_return Result::Success();
}

NetworkResult<PairingOffer> Listener::CreateInvite() {
  using Result = NetworkResult<PairingOffer>;
  if (!state_) return Result::Failure(ClosedListener());
  std::scoped_lock lock(state_->mutex);
  if (state_->closed) return Result::Failure(ClosedListener());
  if (!state_->pairing)
    return Result::Failure({NetworkErrorCode::Unsupported, 0, "Invitations require a paired listener."});
  auto offer = PairingOffer::Create(state_->pairing->identity);
  if (offer.Succeeded()) state_->pairing->policy.offer = offer.Value();
  return offer;
}

Task<NetworkResult<Connection>> Listener::AcceptAsync() { return Accept(state_); }

Task<NetworkResult<Connection>> Listener::Accept(std::shared_ptr<detail::ListenerState> state) {
  using Result = NetworkResult<Connection>;
  if (!state) co_return Result::Failure(ClosedListener());
  {
    std::scoped_lock lock(state->mutex);
    if (state->closed) co_return Result::Failure(ClosedListener());
    if (state->accepting)
      co_return Result::Failure({NetworkErrorCode::Busy, 0, "The listener already has a pending accept."});
    state->accepting = true;
  }
  // Hold one accept slot through the handshake or approval, and release it on task cancellation.
  struct AcceptSlot {
    detail::ListenerState& state;
    ~AcceptSlot() {
      std::scoped_lock lock(state.mutex);
      state.pending_pairing.reset();
      state.accepting = false;
    }
  } slot{*state};

  if (auto* listener = std::get_if<TlsListener>(&state->transport)) {
    auto accepted = co_await listener->AcceptAsync();
    std::scoped_lock lock(state->mutex);
    if (state->closed) co_return Result::Failure(ClosedListener());
    if (!accepted.Succeeded()) co_return Result::Failure(std::move(accepted).Error());
    co_return Result::Success(Connection(std::move(accepted).Value()));
  }

  auto accepted = co_await std::get<TcpListener>(state->transport).AcceptAsync();
  std::optional<PairedListenOptions> pairing;
  {
    std::scoped_lock lock(state->mutex);
    if (state->closed) co_return Result::Failure(ClosedListener());
    if (!accepted.Succeeded()) co_return Result::Failure(std::move(accepted).Error());
    if (!state->pairing) co_return Result::Success(Connection(std::move(accepted).Value()));
    pairing = state->pairing;
  }

  // An approval may be suspended in application code. Give Close() a way to settle the accept and cancel
  // the authentication task even while none of the underlying socket operations are running.
  using PairedResult = NetworkResult<PairedConnection>;
  auto paired = co_await AwaitCallback<PairedResult>(
      [state, client = std::move(accepted).Value(), pairing = std::move(*pairing)](
          CallbackCompletion<PairedResult> completion) mutable -> std::function<void()> {
        std::scoped_lock lock(state->mutex);
        if (state->closed) {
          completion.Complete(PairedResult::Failure(ClosedListener()));
          return {};
        }
        auto task = UseApplicationTaskScope().Launch(AuthenticatePeer(std::move(client), std::move(pairing), completion));
        state->pending_pairing.emplace(detail::ListenerState::PendingPairing{completion, task});
        return [task] { task.Cancel(); };
      });
  std::scoped_lock lock(state->mutex);
  if (state->closed) co_return Result::Failure(ClosedListener());
  if (!paired.Succeeded()) co_return Result::Failure(std::move(paired).Error());
  co_return Result::Success(Connection(std::move(paired).Value()));
}

void Listener::Close() noexcept {
  if (!state_) return;
  std::optional<detail::ListenerState::PendingPairing> pending;
  {
    std::scoped_lock lock(state_->mutex);
    if (std::exchange(state_->closed, true)) return;
    std::visit([](auto& transport) { transport.Close(); }, state_->transport);
    state_->publications.clear();
    pending = std::exchange(state_->pending_pairing, {});
  }
  if (pending) {
    pending->task.Cancel();
    pending->completion.Complete(NetworkResult<PairedConnection>::Failure(ClosedListener()));
  }
}

Task<NetworkResult<Listener>> ListenAsync(ListenOptions options) {
  using Result = NetworkResult<Listener>;
  if (options.mode == ListenMode::Tls) {
    // Hand PEM ownership to the direct TLS API before retaining its lazy open task.
    return [](Task<NetworkResult<TlsListener>> open) -> Task<Result> {
      auto listener = co_await std::move(open);
      if (!listener.Succeeded()) co_return Result::Failure(std::move(listener).Error());
      co_return Result::Success(Listener(std::make_shared<detail::ListenerState>(std::move(listener).Value())));
    }(ListenTlsAsync({std::move(options.endpoint), std::move(options.certificate_pem),
                      std::move(options.private_key_pem)}));
  }

  return [](Endpoint endpoint, ListenMode mode, std::optional<PairedListenOptions> pairing) -> Task<Result> {
    if (mode == ListenMode::PairedTls) {
      if (!IsPairingSupported())
        co_return Result::Failure({NetworkErrorCode::Unsupported, 0, "Paired listeners are unavailable on this platform."});
      if (!pairing)
        co_return Result::Failure({NetworkErrorCode::InvalidIdentity, 0, "A paired listener requires a device identity."});
    } else if (mode != ListenMode::Tcp || pairing) {
      co_return Result::Failure({NetworkErrorCode::InvalidEndpoint, 0, "Invalid listener transport options."});
    }
    auto listener = co_await ListenTcpAsync(std::move(endpoint));
    if (!listener.Succeeded()) co_return Result::Failure(std::move(listener).Error());
    co_return Result::Success(Listener(std::make_shared<detail::ListenerState>(std::move(listener).Value(),
                                                                              std::move(pairing))));
  }(std::move(options.endpoint), options.mode, std::move(options.pairing));
}

} // namespace huxerui::localnetwork
