#ifdef __APPLE__
#include <TargetConditionals.h>
#endif

#include <huxerui/huxerui.h>
#include <huxerui/local_network.h>

#include "file_transfer.h"
#include "identity_store.h"
#include "pairing_qr.h"
#include "wifi_panel.h"
#include "wifi_platform.h"

#include <charconv>
#include <chrono>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using namespace huxerui;
using namespace huxerui::localnetwork;
using namespace local_network_preview;
using namespace std::chrono_literals;

constexpr char service_type[] = "_huxer-lan._tcp";
#ifdef __ANDROID__
constexpr char service_name[] = "LocalNetwork Android";
constexpr bool has_qr_camera = true;
#elif defined(__APPLE__) && TARGET_OS_IOS
constexpr char service_name[] = "LocalNetwork iOS";
constexpr bool has_qr_camera = true;
#elif defined(__APPLE__)
constexpr char service_name[] = "LocalNetwork macOS";
constexpr bool has_qr_camera = false;
#elif defined(__linux__)
constexpr char service_name[] = "LocalNetwork Linux";
constexpr bool has_qr_camera = false;
#else
constexpr char service_name[] = "LocalNetwork Windows";
constexpr bool has_qr_camera = false;
#endif
#ifdef HUXERUI_LOCALNETWORK_PREVIEW_QR
constexpr bool has_pairing_qr = true;
#else
constexpr bool has_pairing_qr = false;
#endif

struct PreviewState {
  bool busy = false;
  std::string status;
  std::string invitation;
  Bitmap invitation_qr;
  std::string publication_status;
  std::vector<DiscoveredService> discovered;
  std::optional<PeerId> pending_peer;
  std::optional<bool> pairing_answer;
  std::optional<Source> source;
  std::string source_name;
  std::optional<File> received;
};

std::string EndpointHost(std::string host) {
  // Some platform keyboards insert localized punctuation even for an address field.
  for (const auto& [punctuation, ascii] : {
           std::pair<std::string_view, char>{"\xE3\x80\x82", '.'}, {"\xEF\xBC\x8E", '.'}, {"\xEF\xBC\x9A", ':'},
       }) {
    for (auto index = host.find(punctuation); index != std::string::npos; index = host.find(punctuation, index + 1)) {
      host.replace(index, punctuation.size(), 1, ascii);
    }
  }
  return host;
}

std::string FormatEndpoint(const Endpoint& endpoint) {
  auto host = endpoint.host.find(':') == std::string::npos ? endpoint.host : "[" + endpoint.host + "]";
  return host + ":" + std::to_string(endpoint.port);
}

std::string FormatError(const NetworkError& error) {
  if (error.diagnostic_code == 0) return error.message;
  return error.message + " (" + std::to_string(error.diagnostic_code) + ")";
}

void FinishOperation(const State<PreviewState>& state, std::string status) {
  state.Update([&](PreviewState& value) {
    value.busy = false;
    value.status = std::move(status);
    value.invitation.clear();
    value.invitation_qr = {};
    value.publication_status.clear();
    value.pending_peer.reset();
    value.pairing_answer.reset();
  });
}

Task<bool> ConfirmPairing(State<PreviewState> state, PeerId peer, std::chrono::steady_clock::time_point expires) {
  state.Update([&](PreviewState& value) {
    value.pending_peer = peer;
    value.pairing_answer.reset();
    value.status = "Approve the requesting device.";
  });
  while (!state->pairing_answer.has_value() && std::chrono::steady_clock::now() < expires) {
    co_await Delay(25ms);
  }
  const bool approved = state->pairing_answer.value_or(false);
  state.Update([](PreviewState& value) {
    value.pending_peer.reset();
    value.pairing_answer.reset();
  });
  co_return approved;
}

Task<NetworkResult<Connection>> ListenForPeer(
    Endpoint endpoint, DeviceIdentity identity, std::optional<PeerId> remembered, State<PreviewState> state) {
  using Result = NetworkResult<Connection>;
  PairingPolicy policy;
  if (remembered) policy.trusted_peers.push_back(*remembered);
  policy.approve = [state](PeerId peer, std::chrono::steady_clock::time_point expires) {
    return ConfirmPairing(state, peer, expires);
  };
  ListenOptions options{.endpoint = std::move(endpoint),
                        .pairing = PairedListenOptions{std::move(identity), std::move(policy)}};
  auto opened = co_await ListenAsync(std::move(options));
  if (!opened.Succeeded()) co_return Result::Failure(std::move(opened).Error());
  auto listener = std::move(opened).Value();
  auto offer = listener.CreateInvite();
  if (!offer.Succeeded()) co_return Result::Failure(std::move(offer).Error());
  auto code = offer.Value().Code();
  auto qr = MakeInvitationQr(listener.LocalEndpoint(), code);
  state.Update([&](PreviewState& value) {
    value.status = "Listening on " + FormatEndpoint(listener.LocalEndpoint());
    value.invitation = std::move(code);
    value.invitation_qr = std::move(qr);
  });
  if (IsDiscoverySupported()) {
    // Manual and QR invitations use the bound endpoint even when the system rejects publication.
    auto published = co_await listener.AdvertiseAsync(service_name, service_type);
    state.Update([&](PreviewState& value) {
      value.publication_status = published.Succeeded() ? "Visible in the device list."
                                                      : FormatError(published.Error());
    });
  }
  co_return co_await listener.AcceptAsync();
}

Task<NetworkResult<Connection>> DialPeer(
    Target target, DeviceIdentity identity, std::optional<PeerId> remembered, std::string code,
    TcpDialOptions options) {
  using Result = NetworkResult<Connection>;
  if (code.empty() && remembered) {
    co_return co_await ConnectAsync(std::move(target), std::move(identity), *remembered, std::move(options));
  }
  const auto parsed = PairingCode::Parse(code);
  if (!parsed) co_return Result::Failure({NetworkErrorCode::PairingRejected, 0, "Enter a valid pairing code."});
  co_return co_await ConnectAsync(std::move(target), std::move(identity), *parsed, std::move(options));
}

struct TemporaryImage {
  File path;
  ~TemporaryImage() { (void)path.Delete(); }
};

std::string UniqueSuffix() { return std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()); }

[[huxerui::composable]] View LocalNetworkPreview() {
  const auto host = UseState(TextEditingValue::FromText("127.0.0.1"));
  const auto port = UseState(TextEditingValue::FromText("46231"));
  const auto code = UseState(TextEditingValue{});
  const auto state = UseState(PreviewState{});
  const auto wifi = UseState(PreviewWifiRoute{});
  const auto running = UseState(TaskHandle{});
  const auto tasks = UseTaskScope();
  const auto picker = UseService<FilePicker>();
  const auto app = UseApplication();
  const auto clipboard = app.Clipboard();
  const auto directories = app.Directories();
  const File identity_key(directories.data_directory, "localnetwork-device-key");
  const File staged_key(directories.data_directory, "localnetwork-device-key.part");
  const File remembered_peer(directories.data_directory, "localnetwork-remembered-peer");
  const File sample(directories.temporary_directory, "localnetwork-sample.bin");
  const bool supported = IsPairingSupported();
  const bool idle = !state->busy && !wifi->busy;

  const auto start = [=](bool listen, Endpoint endpoint, std::string invitation,
                         std::optional<DiscoveredService> discovered = {}) {
    if (state->busy || wifi->busy || !state->source) return;
    // Snapshot the route once for this dial. Manual and QR entry share the same paired transport.
    TcpDialOptions options{.wifi_lease = wifi->network};
    state.Update([](PreviewState& value) { value.busy = true; value.status = "Loading the device identity..."; });
    running = tasks.Launch([=, endpoint = std::move(endpoint), source = *state->source, options = std::move(options),
                            invitation = std::move(invitation), discovered = std::move(discovered)]() mutable
                               -> Task<void> {
      auto identity = co_await LoadIdentity(identity_key, staged_key);
      if (!identity.Succeeded()) {
        FinishOperation(state, FormatError(identity.Error()));
        co_return;
      }

      auto peer_file = co_await remembered_peer.ReadStringAsync();
      const auto remembered = peer_file.Succeeded() ? PeerId::Parse(peer_file.Value()) : std::nullopt;
      state.Update([&](PreviewState& value) {
        value.status = listen ? "Opening listener..." : discovered ? "Resolving service..." : "Connecting...";
      });
      auto local_identity = std::move(identity).Value();
      auto connect = listen
          ? ListenForPeer(std::move(endpoint), std::move(local_identity), remembered, state)
          : DialPeer(discovered ? Target(std::move(*discovered)) : Target(std::move(endpoint)),
                     std::move(local_identity), remembered, std::move(invitation), std::move(options));
      auto paired = co_await std::move(connect);
      if (!paired.Succeeded()) {
        FinishOperation(state, FormatError(paired.Error()));
        co_return;
      }

      auto connection = std::move(paired).Value();
      const auto security = connection.Security();
      const bool remembered_now = security.peer && co_await remembered_peer.WriteStringAsync(security.peer->ToString());
      const auto path = FormatEndpoint(connection.Path().local) + " to " + FormatEndpoint(connection.Path().remote);
      state.Update([&](PreviewState& value) {
        value.status = "TLS 1.3 connected. Transferring files on " + path;
        value.invitation.clear();
        value.invitation_qr = {};
        value.publication_status.clear();
      });
      const auto suffix = UniqueSuffix();
      const File partial(directories.temporary_directory, "localnetwork-received-" + suffix + ".part");
      const File destination(directories.temporary_directory, "localnetwork-received-" + suffix + ".bin");
      auto exchanged = co_await ExchangeFiles(tasks, std::move(connection), std::move(source), partial, destination);
      if (!exchanged.Succeeded()) {
        FinishOperation(state, exchanged.Error().message);
        co_return;
      }

      const auto previous = state->received;
      state.Update([&](PreviewState& value) {
        value.received = destination;
        value.busy = false;
        value.status = "Transfer verified. Sent " + std::to_string(exchanged.Value().sent) +
                       " bytes, received " + std::to_string(exchanged.Value().received) +
                       " bytes. SHA-256 " + exchanged.Value().received_digest;
        if (!remembered_now) value.status += " The peer could not be remembered.";
      });
      if (previous) (void)co_await previous->DeleteAsync();
    });
  };

  const auto manual = [=](bool listen) {
    const auto& text = port->text;
    std::uint16_t number{};
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), number);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() || (!listen && number == 0)) {
      FinishOperation(state, "Enter a valid TCP port.");
      return;
    }
    start(listen, {EndpointHost(host->text), number}, listen ? std::string{} : code->text);
  };

  const auto connect_scanned = [=](IoResult<ScannedInvitation> scanned) {
    if (!scanned.Succeeded()) {
      FinishOperation(state, scanned.Error().message);
      return;
    }
    auto invitation = std::move(scanned).Value();
    host = TextEditingValue::FromText(invitation.endpoint.host);
    port = TextEditingValue::FromText(std::to_string(invitation.endpoint.port));
    FinishOperation(state, "Connecting to the scanned device...");
    start(false, std::move(invitation.endpoint), std::move(invitation.code));
  };

  View invitation_view;
  if (!state->invitation.empty()) {
    invitation_view = Column {
      Text("Pairing code: " + state->invitation),
      Text(state->publication_status),
      state->invitation_qr.HasValue()
          ? Image(state->invitation_qr).Sampling(ImageSampling::Nearest).With(Frame{.width = 240.0F, .height = 240.0F})
          : View{},
      Button("Copy code").With(Enabled(clipboard != nullptr)).OnClick([=] {
        if (clipboard) (void)clipboard->WriteText(state->invitation);
      }),
      state->invitation_qr.HasValue() ? Button("Save QR image").With(Enabled(picker->CanSaveFiles())).OnClick([=] {
        const File file(directories.temporary_directory, "localnetwork-invitation-" + UniqueSuffix() + ".png");
        tasks.Launch([picker, image = state->invitation_qr, file]() -> Task<void> {
          TemporaryImage cleanup{file};
          if (co_await image.SaveAsync(file, {})) {
            (void)co_await picker->SaveFileAsync(file, {.suggested_name = "LocalNetwork invitation.png"});
          }
        });
      }) : View{},
    }.With(Spacing(8.0F)).Key("invitation");
  }

  View approval_view;
  if (state->pending_peer) {
    approval_view = Column {
      Text(state->pending_peer->ToString()),
      Flow {
        Button("Approve device").OnClick([state] {
          state.Update([](PreviewState& value) { value.pairing_answer = true; });
        }),
        Button("Reject device").OnClick([state] {
          state.Update([](PreviewState& value) { value.pairing_answer = false; });
        }),
      }.With(Spacing(8.0F)),
    }.With(Spacing(8.0F)).Key("approval");
  }

  View save_view;
  if (state->received) {
    save_view = Button("Save received file").With(Enabled(!state->busy && picker->CanSaveFiles())).OnClick([=] {
      if (!state->received) return;
      auto save = picker->SaveFileAsync(*state->received, {.suggested_name = "received.bin"});
      tasks.Launch([save = std::move(save)]() mutable -> Task<void> { (void)co_await std::move(save); });
    }).Key("save");
  }

  const auto leased = wifi->network ? wifi->network->AndroidNetwork() : std::nullopt;
  std::vector<View> device_buttons;
  for (const auto& service : state->discovered) {
    if (wifi->network && (!leased || service.scope != *leased)) continue;
    device_buttons.push_back(Button(service.display_name).With(Enabled(idle && state->source.has_value()))
        .OnClick([start, code, service] { start(false, {}, code->text, service); })
        .Key(service.instance_id + "#" + std::to_string(service.scope)));
  }

  return ScrollView {
    Column {
      Text("LocalNetwork", TextRole::Title),
      WifiPanel(wifi, state->busy),
      Flow {
        Button("Choose file").With(Enabled(supported && idle && picker->CanOpenFiles())).OnClick([=] {
          auto selection = picker->OpenFileAsync();
          running = tasks.Launch([state, selection = std::move(selection)]() mutable -> Task<void> {
            auto selected = co_await std::move(selection);
            if (!selected) co_return;
            state.Update([&](PreviewState& value) {
              value.source_name = selected->Name();
              value.source = Source(std::move(*selected));
            });
          });
        }),
        Button("Create 64 MiB sample").With(Enabled(supported && idle)).OnClick([=] {
          state.Update([](PreviewState& value) { value.busy = true; value.status = "Creating the sample file..."; });
          running = tasks.Launch([state, sample]() -> Task<void> {
            auto created = co_await CreateSample(sample);
            if (created.Succeeded()) {
              state.Update([&](PreviewState& value) {
                value.source = Source(sample);
                value.source_name = "64 MiB sample";
              });
            }
            FinishOperation(state, created.Succeeded() ? "Sample file is ready." : created.Error().message);
          });
        }),
      }.With(Spacing(8.0F)),
      Text(state->source_name),
      Text("Bind address or peer address"),
      TextField(host)
          .InputConfiguration({.type = TextInputType::Url, .autocorrect = false})
          .OnChanged([host](const TextEditingValue& value) { host = value; }),
      Text("Port"),
      TextField(port)
          .InputConfiguration({.type = TextInputType::Number})
          .OnChanged([port](const TextEditingValue& value) { port = value; }),
      Text("Pairing code (leave blank to reconnect)"),
      TextField(code)
          .InputConfiguration({.type = TextInputType::Url, .autocorrect = false})
          .OnChanged([code](const TextEditingValue& value) { code = value; }),
      Flow {
        Button("Listen").With(Enabled(supported && idle && state->source.has_value()))
            .OnClick([manual] { manual(true); }),
        Button("Connect").With(Enabled(supported && idle && state->source.has_value()))
            .OnClick([manual] { manual(false); }),
        Button("Cancel").With(Enabled(state->busy)).OnClick([=] {
          running->Cancel();
          FinishOperation(state, "Canceled.");
        }),
      }.With(Spacing(8.0F)),
      IsDiscoverySupported() || has_pairing_qr ? Flow {
        Button("Find devices").With(Enabled(IsDiscoverySupported() && idle)).OnClick([=] {
          const auto selected = wifi->network;
          const auto handle = selected ? selected->AndroidNetwork() : std::nullopt;
          if (selected && !handle) {
            FinishOperation(state, "The Wi-Fi route was lost. Join the hotspot again.");
            return;
          }
          state.Update([](PreviewState& value) {
            value.busy = true;
            value.discovered.clear();
            value.status = "Searching the local network...";
          });
          running = tasks.Launch([state, handle]() -> Task<void> {
            auto result = co_await BrowseServicesAsync(service_type, 2500ms, handle);
            if (!result.Succeeded()) {
              FinishOperation(state, handle && result.Error().code == NetworkErrorCode::Unsupported
                  ? "Discovery is unavailable on this Wi-Fi route. Use an address or QR invitation."
                  : FormatError(result.Error()));
              co_return;
            }
            auto services = std::move(result).Value();
            const bool empty = services.empty();
            state.Update([&](PreviewState& value) { value.discovered = std::move(services); });
            FinishOperation(state, empty
                ? (handle ? "No devices found on this Wi-Fi route. Use an address or QR invitation."
                          : "No LocalNetwork devices found.")
                : "Select a discovered device.");
          });
        }),
        Button("Scan QR image").With(Enabled(has_pairing_qr && supported && idle && state->source &&
                                             picker->CanOpenFiles()))
            .OnClick([=] {
              auto selection = picker->OpenFileAsync({
                  .name = "QR image", .extensions = {"png", "jpg", "jpeg"},
                  .content_types = {"image/png", "image/jpeg"},
              });
              state.Update([](PreviewState& value) { value.busy = true; value.status = "Choose a QR image."; });
              running = tasks.Launch([state, connect_scanned, selection = std::move(selection)]() mutable -> Task<void> {
                auto chosen = co_await std::move(selection);
                if (chosen) connect_scanned(co_await ReadInvitationQr(std::move(*chosen)));
                else FinishOperation(state, "QR image selection canceled.");
              });
            }),
        has_qr_camera ? Button("Scan with camera").With(Enabled(supported && idle && state->source)).OnClick([=] {
          state.Update([](PreviewState& value) { value.busy = true; value.status = "Photograph the pairing QR code."; });
          running = tasks.Launch([state, connect_scanned, directories]() -> Task<void> {
            const File folder(directories.temporary_directory, "qr");
            if (!folder.IsDirectory() && !co_await folder.CreateDirectoryAsync()) {
              FinishOperation(state, "Could not prepare temporary camera storage.");
              co_return;
            }
            TemporaryImage image{File(folder, "pairing-" + UniqueSuffix() + ".jpg")};
            auto captured = co_await CaptureQrPhoto(image.path);
            if (!captured.Succeeded()) FinishOperation(state, captured.Error().message);
            else if (!captured.Value()) FinishOperation(state, "QR photo canceled.");
            else connect_scanned(co_await ReadInvitationQr(image.path));
          });
        }) : View{},
      }.With(Spacing(8.0F)) : View{},
      Column(std::move(device_buttons)).With(Spacing(8.0F)),
      invitation_view,
      approval_view,
      Text(supported ? state->status : "TLS pairing is unavailable on this platform."),
      save_view,
    }.With(Padding(20.0F), Spacing(8.0F), CrossAlign(CrossAxisAlignment::Stretch)),
  };
}

View App() { return MaterialTheme { LocalNetworkPreview() }; }

} // namespace

const Application application{
    App,
    {
        .window = {
            .title = "LocalNetwork Preview",
            .initial_size = {560.0F, 680.0F},
        },
        .application_hooks = {huxerui::localnetwork::Install, local_network_preview::InstallQrCamera,
                              local_network_preview::InstallWifiControls},
    }
};
