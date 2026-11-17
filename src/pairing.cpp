#include <huxerui/local_network_pairing.h>

#include <algorithm>
#include <atomic>
#include <map>
#include <mutex>
#include <utility>

#ifdef HUXERUI_LOCALNETWORK_TLS
#include "socket_io.h"

#include <cstdio>
#include <stop_token>

#include <mbedtls/ecp.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/sha256.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>

extern "C" {
#include <mbedtls/constant_time.h>
}
#endif

namespace huxerui::localnetwork {
namespace {

constexpr std::string_view code_prefix = "hln1-";

std::string Hex(std::span<const std::uint8_t> bytes) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result;
  result.reserve(bytes.size() * 2);
  for (const auto byte : bytes) {
    result.push_back(digits[byte >> 4]);
    result.push_back(digits[byte & 15]);
  }
  return result;
}

int Digit(char ch) {
  if (ch >= '0' && ch <= '9') return ch - '0';
  if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
  if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
  return -1;
}

bool DecodeHex(std::string_view text, std::span<std::uint8_t> bytes) {
  if (text.size() != bytes.size() * 2) return false;
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    const auto high = Digit(text[i * 2]);
    const auto low = Digit(text[i * 2 + 1]);
    if (high < 0 || low < 0) return false;
    bytes[i] = static_cast<std::uint8_t>((high << 4) | low);
  }
  return true;
}

#ifndef HUXERUI_LOCALNETWORK_TLS
NetworkError Unsupported() {
  return {NetworkErrorCode::Unsupported, 0, "TLS pairing is unavailable on this platform."};
}
#endif

} // namespace

std::string PeerId::ToString() const { return Hex(digest); }

std::optional<PeerId> PeerId::Parse(std::string_view text) {
  PeerId peer;
  if (!DecodeHex(text, peer.digest)) return std::nullopt;
  return peer;
}

std::optional<PairingCode> PairingCode::Parse(std::string_view text) {
  if (!text.starts_with(code_prefix)) return std::nullopt;
  text.remove_prefix(code_prefix.size());
  PairingCode code;
  const auto pin_size = code.host_.digest.size() * 2;
  if (text.size() != pin_size + code.secret_.size() * 2 ||
      !DecodeHex(text.substr(0, pin_size), code.host_.digest) ||
      !DecodeHex(text.substr(pin_size), code.secret_)) return std::nullopt;
  return code;
}

const PeerId& PairingCode::Host() const noexcept { return host_; }

namespace detail {

using Clock = std::chrono::steady_clock;
using Secret = std::array<std::uint8_t, 16>;

struct IdentityState {
  struct PeerSessions {
    bool revoked = false;
    std::vector<std::weak_ptr<TlsSocket>> sockets;
  };

  PeerId id;
  std::mutex peers_mutex;
  std::map<decltype(PeerId::digest), PeerSessions> peers;
#ifdef HUXERUI_LOCALNETWORK_TLS
  mbedtls_pk_context key;
  mbedtls_x509_crt certificate;

  IdentityState() { mbedtls_pk_init(&key); mbedtls_x509_crt_init(&certificate); }
  ~IdentityState() { mbedtls_x509_crt_free(&certificate); mbedtls_pk_free(&key); }
#endif
};

struct InvitationState {
  PeerId host;
  Secret secret{};
#ifdef HUXERUI_LOCALNETWORK_TLS
  std::mutex mutex;
  Clock::time_point expires;
  std::optional<PeerId> approved_peer;
  bool approval_pending = false;
#endif
};

struct PairingAccess {
  static const std::shared_ptr<IdentityState>& Identity(const DeviceIdentity& identity) { return identity.state_; }
  static const std::shared_ptr<InvitationState>& Invitation(const PairingOffer& offer) { return offer.state_; }
  static const Secret& Proof(const PairingCode& code) { return code.secret_; }
  static bool Track(const DeviceIdentity& identity, const PeerId& peer, const std::shared_ptr<TlsSocket>& socket) {
    auto& state = *identity.state_;
    std::scoped_lock lock(state.peers_mutex);
    // Track only live sockets. Revocations remain effective after all associated sessions close.
    for (auto entry = state.peers.begin(); entry != state.peers.end();) {
      auto& sessions = entry->second;
      std::erase_if(sessions.sockets, [](const auto& session) { return session.expired(); });
      if (!sessions.revoked && sessions.sockets.empty()) entry = state.peers.erase(entry);
      else ++entry;
    }
    auto& sessions = state.peers[peer.digest];
    if (sessions.revoked) return false;
    sessions.sockets.push_back(socket);
    return true;
  }
  static PairedConnection Connection(std::shared_ptr<TlsSocket> socket, PeerId peer, ConnectionPath path) {
    return PairedConnection(std::move(socket), peer, std::move(path));
  }
};

#ifdef HUXERUI_LOCALNETWORK_TLS
namespace {

using namespace std::chrono_literals;
constexpr char protocol_name[] = "huxer-lan/1";
const char* protocols[] = {protocol_name, nullptr};
constexpr auto retry_interval = 4ms;
constexpr auto handshake_timeout = 20s;
constexpr std::size_t stream_chunk = 64 * 1024;
constexpr std::uint8_t reconnect = 0;
constexpr std::uint8_t pair = 1;
constexpr std::uint8_t accepted = 1;

// The default Mbed TLS build shares PSA state without platform mutex callbacks. Serialize its entry points.
std::mutex& CryptoMutex() { static std::mutex mutex; return mutex; }

int InitializeCrypto() { static const auto result = psa_crypto_init(); return result; }

int Random(void*, unsigned char* data, std::size_t size) {
  return static_cast<int>(psa_generate_random(data, size));
}

NetworkError CryptoError(NetworkErrorCode code, int error, std::string message) {
  return {code, error, std::move(message)};
}

NetworkError PairingRejected() { return {NetworkErrorCode::PairingRejected, 0, "Pairing was rejected."}; }

int PublicKeyId(const mbedtls_pk_context& key, PeerId& id) {
  std::array<unsigned char, 384> encoded;
  const auto size = mbedtls_pk_write_pubkey_der(&key, encoded.data(), encoded.size());
  if (size < 0) return size;
  return mbedtls_sha256(encoded.data() + encoded.size() - size, size, id.digest.data(), 0);
}

std::array<char, 16> CertificateDate(std::chrono::sys_days date) {
  const std::chrono::year_month_day parts{date};
  std::array<char, 16> stamp{};
  std::snprintf(stamp.data(), stamp.size(), "%04d%02u%02u000000", int(parts.year()), unsigned(parts.month()),
                unsigned(parts.day()));
  return stamp;
}

int MakeCertificate(IdentityState& identity) {
  struct CertificateWriter {
    mbedtls_x509write_cert value;
    CertificateWriter() { mbedtls_x509write_crt_init(&value); }
    ~CertificateWriter() { mbedtls_x509write_crt_free(&value); }
  } writer;
  auto* cert = &writer.value;
  mbedtls_x509write_crt_set_version(cert, MBEDTLS_X509_CRT_VERSION_3);
  mbedtls_x509write_crt_set_md_alg(cert, MBEDTLS_MD_SHA256);
  mbedtls_x509write_crt_set_subject_key(cert, &identity.key);
  mbedtls_x509write_crt_set_issuer_key(cert, &identity.key);
  auto result = mbedtls_x509write_crt_set_subject_name(cert, "CN=HuxerUI LocalNetwork");
  if (result != 0) return result;
  result = mbedtls_x509write_crt_set_issuer_name(cert, "CN=HuxerUI LocalNetwork");
  if (result != 0) return result;
  const auto today = std::chrono::floor<std::chrono::days>(std::chrono::system_clock::now());
  const auto from = CertificateDate(today - std::chrono::days(1));
  const auto to = CertificateDate(today + std::chrono::days(3650));
  result = mbedtls_x509write_crt_set_validity(cert, from.data(), to.data());
  if (result != 0) return result;
  std::array<unsigned char, 16> serial{};
  result = Random(nullptr, serial.data(), serial.size());
  if (result != 0) return result;
  serial.front() = static_cast<unsigned char>((serial.front() & 0x7f) | 0x01);
  result = mbedtls_x509write_crt_set_serial_raw(cert, serial.data(), serial.size());
  if (result != 0) return result;
  result = mbedtls_x509write_crt_set_key_usage(cert, MBEDTLS_X509_KU_DIGITAL_SIGNATURE);
  if (result != 0) return result;
  std::array<unsigned char, 1024> der;
  const auto size = mbedtls_x509write_crt_der(cert, der.data(), der.size(), Random, nullptr);
  if (size < 0) return size;
  return mbedtls_x509_crt_parse_der(&identity.certificate, der.data() + der.size() - size, size);
}

NetworkResult<std::shared_ptr<IdentityState>> PrepareIdentity(std::optional<Bytes> encoded) {
  using Result = NetworkResult<std::shared_ptr<IdentityState>>;
  std::scoped_lock lock(CryptoMutex());
  if (const auto error = InitializeCrypto(); error != 0) {
    return Result::Failure(CryptoError(NetworkErrorCode::InvalidIdentity, error, "Could not initialize TLS crypto."));
  }
  auto identity = std::make_shared<IdentityState>();
  int result;
  if (encoded) {
    result = mbedtls_pk_parse_key(&identity->key, reinterpret_cast<const unsigned char*>(encoded->data()),
                                 encoded->size(), nullptr, 0, Random, nullptr);
    if (!encoded->empty()) mbedtls_platform_zeroize(encoded->data(), encoded->size());
    if (result == 0 && (!mbedtls_pk_can_do(&identity->key, MBEDTLS_PK_ECDSA) ||
                        mbedtls_pk_get_bitlen(&identity->key) != 256)) result = MBEDTLS_ERR_PK_TYPE_MISMATCH;
  } else {
    result = mbedtls_pk_setup(&identity->key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (result == 0) {
      result = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(identity->key), Random, nullptr);
    }
  }
  if (result == 0) result = PublicKeyId(identity->key, identity->id);
  if (result == 0) result = MakeCertificate(*identity);
  if (result != 0) {
    return Result::Failure(CryptoError(NetworkErrorCode::InvalidIdentity, result, "Invalid TLS device identity."));
  }
  return Result::Success(std::move(identity));
}

NetworkResult<Bytes> ExportIdentity(const std::shared_ptr<IdentityState>& identity) {
  std::scoped_lock lock(CryptoMutex());
  std::array<unsigned char, 384> encoded{};
  const auto size = mbedtls_pk_write_key_der(&identity->key, encoded.data(), encoded.size());
  Bytes result;
  if (size > 0) {
    const auto* first = reinterpret_cast<const std::byte*>(encoded.data() + encoded.size() - size);
    result.assign(first, first + size);
  }
  mbedtls_platform_zeroize(encoded.data(), encoded.size());
  if (size <= 0) {
    return NetworkResult<Bytes>::Failure(
        CryptoError(NetworkErrorCode::InvalidIdentity, size, "Could not export the TLS device key."));
  }
  return NetworkResult<Bytes>::Success(std::move(result));
}

bool Retry(int result) { return result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE; }

} // namespace

class TlsSocket final {
public:
  TlsSocket(std::shared_ptr<SocketIo> socket, std::shared_ptr<IdentityState> identity)
      : socket_(std::move(socket)), identity_(std::move(identity)) {
    mbedtls_ssl_init(&tls_);
    mbedtls_ssl_config_init(&config_);
  }

  ~TlsSocket() {
    Close();
    std::scoped_lock lock(CryptoMutex());
    mbedtls_ssl_free(&tls_);
    mbedtls_ssl_config_free(&config_);
  }

  int Configure(bool listener) {
    std::scoped_lock lock(CryptoMutex());
    if (!socket_) return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    auto result = mbedtls_ssl_config_defaults(&config_, listener ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT,
                                              MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (result != 0) return result;
    mbedtls_ssl_conf_min_tls_version(&config_, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_max_tls_version(&config_, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_tls13_key_exchange_modes(&config_, MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL);
    mbedtls_ssl_conf_rng(&config_, Random, nullptr);
    // Request certificates on both ends. Device trust comes from the SPKI pin or approved invitation after TLS.
    mbedtls_ssl_conf_authmode(&config_, MBEDTLS_SSL_VERIFY_OPTIONAL);
#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_CLI_C)
    mbedtls_ssl_conf_session_tickets(&config_, MBEDTLS_SSL_SESSION_TICKETS_DISABLED);
#endif
    result = mbedtls_ssl_conf_alpn_protocols(&config_, protocols);
    if (result != 0) return result;
    result = mbedtls_ssl_conf_own_cert(&config_, &identity_->certificate, &identity_->key);
    if (result != 0) return result;
    result = mbedtls_ssl_setup(&tls_, &config_);
    if (result == 0) mbedtls_ssl_set_bio(&tls_, this, SendEncrypted, ReceiveEncrypted, nullptr);
    return result;
  }

  NetworkResult<PeerId> Peer() {
    std::scoped_lock lock(CryptoMutex());
    const auto* certificate = mbedtls_ssl_get_peer_cert(&tls_);
    const auto* alpn = mbedtls_ssl_get_alpn_protocol(&tls_);
    const auto flags = mbedtls_ssl_get_verify_result(&tls_);
    if (!certificate || !alpn || std::string_view(alpn) != protocol_name ||
        (flags & ~static_cast<std::uint32_t>(MBEDTLS_X509_BADCERT_NOT_TRUSTED)) != 0) {
      return NetworkResult<PeerId>::Failure(CryptoError(
          NetworkErrorCode::Authentication, static_cast<int>(flags), "The TLS peer certificate is invalid."));
    }
    PeerId peer;
    const auto error = PublicKeyId(certificate->pk, peer);
    if (error != 0) {
      return NetworkResult<PeerId>::Failure(
          CryptoError(NetworkErrorCode::Authentication, error, "Could not verify the TLS public key."));
    }
    return NetworkResult<PeerId>::Success(peer);
  }

  int Handshake() { std::scoped_lock lock(CryptoMutex()); return mbedtls_ssl_handshake(&tls_); }
  int Read(std::span<unsigned char> bytes) {
    std::scoped_lock lock(CryptoMutex());
    if (closed_) return MBEDTLS_ERR_NET_CONN_RESET;
    const auto result = mbedtls_ssl_read(&tls_, bytes.data(), bytes.size());
    // TLS may retain decrypted data even after TCP closes. A closed session must not deliver it.
    return closed_ ? MBEDTLS_ERR_NET_CONN_RESET : result;
  }
  int Write(std::span<const unsigned char> bytes) {
    std::scoped_lock lock(CryptoMutex());
    if (closed_) return MBEDTLS_ERR_NET_CONN_RESET;
    return mbedtls_ssl_write(&tls_, bytes.data(), bytes.size());
  }
  int Finish() {
    std::scoped_lock lock(CryptoMutex());
    return closed_ ? MBEDTLS_ERR_NET_CONN_RESET : mbedtls_ssl_close_notify(&tls_);
  }
  void Close() noexcept {
    if (!closed_.exchange(true) && socket_) socket_->Close();
  }

private:
  static int SendEncrypted(void* context, const unsigned char* data, std::size_t size) {
    auto& self = *static_cast<TlsSocket*>(context);
    auto sent = self.socket_->Send(std::as_bytes(std::span(data, size)));
    if (!sent.Succeeded()) return MBEDTLS_ERR_NET_SEND_FAILED;
    return sent.Value() ? static_cast<int>(sent.Value()) : MBEDTLS_ERR_SSL_WANT_WRITE;
  }

  static int ReceiveEncrypted(void* context, unsigned char* data, std::size_t size) {
    auto& self = *static_cast<TlsSocket*>(context);
    auto received = self.socket_->Receive(std::as_writable_bytes(std::span(data, size)));
    if (!received.Succeeded()) return MBEDTLS_ERR_NET_RECV_FAILED;
    return received.Value() ? static_cast<int>(*received.Value()) : MBEDTLS_ERR_SSL_WANT_READ;
  }

  std::shared_ptr<SocketIo> socket_;
  std::shared_ptr<IdentityState> identity_;
  std::atomic_bool closed_ = false;
  mbedtls_ssl_config config_;
  mbedtls_ssl_context tls_;
};

namespace {

template <class Operation>
Task<NetworkResult<int>> RunControl(Operation operation, Clock::time_point deadline, NetworkErrorCode failure) {
  for (;;) {
    if (Clock::now() >= deadline) {
      co_return NetworkResult<int>::Failure({NetworkErrorCode::TimedOut, 0, "The TLS session setup timed out."});
    }
    const auto result = operation();
    if (result >= 0) co_return NetworkResult<int>::Success(result);
    if (!Retry(result)) {
      co_return NetworkResult<int>::Failure(CryptoError(failure, result, "The TLS session setup failed."));
    }
    co_await Delay(retry_interval);
  }
}

Task<NetworkResult<void>> ReadControl(TlsSocket& socket, std::span<unsigned char> bytes, Clock::time_point deadline) {
  while (!bytes.empty()) {
    auto read = co_await RunControl([&] { return socket.Read(bytes); }, deadline, NetworkErrorCode::PairingRejected);
    if (!read.Succeeded()) co_return NetworkResult<void>::Failure(std::move(read).Error());
    if (read.Value() == 0) co_return NetworkResult<void>::Failure(PairingRejected());
    bytes = bytes.subspan(static_cast<std::size_t>(read.Value()));
  }
  co_return NetworkResult<void>::Success();
}

Task<NetworkResult<void>> WriteControl(TlsSocket& socket, std::span<const unsigned char> bytes,
                                       Clock::time_point deadline) {
  while (!bytes.empty()) {
    auto written = co_await RunControl([&] { return socket.Write(bytes); }, deadline, NetworkErrorCode::Protocol);
    if (!written.Succeeded()) co_return NetworkResult<void>::Failure(std::move(written).Error());
    if (written.Value() == 0) co_return NetworkResult<void>::Failure(PairingRejected());
    bytes = bytes.subspan(static_cast<std::size_t>(written.Value()));
  }
  co_return NetworkResult<void>::Success();
}

Task<NetworkResult<PeerId>> Authenticate(TlsSocket& socket, bool listener, Clock::time_point deadline) {
  const auto error = socket.Configure(listener);
  if (error != 0) {
    co_return NetworkResult<PeerId>::Failure(
        CryptoError(NetworkErrorCode::Authentication, error, "Could not configure the TLS session."));
  }
  auto handshake = co_await RunControl([&] { return socket.Handshake(); }, deadline, NetworkErrorCode::Authentication);
  if (!handshake.Succeeded()) co_return NetworkResult<PeerId>::Failure(std::move(handshake).Error());
  co_return socket.Peer();
}

Task<bool> ApproveInvite(std::shared_ptr<InvitationState> invitation, PeerId peer, std::span<const unsigned char> proof,
                         const PairingApproval& approve) {
  {
    std::scoped_lock lock(invitation->mutex);
    if (Clock::now() >= invitation->expires ||
        mbedtls_ct_memcmp(invitation->secret.data(), proof.data(), invitation->secret.size()) != 0) co_return false;
    if (invitation->approved_peer) co_return invitation->approved_peer == peer;
    if (invitation->approval_pending || !approve) co_return false;
    invitation->approval_pending = true;
  }
  // Release the reservation if the approval task is canceled. A redeemed offer can only replay to the same key.
  struct Release {
    InvitationState& offer;
    ~Release() { std::scoped_lock lock(offer.mutex); offer.approval_pending = false; }
  } release{*invitation};
  if (!co_await approve(peer, invitation->expires)) co_return false;
  std::scoped_lock lock(invitation->mutex);
  if (Clock::now() >= invitation->expires) co_return false;
  invitation->approved_peer = peer;
  co_return true;
}

Task<IoResult<Bytes>> ReadTls(std::shared_ptr<TlsSocket> socket, std::stop_token stop, std::size_t maximum) {
  std::stop_callback cancel(stop, [socket] { socket->Close(); });
  Bytes bytes((std::min)(maximum, stream_chunk));
  for (;;) {
    const auto count = socket->Read({reinterpret_cast<unsigned char*>(bytes.data()), bytes.size()});
    if (count > 0 || count == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
      bytes.resize(count > 0 ? static_cast<std::size_t>(count) : 0);
      co_return IoResult<Bytes>::Success(std::move(bytes));
    }
    if (!Retry(count)) {
      socket->Close();
      co_return IoResult<Bytes>::Failure({IoErrorCode::Io, "The TLS input closed without a complete stream."});
    }
    co_await Delay(retry_interval);
  }
}

Task<IoResult<void>> WriteTls(std::shared_ptr<TlsSocket> socket, std::stop_token stop, Bytes bytes) {
  std::stop_callback cancel(stop, [socket] { socket->Close(); });
  auto remaining = std::span(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size());
  std::size_t written = 0;
  while (!remaining.empty()) {
    // Mbed TLS requires the same pointer and length when retrying a pending write.
    const auto count = socket->Write(remaining);
    if (count > 0) {
      remaining = remaining.subspan(static_cast<std::size_t>(count));
      written += static_cast<std::size_t>(count);
      if (written >= stream_chunk && !remaining.empty()) {
        written = 0;
        co_await Delay(1ms);
      }
    } else if (Retry(count)) {
      co_await Delay(retry_interval);
    } else {
      socket->Close();
      co_return IoResult<void>::Failure({IoErrorCode::Io, "Could not write to the TLS stream."});
    }
  }
  co_return IoResult<void>::Success();
}

Task<IoResult<void>> FinishTls(std::shared_ptr<TlsSocket> socket, std::stop_token stop) {
  std::stop_callback cancel(stop, [socket] { socket->Close(); });
  for (;;) {
    const auto result = socket->Finish();
    if (result == 0) co_return IoResult<void>::Success();
    if (!Retry(result)) {
      socket->Close();
      co_return IoResult<void>::Failure({IoErrorCode::Io, "Could not close TLS output."});
    }
    co_await Delay(retry_interval);
  }
}

} // namespace
#else
class TlsSocket final {
public:
  void Close() noexcept {}
};
#endif
} // namespace detail

DeviceIdentity::DeviceIdentity(std::shared_ptr<detail::IdentityState> state) : state_(std::move(state)) {}
const PeerId& DeviceIdentity::Id() const noexcept { return state_->id; }

void DeviceIdentity::RevokePeer(const PeerId& peer) const {
  std::vector<std::weak_ptr<detail::TlsSocket>> sockets;
  {
    std::scoped_lock lock(state_->peers_mutex);
    auto& sessions = state_->peers[peer.digest];
    sessions.revoked = true;
    sockets.swap(sessions.sockets);
  }
  // Close outside the registry lock. Socket shutdown also releases any retained network lease.
  for (const auto& session : sockets) {
    if (auto socket = session.lock()) socket->Close();
  }
}

bool DeviceIdentity::IsPeerRevoked(const PeerId& peer) const {
  std::scoped_lock lock(state_->peers_mutex);
  const auto found = state_->peers.find(peer.digest);
  return found != state_->peers.end() && found->second.revoked;
}

Task<NetworkResult<DeviceIdentity>> DeviceIdentity::GenerateAsync() {
#ifdef HUXERUI_LOCALNETWORK_TLS
  auto identity = co_await RunWorker(detail::PrepareIdentity, std::optional<Bytes>{});
  if (!identity.Succeeded()) co_return NetworkResult<DeviceIdentity>::Failure(std::move(identity).Error());
  co_return NetworkResult<DeviceIdentity>::Success(DeviceIdentity(std::move(identity).Value()));
#else
  co_return NetworkResult<DeviceIdentity>::Failure(Unsupported());
#endif
}

Task<NetworkResult<DeviceIdentity>> DeviceIdentity::ImportAsync(Bytes private_key) {
#ifdef HUXERUI_LOCALNETWORK_TLS
  auto identity = co_await RunWorker(detail::PrepareIdentity, std::optional<Bytes>(std::move(private_key)));
  if (!identity.Succeeded()) co_return NetworkResult<DeviceIdentity>::Failure(std::move(identity).Error());
  co_return NetworkResult<DeviceIdentity>::Success(DeviceIdentity(std::move(identity).Value()));
#else
  co_return NetworkResult<DeviceIdentity>::Failure(Unsupported());
#endif
}

Task<NetworkResult<Bytes>> DeviceIdentity::ExportPrivateKeyAsync() const {
#ifdef HUXERUI_LOCALNETWORK_TLS
  return RunWorker(detail::ExportIdentity, state_);
#else
  co_return NetworkResult<Bytes>::Failure(Unsupported());
#endif
}

PairingOffer::PairingOffer(std::shared_ptr<detail::InvitationState> state) : state_(std::move(state)) {}

NetworkResult<PairingOffer> PairingOffer::Create(const DeviceIdentity& identity) {
#ifdef HUXERUI_LOCALNETWORK_TLS
  std::scoped_lock lock(detail::CryptoMutex());
  auto offer = std::make_shared<detail::InvitationState>();
  const auto result = detail::Random(nullptr, offer->secret.data(), offer->secret.size());
  if (result != 0) {
    return NetworkResult<PairingOffer>::Failure(
        detail::CryptoError(NetworkErrorCode::System, result, "Could not create a pairing invitation."));
  }
  offer->host = identity.Id();
  offer->expires = detail::Clock::now() + std::chrono::minutes(5);
  return NetworkResult<PairingOffer>::Success(PairingOffer(std::move(offer)));
#else
  return NetworkResult<PairingOffer>::Failure(Unsupported());
#endif
}

std::string PairingOffer::Code() const {
  return std::string(code_prefix) + state_->host.ToString() + Hex(state_->secret);
}

#ifdef HUXERUI_LOCALNETWORK_TLS
PairedConnection::PairedConnection(std::shared_ptr<detail::TlsSocket> socket, PeerId peer, ConnectionPath path)
    : socket_(std::move(socket)), peer_(peer), path_(std::move(path)),
      input_(AsyncInputStream::FromReader([socket = socket_](std::stop_token stop, std::size_t maximum) {
        return detail::ReadTls(socket, stop, maximum);
      })),
      output_(AsyncOutputStream::FromWriter(
          [socket = socket_](std::stop_token stop, Bytes bytes) {
            return detail::WriteTls(socket, stop, std::move(bytes));
          },
          [socket = socket_](std::stop_token stop) { return detail::FinishTls(socket, stop); })) {}
#endif

PairedConnection::PairedConnection(PairedConnection&&) noexcept = default;
PairedConnection& PairedConnection::operator=(PairedConnection&& other) noexcept {
  if (this != &other) {
    Close();
    socket_ = std::move(other.socket_);
    peer_ = other.peer_;
    path_ = std::move(other.path_);
    input_ = std::move(other.input_);
    output_ = std::move(other.output_);
  }
  return *this;
}
PairedConnection::~PairedConnection() { Close(); }
AsyncInputStream& PairedConnection::Input() noexcept { return input_; }
AsyncOutputStream& PairedConnection::Output() noexcept { return output_; }
const PeerId& PairedConnection::Peer() const noexcept { return peer_; }
const ConnectionPath& PairedConnection::Path() const noexcept { return path_; }
void PairedConnection::Close() noexcept { if (socket_) socket_->Close(); }

bool IsPairingSupported() noexcept {
#ifdef HUXERUI_LOCALNETWORK_TLS
  return true;
#else
  return false;
#endif
}

Task<NetworkResult<PairedConnection>> ConnectPairedAsync(Endpoint endpoint, DeviceIdentity identity,
                                                         PeerCredential credential, TcpDialOptions options) {
  using Result = NetworkResult<PairedConnection>;
#ifdef HUXERUI_LOCALNETWORK_TLS
  const auto* offer = std::get_if<PairingCode>(&credential);
  const auto& expected = offer ? offer->Host() : std::get<PeerId>(credential);
  if (identity.IsPeerRevoked(expected)) co_return Result::Failure(detail::PairingRejected());
  auto dialed = co_await DialTcpAsync(std::move(endpoint), options);
  if (!dialed.Succeeded()) co_return Result::Failure(std::move(dialed).Error());
  auto connection = std::move(dialed).Value();
  auto path = connection.Path();
  auto socket = std::make_shared<detail::TlsSocket>(detail::TcpConnectionAccess::TakeSocket(connection),
                                                    detail::PairingAccess::Identity(identity));
  const auto deadline = detail::Clock::now() + detail::handshake_timeout;
  auto peer = co_await detail::Authenticate(*socket, false, deadline);
  if (!peer.Succeeded()) co_return Result::Failure(std::move(peer).Error());
  if (peer.Value() != expected) {
    co_return Result::Failure({NetworkErrorCode::Authentication, 0, "The peer public key does not match."});
  }
  if (!detail::PairingAccess::Track(identity, peer.Value(), socket)) {
    co_return Result::Failure(detail::PairingRejected());
  }
  std::array<unsigned char, 1 + detail::Secret{}.size()> request{};
  request.front() = offer ? detail::pair : detail::reconnect;
  if (offer) std::ranges::copy(detail::PairingAccess::Proof(*offer), request.begin() + 1);
  auto sent = co_await detail::WriteControl(*socket, request, deadline);
  mbedtls_platform_zeroize(request.data(), request.size());
  if (!sent.Succeeded()) co_return Result::Failure(std::move(sent).Error());
  unsigned char response = 0;
  auto received = co_await detail::ReadControl(*socket, std::span(&response, 1),
                                                deadline + std::chrono::minutes(5));
  if (!received.Succeeded()) co_return Result::Failure(std::move(received).Error());
  if (response != detail::accepted || identity.IsPeerRevoked(peer.Value())) {
    co_return Result::Failure(detail::PairingRejected());
  }
  co_return Result::Success(detail::PairingAccess::Connection(std::move(socket), peer.Value(), std::move(path)));
#else
  co_return Result::Failure(Unsupported());
#endif
}

Task<NetworkResult<PairedConnection>> AcceptPairedAsync(TcpConnection connection, DeviceIdentity identity,
                                                        PairingPolicy policy) {
  using Result = NetworkResult<PairedConnection>;
#ifdef HUXERUI_LOCALNETWORK_TLS
  auto path = connection.Path();
  auto socket = std::make_shared<detail::TlsSocket>(detail::TcpConnectionAccess::TakeSocket(connection),
                                                    detail::PairingAccess::Identity(identity));
  const auto deadline = detail::Clock::now() + detail::handshake_timeout;
  auto peer = co_await detail::Authenticate(*socket, true, deadline);
  if (!peer.Succeeded()) co_return Result::Failure(std::move(peer).Error());
  if (!detail::PairingAccess::Track(identity, peer.Value(), socket)) {
    co_return Result::Failure(detail::PairingRejected());
  }
  std::array<unsigned char, 1 + detail::Secret{}.size()> request{};
  auto received = co_await detail::ReadControl(*socket, request, deadline);
  if (!received.Succeeded()) co_return Result::Failure(std::move(received).Error());
  bool allowed = false;
  if (request.front() == detail::reconnect) {
    allowed = std::ranges::find(policy.trusted_peers, peer.Value()) != policy.trusted_peers.end();
  } else if (request.front() == detail::pair && policy.offer) {
    const auto offer = detail::PairingAccess::Invitation(*policy.offer);
    if (offer->host == identity.Id()) {
      allowed = co_await detail::ApproveInvite(offer, peer.Value(), std::span(request).subspan(1), policy.approve);
    }
  }
  mbedtls_platform_zeroize(request.data(), request.size());
  if (identity.IsPeerRevoked(peer.Value())) co_return Result::Failure(detail::PairingRejected());
  const unsigned char response = allowed ? detail::accepted : 0;
  auto sent = co_await detail::WriteControl(*socket, std::span(&response, 1),
                                             detail::Clock::now() + detail::handshake_timeout);
  if (!sent.Succeeded()) co_return Result::Failure(std::move(sent).Error());
  if (!allowed || identity.IsPeerRevoked(peer.Value())) co_return Result::Failure(detail::PairingRejected());
  co_return Result::Success(detail::PairingAccess::Connection(std::move(socket), peer.Value(), std::move(path)));
#else
  co_return Result::Failure(Unsupported());
#endif
}

} // namespace huxerui::localnetwork
