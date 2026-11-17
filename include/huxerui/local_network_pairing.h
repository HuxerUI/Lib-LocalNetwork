#pragma once

/// @file
/// @brief TLS 1.3 device identities, pairing invitations, and authenticated local connections.
///
/// Include <huxerui/local_network_pairing.h> and link HuxerUI::LocalNetwork. Pairing is built for Windows, macOS,
/// Linux, Android, and iOS. Run the returned tasks in a HuxerUI TaskScope. Use ConnectPairedAsync() on the dialer and
/// AcceptPairedAsync() on a connection from TcpListener::AcceptAsync(). After both sides authenticate, use the
/// returned streams for application data. The application owns private key storage, remembered peer identities,
/// and the approval UI.

#include <array>
#include <functional>
#include <string_view>
#include <variant>
#include <vector>

#include <huxerui/local_network_tcp.h>

namespace huxerui::localnetwork {

namespace detail {
struct PairingAccess;
struct IdentityState;
struct InvitationState;
class TlsSocket;
}

/// @brief A device identifier derived from the SHA-256 digest of its public key's DER SubjectPublicKeyInfo.
struct PeerId {
  /// Full public-key digest. Store the complete value when remembering a device.
  std::array<std::uint8_t, 32> digest{};

  /// Formats the complete identifier as lowercase hexadecimal.
  std::string ToString() const;
  /// Parses exactly 64 hexadecimal digits. Returns an empty optional on malformed input.
  static std::optional<PeerId> Parse(std::string_view text);
  /// Compares the full public-key digests.
  bool operator==(const PeerId&) const = default;
};

/// @brief A copyable TLS device identity. Copies refer to the same private key.
class DeviceIdentity final {
public:
  /// @brief Creates a new P-256 key and self-signed certificate off the application thread.
  /// @return A lazy task yielding a new device identity or a NetworkError.
  static Task<NetworkResult<DeviceIdentity>> GenerateAsync();
  /// @brief Restores an identity with the same public-key identifier.
  /// @param private_key DER key bytes previously returned by ExportPrivateKeyAsync().
  /// @return A lazy task yielding the restored identity or a NetworkError.
  static Task<NetworkResult<DeviceIdentity>> ImportAsync(Bytes private_key);
  /// @brief Exports the DER private key for application-owned storage.
  ///
  /// Store it as secret key material and exclude it from logs.
  /// @return A lazy task yielding the encoded private key or a NetworkError.
  Task<NetworkResult<Bytes>> ExportPrivateKeyAsync() const;
  /// Returns the stable identifier of the public key, independent of the certificate's lifetime.
  const PeerId& Id() const noexcept;

private:
  explicit DeviceIdentity(std::shared_ptr<detail::IdentityState> state);
  std::shared_ptr<detail::IdentityState> state_;
  friend struct detail::PairingAccess;
};

/// @brief A short-lived pairing credential received through a trusted exchange between users or devices.
class PairingCode final {
public:
  /// Parses the complete text from PairingOffer::Code(). The listener checks expiry and redemption during pairing.
  /// Returns an empty optional on malformed input.
  static std::optional<PairingCode> Parse(std::string_view text);
  /// Returns the pinned identity expected from the listener's TLS certificate.
  const PeerId& Host() const noexcept;

private:
  PeerId host_;
  std::array<std::uint8_t, 16> secret_{};
  friend struct detail::PairingAccess;
};

/// @brief A listening application's invitation. Copies share expiry, approval, and redemption state.
///
/// Once approved, the same requesting public key can reuse this invitation until it expires. To reconnect after
/// expiry, the dialer supplies a remembered PeerId and the listener includes that peer in its trusted list.
class PairingOffer final {
public:
  /// Creates an invitation that expires five minutes after this call. Use the same identity in AcceptPairedAsync().
  static NetworkResult<PairingOffer> Create(const DeviceIdentity& identity);
  /// Returns the secret-bearing text to show or copy for the user. Exclude it from logs.
  std::string Code() const;

private:
  explicit PairingOffer(std::shared_ptr<detail::InvitationState> state);
  std::shared_ptr<detail::InvitationState> state_;
  friend struct detail::PairingAccess;
};

/// A remembered peer identity or a freshly received pairing code.
using PeerCredential = std::variant<PeerId, PairingCode>;

/// @brief Application approval for the requesting public key after certificate and invitation checks.
///
/// The arguments are the requesting device's PeerId and the invitation expiry on the steady clock.
/// Return true before that deadline to approve. Any state borrowed by the callback must outlive the accept task.
using PairingApproval = std::function<Task<bool>(PeerId, std::chrono::steady_clock::time_point)>;

/// @brief Authentication policy for a connection accepted by a plain TCP listener.
struct PairingPolicy {
  /// Devices accepted for a reconnect after proving possession of their private key.
  std::vector<PeerId> trusted_peers;
  /// A live invitation to allow first-time pairing during the accept.
  std::optional<PairingOffer> offer;
  /// UI callback for a new approval request. Leave it empty to reject new peers.
  PairingApproval approve;
};

/// @brief An authenticated TLS 1.3 session with independent, concurrent input and output.
///
/// Input() and Output() borrow the session's stream handles. Keep the session in place while operations run.
/// Each direction permits one pending operation. Canceling either stream's pending operation closes the TCP connection.
class PairedConnection final {
public:
  /// Transfers the TLS session and stream handles.
  PairedConnection(PairedConnection&&) noexcept;
  /// Closes the current session and transfers ownership of the supplied session.
  PairedConnection& operator=(PairedConnection&&) noexcept;
  /// Releases the streams and closes the underlying TCP connection.
  ~PairedConnection();

  /// Returns decrypted application bytes. An empty successful read means the peer sent a TLS close notification.
  AsyncInputStream& Input() noexcept;
  /// Returns the stream for application bytes. Await its CloseAsync() to send a TLS close notification while
  /// keeping the input stream available.
  AsyncOutputStream& Output() noexcept;
  /// Returns the authenticated peer identity.
  const PeerId& Peer() const noexcept;
  /// Returns the actual TCP endpoints underlying this session.
  const ConnectionPath& Path() const noexcept;
  /// Closes both directions immediately. Additional calls have no effect.
  void Close() noexcept;

private:
  PairedConnection(std::shared_ptr<detail::TlsSocket> socket, PeerId peer, ConnectionPath path);
  std::shared_ptr<detail::TlsSocket> socket_;
  PeerId peer_;
  ConnectionPath path_;
  AsyncInputStream input_;
  AsyncOutputStream output_;
  friend struct detail::PairingAccess;
};

/// @brief Reports whether paired TLS is implemented on the current platform.
/// @return True when the library was built with the TLS backend. Connectivity and approval are checked when connecting.
bool IsPairingSupported() noexcept;

/// @brief Dials the endpoint and authenticates it with a remembered identity or pairing code.
///
/// Validates the listener's public key against the credential before sending any invitation secret.
/// For a new pairing, the task waits for the listener's decision. Save Peer() after success to reconnect later.
/// @param endpoint Peer address and port obtained separately from the credential.
/// @param identity Local device identity used for TLS client authentication.
/// @param credential Expected peer identity and, for first-time pairing, the invitation secret.
/// @param options TCP deadline and optional Android network handle or Wi-Fi lease. TLS has its own handshake deadline.
/// @return A lazy task yielding an authenticated connection or a NetworkError.
Task<NetworkResult<PairedConnection>> ConnectPairedAsync(
    Endpoint endpoint, DeviceIdentity identity, PeerCredential credential, TcpDialOptions options = {});

/// @brief Upgrades an accepted TCP connection to TLS and authorizes the peer before exposing application bytes.
///
/// Save Peer() after success if the application should allow future reconnects from this device.
/// @param connection A newly accepted connection with both streams still unused.
/// @param identity Local identity used for TLS server authentication.
/// @param policy Remembered peers, optional invitation, and user approval callback.
/// @return A lazy task yielding an authenticated connection or a NetworkError. Failure closes the transport.
Task<NetworkResult<PairedConnection>> AcceptPairedAsync(
    TcpConnection connection, DeviceIdentity identity, PairingPolicy policy);

} // namespace huxerui::localnetwork
