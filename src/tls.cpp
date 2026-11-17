#ifdef HUXERUI_LOCALNETWORK_TLS
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif
#endif

#include "tls_backend.h"

#include <algorithm>
#include <utility>

#ifdef HUXERUI_LOCALNETWORK_TLS
#include <huxerui/local_network_wifi.h>
#endif

namespace huxerui::localnetwork {
namespace {

#ifdef HUXERUI_LOCALNETWORK_TLS
bool Alphanumeric(char value) {
  return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9');
}

bool ValidDnsName(std::string_view name) {
  if (name.empty() || name.size() > 253) return false;
  while (!name.empty()) {
    const auto dot = name.find('.');
    const auto label = name.substr(0, dot);
    if (label.empty() || label.size() > 63 || !Alphanumeric(label.front()) || !Alphanumeric(label.back()) ||
        !std::ranges::all_of(label, [](char ch) { return Alphanumeric(ch) || ch == '-'; })) return false;
    if (dot == std::string_view::npos) return true;
    name.remove_prefix(dot + 1);
  }
  return false;
}

std::optional<detail::TlsServerName> ParseServerName(std::string host) {
  if (host.empty() || host.find('\0') != std::string::npos) return std::nullopt;
  detail::TlsServerName name;
  const auto scope = host.find('%');
  if (scope != std::string::npos) {
    if (host.find(':') == std::string::npos || scope + 1 == host.size()) return std::nullopt;
    host.resize(scope);
  }
  if (inet_pton(AF_INET6, host.c_str(), name.address.data()) == 1) {
    name.address_size = 16;
  } else if (scope != std::string::npos) {
    return std::nullopt;
  } else if (inet_pton(AF_INET, host.c_str(), name.address.data()) == 1) {
    name.address_size = 4;
  } else {
    if (host.ends_with('.')) host.pop_back();
    // A name consisting of digits and dots must parse as an IPv4 address.
    if (!ValidDnsName(host) || std::ranges::all_of(host, [](char ch) { return (ch >= '0' && ch <= '9') || ch == '.'; }))
      return std::nullopt;
  }
  name.host = std::move(host);
  return name;
}
#endif

} // namespace

#ifdef HUXERUI_LOCALNETWORK_TLS
TlsConnection::TlsConnection(std::shared_ptr<detail::TlsSocket> socket, ConnectionPath path)
    : socket_(std::move(socket)), path_(std::move(path)),
      input_(detail::MakeTlsInput(socket_)), output_(detail::MakeTlsOutput(socket_)) {}
#endif

TlsConnection::TlsConnection(TlsConnection&&) noexcept = default;

TlsConnection& TlsConnection::operator=(TlsConnection&& other) noexcept {
  if (this != &other) {
    Close();
    socket_ = std::move(other.socket_);
    path_ = std::move(other.path_);
    input_ = std::move(other.input_);
    output_ = std::move(other.output_);
  }
  return *this;
}

TlsConnection::~TlsConnection() { Close(); }
AsyncInputStream& TlsConnection::Input() noexcept { return input_; }
AsyncOutputStream& TlsConnection::Output() noexcept { return output_; }
const ConnectionPath& TlsConnection::Path() const noexcept { return path_; }
void TlsConnection::Close() noexcept { detail::CloseTlsSocket(socket_); }

bool IsTlsClientSupported() noexcept {
#ifdef HUXERUI_LOCALNETWORK_TLS
  return true;
#else
  return false;
#endif
}

Task<NetworkResult<TlsConnection>> DialTlsAsync(Endpoint endpoint, TlsDialOptions options) {
  using Result = NetworkResult<TlsConnection>;
#ifdef HUXERUI_LOCALNETWORK_TLS
  auto server = ParseServerName(options.server_name.empty() ? endpoint.host : std::move(options.server_name));
  if (!server) co_return Result::Failure({NetworkErrorCode::InvalidEndpoint, 0, "Invalid TLS server name."});
  const auto lease = options.tcp.wifi_network;
  auto dialed = co_await DialTcpAsync(std::move(endpoint), std::move(options.tcp));
  if (!dialed.Succeeded()) co_return Result::Failure(dialed.Error());
  auto path = dialed.Value().Path();
  auto tls = co_await detail::ConnectSystemTls(std::move(dialed).Value(), std::move(*server));
  if (lease && !lease->AndroidNetwork())
    co_return Result::Failure({NetworkErrorCode::NetworkLost, 0, "The selected Wi-Fi network was lost."});
  if (!tls.Succeeded()) co_return Result::Failure(tls.Error());
  co_return Result::Success(TlsConnection(std::move(tls).Value(), std::move(path)));
#else
  co_return Result::Failure({NetworkErrorCode::Unsupported, 0, "Direct TLS is unavailable on this platform."});
#endif
}

} // namespace huxerui::localnetwork
