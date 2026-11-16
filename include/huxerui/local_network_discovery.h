#pragma once

/// @file
/// @brief Local DNS-SD browsing, endpoint resolution, and service publication.
///
/// Include <huxerui/local_network_discovery.h> and link HuxerUI::LocalNetwork. DNS-SD uses the Windows DNS Service
/// API, Android NSD, or Avahi on Linux when the Avahi client is available at build time. On Android, register
/// Install() as an application hook and run the tasks in the initialized host.
/// Launch the tasks through a TaskScope from application work such as a UI event.
/// Discovery identifies candidate endpoints. Authenticate the peer separately before exchanging application data.

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <huxerui/local_network_common.h>
#include <huxerui/task.h>

namespace huxerui::localnetwork {

namespace detail {
class PublicationState;
}

/// @brief A discovered service in the local DNS-SD domain.
struct DiscoveredService {
  /// Instance label as reported by the system. Use this for display.
  std::string name;
  /// TCP service type such as _huxer-lan._tcp.
  std::string type;
  /// Opaque instance identifier used by ResolveServiceAsync(). Keep it with type and scope.
  std::string instance;
  /// Platform resolution scope. Windows and Linux use an interface index. Android uses a system network handle.
  /// Zero means the browse result came without a specific scope.
  std::uint64_t scope = 0;
};

/// @brief A resolved service's addresses and Android route constraint, when known.
struct ResolvedService {
  /// Candidate numeric endpoints with the resolved TCP port. Preserve any IPv6 scope included in the host.
  std::vector<Endpoint> endpoints;
  /// Available when Android supplies a network handle. Pass it to TcpDialOptions::android_network for each dial.
  std::optional<std::uint64_t> android_network;
};

/// @brief A service announcement in the local DNS-SD domain.
struct ServiceAnnouncement {
  /// A single nonempty UTF-8 instance label of up to 63 bytes. Dots and embedded NUL bytes are rejected.
  std::string name;
  /// TCP service type using the same syntax as BrowseServicesAsync().
  std::string type;
  /// The active listener's numeric LAN address and nonzero port. For a wildcard listener, supply the concrete
  /// address of the interface to advertise and the actual port from TcpListener::LocalEndpoint().
  Endpoint endpoint;
};

/// @brief A move-only registration of a DNS-SD service.
///
/// Keep this handle alongside the listener while it accepts new connections. Each handle has its own lifetime.
class ServicePublication final {
public:
  /// Transfers ownership of the registration.
  ServicePublication(ServicePublication&&) noexcept;
  /// Withdraws the current registration and transfers the supplied one.
  ServicePublication& operator=(ServicePublication&&) noexcept;
  /// Requests withdrawal of the registration.
  ~ServicePublication();
  /// Requests withdrawal once. The system may complete it asynchronously.
  void Close() noexcept;

private:
  explicit ServicePublication(std::shared_ptr<detail::PublicationState> state);
  std::shared_ptr<detail::PublicationState> state_;
  friend Task<NetworkResult<ServicePublication>> PublishServiceAsync(ServiceAnnouncement announcement);
};

/// @brief Reports whether DNS-SD is implemented on the current platform.
/// @return True when the current build includes a DNS-SD backend. Linux operations also require the Avahi service.
bool IsDiscoverySupported() noexcept;

/// @brief Browses for local services during a bounded observation window.
///
/// Canceling the task skips result delivery and requests that the system stop browsing.
/// @param type TCP service type in the form `_name._tcp`. Use 1 to 15 lowercase ASCII letters, digits, or hyphens
/// for the name, beginning and ending with a letter or digit.
/// @param observation Positive interval up to ten seconds. The default is 2.5 seconds.
/// @return A lazy task yielding the services still visible at the end of the interval, or a NetworkError.
Task<NetworkResult<std::vector<DiscoveredService>>> BrowseServicesAsync(
    std::string type, std::chrono::milliseconds observation = std::chrono::milliseconds(2500));

/// @brief Resolves a discovered service on its original interface or network, when available.
///
/// Resolve shortly before dialing, since addresses and network membership can change after browsing.
/// Canceling the task skips result delivery and requests system cancellation where available.
/// @param service An entry from BrowseServicesAsync(), including its instance identifier and scope.
/// @return A lazy task yielding one or more numeric endpoints, the Android network handle if available,
/// or a NetworkError.
Task<NetworkResult<ResolvedService>> ResolveServiceAsync(DiscoveredService service);

/// @brief Publishes an active TCP listener on the local network.
///
/// Windows and Linux publish on the interface that owns the supplied address. Android scopes publication to the
/// matching network when the system API supports it.
/// @param announcement Instance label, TCP service type, and the listener's concrete endpoint.
/// @return A lazy task yielding an owning registration. Failure leaves the listener available for direct dialing.
Task<NetworkResult<ServicePublication>> PublishServiceAsync(ServiceAnnouncement announcement);

} // namespace huxerui::localnetwork
