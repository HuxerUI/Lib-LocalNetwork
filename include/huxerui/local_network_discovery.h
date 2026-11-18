#pragma once

/// @file
/// @brief Local DNS-SD browsing, endpoint resolution, and service publication.
///
/// Include <huxerui/local_network_discovery.h> and link HuxerUI::LocalNetwork. DNS-SD uses the Windows DNS Service
/// API, Android NSD, Bonjour on macOS and iOS, or Avahi on Linux when the Avahi client is available at build time.
/// On Android, register Install() as an application hook and run the tasks in the initialized host.
/// Apple hosts declare the Bonjour service types they use and supply a local network usage description.
/// Launch the tasks through a TaskScope from application work such as a UI event.
/// Discovery identifies candidate endpoints. Authenticate the peer separately before exchanging application data.

#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <huxerui/local_network_common.h>
#include <huxerui/task.h>

namespace huxerui::localnetwork {

namespace detail {
class PublicationState;
struct ServiceBrowserState;
}

/// @brief A discovered service in the local DNS-SD domain.
struct DiscoveredService {
  /// Instance label as reported by the system. Use this for display.
  std::string display_name;
  /// TCP service type such as _huxer-lan._tcp.
  std::string type;
  /// Opaque instance identifier used by ResolveServiceAsync(). Keep it with type and scope.
  std::string instance_id;
  /// Platform resolution scope. Windows, macOS, iOS, and Linux use an interface index.
  /// Android uses a system network handle.
  /// Zero means the browse result came without a specific scope.
  std::uint64_t scope = 0;
};

/// @brief Changes in the set of services observed by a service browser.
enum class ServiceChange {
  Added,              ///< A service became visible on its discovery scope.
  DisplayNameChanged, ///< The system reported a different display label for the same service reference.
  Removed,            ///< A service is absent from a later successful observation.
};

/// @brief A change to one service instance on one discovery scope.
struct ServiceEvent {
  /// The change relative to the previous observation.
  ServiceChange change;
  /// The service reference, including its scope. For removal this is the last observed reference.
  DiscoveredService service;
};

/// @brief Options for continuously observing a local DNS-SD service type.
struct ServiceBrowseOptions {
  /// Positive interval per observation, up to ten seconds.
  std::chrono::milliseconds observation = std::chrono::milliseconds(2500);
  /// Optional interface index or Android network handle. Only results verified on this scope are delivered.
  std::optional<std::uint64_t> scope;
};

/// @brief A move-only browser that reports changes across successive DNS-SD observations.
///
/// Each outstanding NextAsync() either returns a queued change or observes another system snapshot. Keep one
/// consumer per browser. Resolve the returned reference to get current addresses and TXT attributes.
class ServiceBrowser final {
public:
  /// Transfers ownership of the browser.
  ServiceBrowser(ServiceBrowser&&) noexcept;
  /// Closes this browser and transfers ownership of the supplied browser.
  ServiceBrowser& operator=(ServiceBrowser&&) noexcept;
  /// Closes the browser.
  ~ServiceBrowser();

  /// @brief Waits for the next visible service change.
  /// @return A lazy task yielding a change, or a NetworkError. A concurrent read returns Busy.
  Task<NetworkResult<ServiceEvent>> NextAsync();

  /// Stops the browser. If a system observation has started, the pending read returns Closed after it completes.
  void Close() noexcept;

private:
  explicit ServiceBrowser(std::shared_ptr<detail::ServiceBrowserState> state);
  std::shared_ptr<detail::ServiceBrowserState> state_;
  friend NetworkResult<ServiceBrowser> BrowseServiceChanges(std::string type, ServiceBrowseOptions options);
};

/// @brief Creates an on-demand browser for a local TCP service type.
/// @param type TCP service type using the same syntax as BrowseServicesAsync().
/// @param options Observation interval and optional verified discovery scope.
/// @return An owning browser, or a NetworkError if the options or platform do not support browsing.
NetworkResult<ServiceBrowser> BrowseServiceChanges(std::string type, ServiceBrowseOptions options = {});

/// @brief Portable DNS-SD TXT attributes exposed as public UTF-8 text.
///
/// Keys contain printable ASCII excluding '=' and are compared without ASCII case. Resolved keys are lowercase.
/// Values are UTF-8 without embedded nulls. Incoming presence-only keys use an empty value. Keep TXT public.
using ServiceTxt = std::map<std::string, std::string, std::less<>>;

/// @brief A resolved service's addresses and Android route constraint, when known.
struct ResolvedService {
  /// Candidate numeric endpoints with the resolved TCP port. Preserve any IPv6 scope included in the host.
  std::vector<Endpoint> endpoints;
  /// Android system network handle, when available. Pass it to TcpDialOptions::android_network_handle when dialing
  /// a resolved endpoint without a Wi-Fi lease.
  std::optional<std::uint64_t> android_network_handle;
  /// Text attributes returned by the system. Invalid or non-text attributes are ignored.
  ServiceTxt txt;
};

/// @brief A service announcement in the local DNS-SD domain.
struct ServiceAnnouncement {
  /// A single nonempty UTF-8 instance label of up to 63 bytes. Dots and embedded NUL bytes are rejected.
  /// The system may append a suffix to distinguish services with the same label.
  std::string name;
  /// TCP service type using the same syntax as BrowseServicesAsync().
  std::string type;
  /// The active listener's numeric LAN address and nonzero port. For a wildcard listener, supply the concrete
  /// address of the interface to advertise and the actual port from TcpListener::LocalEndpoint().
  Endpoint endpoint;
  /// Public metadata. The key, '=', and value must fit in 255 bytes per entry. The entire record is capped at 1024 bytes.
  ServiceTxt txt;
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

/// @brief Browses on a specified LAN interface or Android network.
/// @param type TCP service type using the same syntax as unscoped browsing.
/// @param observation Positive interval up to ten seconds.
/// @param scope Nonzero interface index on desktop or Apple platforms, or a nonzero Android network handle.
/// Use std::nullopt to browse all available interfaces. Android requires API level 33 for a specified scope.
/// @return A lazy task yielding a snapshot on the requested scope, or a NetworkError.
Task<NetworkResult<std::vector<DiscoveredService>>> BrowseServicesAsync(
    std::string type, std::chrono::milliseconds observation, std::optional<std::uint64_t> scope);

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
/// Windows, macOS, iOS, and Linux publish on the interface that owns the supplied address.
/// Android scopes publication to the matching network when the system API supports it.
/// @param announcement Instance label, TCP service type, and the listener's concrete endpoint.
/// @return A lazy task yielding an owning registration. Failure leaves the listener available for direct dialing.
Task<NetworkResult<ServicePublication>> PublishServiceAsync(ServiceAnnouncement announcement);

} // namespace huxerui::localnetwork
