#pragma once

#include <huxerui/local_network_discovery.h>

namespace huxerui::localnetwork::detail {

/// Owns the platform registration behind a public ServicePublication.
class PublicationState {
public:
  virtual ~PublicationState() = default;
  /// Requests withdrawal. A pending platform completion may retain the registration state.
  virtual void Close() noexcept = 0;
};

Task<NetworkResult<std::vector<DiscoveredService>>> BrowsePlatformServices(
    std::string type, std::chrono::milliseconds observation);
Task<NetworkResult<ResolvedService>> ResolvePlatformService(DiscoveredService service);
Task<NetworkResult<std::shared_ptr<PublicationState>>> PublishPlatformService(ServiceAnnouncement announcement);

#ifdef __ANDROID__
void InstallPlatformDiscovery(ApplicationContext& context);
#endif

} // namespace huxerui::localnetwork::detail
