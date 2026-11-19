#pragma once

#include <huxerui/local_network_discovery.h>

#include <span>
#include <string_view>

namespace huxerui::localnetwork::detail {

/// Owns the platform registration behind a public ServicePublication.
class PublicationState {
public:
  virtual ~PublicationState() = default;
  /// Requests withdrawal. A pending platform completion may retain the registration state.
  virtual void Close() noexcept = 0;
};

Task<NetworkResult<std::vector<DiscoveredService>>> BrowsePlatformServices(
    std::string type, ServiceBrowseOptions options);
Task<NetworkResult<ResolvedService>> ResolvePlatformService(DiscoveredService service);
Task<NetworkResult<std::shared_ptr<PublicationState>>> PublishPlatformService(ServiceAnnouncement announcement);

/// Inserts one bounded text attribute. The first value wins if names differ only by ASCII case.
bool InsertServiceTxt(ServiceTxt& txt, std::string_view key, std::string_view value);
/// Reads one DNS-SD character-string split at its first '='.
void InsertServiceTxtItem(ServiceTxt& txt, std::string_view item);
/// Converts between Bonjour length-prefixed character-strings and normalized attributes.
ServiceTxt DecodeServiceTxt(std::span<const unsigned char> bytes);
std::vector<unsigned char> EncodeServiceTxt(const ServiceTxt& txt);

#ifdef __ANDROID__
void InstallPlatformDiscovery(ApplicationContext& context);
bool IsPlatformServicePickerSupported() noexcept;
Task<NetworkResult<std::optional<ResolvedService>>> PickPlatformService(
    std::string type, std::optional<std::uint64_t> android_network_handle);
#endif

} // namespace huxerui::localnetwork::detail
