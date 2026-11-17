#import <NetworkExtension/NetworkExtension.h>

#include "../../../src/wifi_backend.h"

#include <functional>

namespace huxerui::localnetwork::detail {
namespace {

using namespace std::chrono_literals;

Task<NetworkResult<void>> ApplyConfiguration(NEHotspotConfiguration* configuration) {
  using Result = NetworkResult<void>;
  return AwaitCallback<Result>([configuration](auto completion) {
    [[NEHotspotConfigurationManager sharedManager] applyConfiguration:configuration completionHandler:^(NSError* error) {
      if (!error || ([error.domain isEqualToString:NEHotspotConfigurationErrorDomain] &&
                     error.code == NEHotspotConfigurationErrorAlreadyAssociated)) {
        completion.Complete(Result::Success());
        return;
      }
      auto code = NetworkErrorCode::WifiJoinFailed;
      if ([error.domain isEqualToString:NEHotspotConfigurationErrorDomain] &&
          error.code == NEHotspotConfigurationErrorUserDenied) code = NetworkErrorCode::PermissionDenied;
      completion.Complete(Result::Failure({code, static_cast<int>(error.code),
                                          "iOS did not accept the Wi-Fi configuration. Check Wi-Fi settings."}));
    }];
    // The system owns the authorization prompt and may finish applying the configuration after task cancellation.
    return std::function<void()>{};
  });
}

Task<std::optional<std::string>> CurrentSsid() {
  return AwaitCallback<std::optional<std::string>>([](auto completion) {
    [NEHotspotNetwork fetchCurrentWithCompletionHandler:^(NEHotspotNetwork* network) {
      const char* ssid = network.SSID.UTF8String;
      if (ssid) completion.Complete(std::string(ssid));
      else completion.Complete(std::nullopt);
    }];
    return std::function<void()>{};
  });
}

} // namespace

Task<NetworkResult<WifiJoinResult>> JoinPlatformWifi(WifiJoinRequest request) {
  using Result = NetworkResult<WifiJoinResult>;
  if (request.security == WifiSecurity::Wpa3Personal) {
    co_return Result::Failure({NetworkErrorCode::Unsupported, 0, "Use iOS Wi-Fi settings to require WPA3-Personal."});
  }
  NSString* ssid = [NSString stringWithUTF8String:request.ssid.c_str()];
  NEHotspotConfiguration* configuration = nil;
  if (request.security == WifiSecurity::Open) {
    configuration = [[NEHotspotConfiguration alloc] initWithSSID:ssid];
  } else {
    NSString* password = [NSString stringWithUTF8String:request.passphrase.c_str()];
    configuration = [[NEHotspotConfiguration alloc] initWithSSID:ssid passphrase:password isWEP:NO];
  }
  configuration.joinOnce = request.mode != WifiJoinMode::Persistent;
  auto applied = co_await ApplyConfiguration(configuration);
  if (!applied.Succeeded()) co_return Result::Failure(std::move(applied).Error());

  // An accepted configuration can precede association. Without Wi-Fi Information access the SSID may stay unavailable.
  const auto deadline = std::chrono::steady_clock::now() + 6s;
  do {
    auto current = co_await CurrentSsid();
    if (current && *current == request.ssid) co_return Result::Success({WifiJoinStatus::Associated, {}});
    co_await Delay(500ms);
  } while (std::chrono::steady_clock::now() < deadline);
  co_return Result::Success({WifiJoinStatus::ConfigurationAccepted, {}});
}

} // namespace huxerui::localnetwork::detail
