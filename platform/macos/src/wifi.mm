#import <CoreLocation/CoreLocation.h>
#import <CoreWLAN/CoreWLAN.h>

#include "../../../src/wifi_backend.h"

namespace huxerui::localnetwork::detail {
namespace {

bool LocationAllowed() {
  CLLocationManager* location = [[CLLocationManager alloc] init];
  const auto status = location.authorizationStatus;
  return status == kCLAuthorizationStatusAuthorizedAlways;
}

std::string Ssid(NSData* data) {
  if (!data.length) return {};
  return {static_cast<const char*>(data.bytes), data.length};
}

CWSecurity Security(WifiSecurity security) {
  switch (security) {
    case WifiSecurity::Open: return kCWSecurityNone;
    case WifiSecurity::Wpa2Personal: return kCWSecurityWPA2Personal;
    case WifiSecurity::Wpa3Personal: return kCWSecurityWPA3Personal;
    case WifiSecurity::Other: return kCWSecurityUnknown;
  }
  return kCWSecurityUnknown;
}

WifiSecurity Security(CWNetwork* network) {
  if ([network supportsSecurity:kCWSecurityNone]) return WifiSecurity::Open;
  if ([network supportsSecurity:kCWSecurityWPA2Personal]) return WifiSecurity::Wpa2Personal;
  if ([network supportsSecurity:kCWSecurityWPA3Personal]) return WifiSecurity::Wpa3Personal;
  return WifiSecurity::Other;
}

NetworkResult<WifiScanResult> Scan() {
  using Result = NetworkResult<WifiScanResult>;
  @autoreleasepool {
    CWInterface* adapter = [CWWiFiClient sharedWiFiClient].interface;
    if (!adapter) return Result::Failure({NetworkErrorCode::Unsupported, 0, "No Wi-Fi adapter is available."});
    NSError* error = nil;
    NSSet<CWNetwork*>* networks = [adapter scanForNetworksWithSSID:nil includeHidden:NO error:&error];
    if (!networks) {
      return Result::Failure({NetworkErrorCode::WifiScanFailed, static_cast<int>(error.code), "CoreWLAN could not scan for Wi-Fi."});
    }
    WifiScanResult result{.refreshed = true};
    for (CWNetwork* entry in networks) result.networks.push_back({Ssid(entry.ssidData), Security(entry)});
    return Result::Success(std::move(result));
  }
}

NetworkResult<WifiJoinResult> Join(WifiJoinRequest request) {
  using Result = NetworkResult<WifiJoinResult>;
  @autoreleasepool {
    CWInterface* adapter = [CWWiFiClient sharedWiFiClient].interface;
    if (!adapter) return Result::Failure({NetworkErrorCode::Unsupported, 0, "No Wi-Fi adapter is available."});
    NSData* ssid = [NSData dataWithBytes:request.ssid.data() length:request.ssid.size()];
    NSError* error = nil;
    NSSet<CWNetwork*>* candidates = [adapter scanForNetworksWithSSID:ssid includeHidden:NO error:&error];
    CWNetwork* selected = nil;
    for (CWNetwork* entry in candidates) {
      if ([entry.ssidData isEqualToData:ssid] && [entry supportsSecurity:Security(request.security)] &&
          (!selected || entry.rssiValue > selected.rssiValue)) selected = entry;
    }
    if (!selected) {
      return Result::Failure({NetworkErrorCode::WifiJoinFailed, static_cast<int>(error.code),
                              "CoreWLAN did not find the requested hotspot."});
    }
    NSString* password = request.security == WifiSecurity::Open ? nil :
        [NSString stringWithUTF8String:request.passphrase.c_str()];
    if (![adapter associateToNetwork:selected password:password error:&error]) {
      return Result::Failure({NetworkErrorCode::WifiJoinFailed, static_cast<int>(error.code),
                              "CoreWLAN could not associate with the hotspot. Check system Wi-Fi settings."});
    }
    const auto status = [adapter.ssidData isEqualToData:ssid] ? WifiJoinStatus::Associated
                                                            : WifiJoinStatus::ConfigurationAccepted;
    return Result::Success({status, {}});
  }
}

} // namespace

Task<NetworkResult<WifiScanResult>> ScanPlatformWifi() {
  if (!LocationAllowed()) {
    co_return NetworkResult<WifiScanResult>::Failure(
        {NetworkErrorCode::PermissionDenied, 0, "Allow Location access for this app to scan for Wi-Fi."});
  }
  co_return co_await RunWorker(Scan);
}

Task<NetworkResult<WifiJoinResult>> JoinPlatformWifi(WifiJoinRequest request) {
  using Result = NetworkResult<WifiJoinResult>;
  if (request.mode != WifiJoinMode::PlatformDefault) {
    co_return Result::Failure({NetworkErrorCode::Unsupported, 0, "CoreWLAN manages the configuration lifetime."});
  }
  if (!LocationAllowed()) {
    co_return Result::Failure({NetworkErrorCode::PermissionDenied, 0, "Allow Location access to identify the Wi-Fi hotspot."});
  }
  co_return co_await RunWorker(Join, std::move(request));
}

} // namespace huxerui::localnetwork::detail
