#include <windows.h>
#include <wlanapi.h>

#include "../../../src/wifi_backend.h"

#include <atomic>
#include <mutex>

namespace huxerui::localnetwork::detail {
namespace {

std::mutex wlan_operations;

NetworkError Failure(NetworkErrorCode code, DWORD status, std::string message) {
  if (status == ERROR_ACCESS_DENIED || status == ERROR_PRIVILEGE_NOT_HELD) code = NetworkErrorCode::PermissionDenied;
  else if (status == ERROR_SERVICE_NOT_ACTIVE || status == ERROR_NOT_SUPPORTED) code = NetworkErrorCode::Unsupported;
  else if (status == WAIT_TIMEOUT) code = NetworkErrorCode::TimedOut;
  return {code, static_cast<int>(status), std::move(message)};
}

struct Notification {
  GUID interface_id{};
  std::string ssid;
  std::wstring profile;
  WLAN_CONNECTION_MODE mode = wlan_connection_mode_temporary_profile;
  HANDLE ready = nullptr;
  std::atomic<DWORD> result = ERROR_GEN_FAILURE;

  static void WINAPI Receive(PWLAN_NOTIFICATION_DATA note, void* context) {
    auto& self = *static_cast<Notification*>(context);
    if (note->NotificationSource != WLAN_NOTIFICATION_SOURCE_ACM ||
        !InlineIsEqualGUID(note->InterfaceGuid, self.interface_id)) return;
    auto code = note->NotificationCode;
    if (self.profile.empty()) {
      if (code != wlan_notification_acm_scan_complete && code != wlan_notification_acm_scan_fail) return;
      self.result = code == wlan_notification_acm_scan_complete ? ERROR_SUCCESS : ERROR_GEN_FAILURE;
    } else {
      // An attempt can fail before WLAN AutoConfig exhausts other access points in the same network.
      if (code != wlan_notification_acm_connection_complete) return;
      if (!note->pData || note->dwDataSize < FIELD_OFFSET(WLAN_CONNECTION_NOTIFICATION_DATA, strProfileXml)) return;
      const auto& response = *static_cast<const WLAN_CONNECTION_NOTIFICATION_DATA*>(note->pData);
      const auto& ssid = response.dot11Ssid;
      if (response.wlanConnectionMode != self.mode || self.profile != response.strProfileName ||
          ssid.uSSIDLength > sizeof(ssid.ucSSID)) return;
      if (!self.ssid.empty() &&
          self.ssid != std::string_view(reinterpret_cast<const char*>(ssid.ucSSID), ssid.uSSIDLength)) return;
      self.result = response.wlanReasonCode;
    }
    SetEvent(self.ready);
  }
};

class WlanClient final {
public:
  WlanClient() = default;
  WlanClient(const WlanClient&) = delete;
  ~WlanClient() {
    // Deregistration waits for callbacks before their context and event are released.
    if (client_) {
      if (registered_) {
        WlanRegisterNotification(client_, WLAN_NOTIFICATION_SOURCE_NONE, FALSE, nullptr, nullptr, nullptr, nullptr);
      }
      WlanCloseHandle(client_, nullptr);
    }
    if (note.ready) CloseHandle(note.ready);
  }

  DWORD Open() {
    DWORD version = 0;
    const auto status = WlanOpenHandle(2, nullptr, &version, &client_);
    if (status != ERROR_SUCCESS) return status;
    WLAN_INTERFACE_INFO_LIST* list = nullptr;
    const auto listed = WlanEnumInterfaces(client_, nullptr, &list);
    if (listed != ERROR_SUCCESS) return listed;
    const std::unique_ptr<WLAN_INTERFACE_INFO_LIST, decltype(&WlanFreeMemory)> interfaces(list, WlanFreeMemory);
    if (!list->dwNumberOfItems) return ERROR_NOT_SUPPORTED;
    note.interface_id = list->InterfaceInfo[0].InterfaceGuid;
    return ERROR_SUCCESS;
  }

  DWORD Register() {
    note.ready = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!note.ready) return GetLastError();
    const auto status = WlanRegisterNotification(client_, WLAN_NOTIFICATION_SOURCE_ACM, FALSE, Notification::Receive,
                                                  &note, nullptr, nullptr);
    registered_ = status == ERROR_SUCCESS;
    return status;
  }

  HANDLE Handle() const noexcept { return client_; }

  Notification note;

private:
  HANDLE client_ = nullptr;
  bool registered_ = false;
};

NetworkResult<void> Connect(WlanClient& client, WLAN_CONNECTION_PARAMETERS parameters) {
  using Result = NetworkResult<void>;
  client.note.mode = parameters.wlanConnectionMode;
  auto status = client.Register();
  if (status != ERROR_SUCCESS) {
    return Result::Failure(Failure(NetworkErrorCode::WifiJoinFailed, status, "Could not observe Wi-Fi association."));
  }
  status = WlanConnect(client.Handle(), &client.note.interface_id, &parameters, nullptr);
  if (status != ERROR_SUCCESS) {
    return Result::Failure(Failure(NetworkErrorCode::WifiJoinFailed, status, "Windows rejected the Wi-Fi connection request."));
  }
  const auto ready = WaitForSingleObject(client.note.ready, 25000);
  if (ready != WAIT_OBJECT_0) {
    return Result::Failure(Failure(NetworkErrorCode::WifiJoinFailed, ready == WAIT_FAILED ? GetLastError() : ready,
                                   "Windows did not confirm Wi-Fi association."));
  }
  if (client.note.result != WLAN_REASON_CODE_SUCCESS) {
    return Result::Failure({NetworkErrorCode::WifiJoinFailed, static_cast<int>(client.note.result.load()),
                            "Windows was unable to associate with the hotspot."});
  }
  return Result::Success();
}

WifiSecurity Security(const WLAN_AVAILABLE_NETWORK& network) {
  if (!network.bSecurityEnabled) return WifiSecurity::Open;
  if (network.dot11DefaultAuthAlgorithm == DOT11_AUTH_ALGO_RSNA_PSK) return WifiSecurity::Wpa2Personal;
  if (network.dot11DefaultAuthAlgorithm == DOT11_AUTH_ALGO_WPA3_SAE) return WifiSecurity::Wpa3Personal;
  return WifiSecurity::Other;
}

NetworkResult<WifiScanResult> Scan() {
  using Result = NetworkResult<WifiScanResult>;
  std::scoped_lock lock(wlan_operations);
  WlanClient client;
  auto status = client.Open();
  if (status == ERROR_SUCCESS) status = client.Register();
  if (status != ERROR_SUCCESS) {
    return Result::Failure(Failure(NetworkErrorCode::WifiScanFailed, status, "Could not open the system Wi-Fi adapter."));
  }
  status = WlanScan(client.Handle(), &client.note.interface_id, nullptr, nullptr, nullptr);
  if (status != ERROR_SUCCESS) {
    return Result::Failure(Failure(NetworkErrorCode::WifiScanFailed, status, "Windows could not scan. Check Wi-Fi and location access."));
  }
  WifiScanResult result;
  result.refreshed = WaitForSingleObject(client.note.ready, 5000) == WAIT_OBJECT_0 && client.note.result == ERROR_SUCCESS;
  WLAN_AVAILABLE_NETWORK_LIST* list = nullptr;
  status = WlanGetAvailableNetworkList(client.Handle(), &client.note.interface_id, 0, nullptr, &list);
  if (status != ERROR_SUCCESS) {
    return Result::Failure(Failure(NetworkErrorCode::WifiScanFailed, status, "Windows could not read the Wi-Fi list."));
  }
  const std::unique_ptr<WLAN_AVAILABLE_NETWORK_LIST, decltype(&WlanFreeMemory)> available(list, WlanFreeMemory);
  for (DWORD i = 0; i < list->dwNumberOfItems; ++i) {
    const auto& entry = list->Network[i];
    const auto& ssid = entry.dot11Ssid;
    if (entry.dot11BssType != dot11_BSS_type_infrastructure || ssid.uSSIDLength > sizeof(ssid.ucSSID)) continue;
    result.networks.push_back({std::string(reinterpret_cast<const char*>(ssid.ucSSID), ssid.uSSIDLength), Security(entry)});
  }
  return Result::Success(std::move(result));
}

std::wstring HexSsid(std::string_view ssid) {
  constexpr wchar_t hex[] = L"0123456789ABCDEF";
  std::wstring value;
  for (unsigned char octet : ssid) {
    value.push_back(hex[octet >> 4]);
    value.push_back(hex[octet & 15]);
  }
  return value;
}

std::wstring Profile(const WifiJoinRequest& request, const std::wstring& name, const std::wstring& ssid) {
  const bool open = request.security == WifiSecurity::Open;
  const wchar_t* authentication = open ? L"open" : request.security == WifiSecurity::Wpa2Personal ? L"WPA2PSK" : L"WPA3SAE";
  const wchar_t* encryption = open ? L"none" : L"AES";
  std::wstring xml = L"<WLANProfile xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v1\"><name>" + name +
      L"</name><SSIDConfig><SSID><hex>" + ssid + L"</hex></SSID></SSIDConfig><connectionType>ESS</connectionType>"
      L"<connectionMode>manual</connectionMode><MSM><security><authEncryption><authentication>" + authentication +
      L"</authentication><encryption>" + encryption + L"</encryption><useOneX>false</useOneX></authEncryption>";
  if (!open) {
    xml += L"<sharedKey><keyType>passPhrase</keyType><protected>false</protected><keyMaterial>";
    // Keep SSID bytes in the XML hex field. Escape the printable ASCII passphrase as XML text.
    for (char ch : request.passphrase) {
      switch (ch) {
        case '&': xml += L"&amp;"; break;
        case '<': xml += L"&lt;"; break;
        case '>': xml += L"&gt;"; break;
        default: xml.push_back(static_cast<wchar_t>(ch)); break;
      }
    }
    xml += L"</keyMaterial></sharedKey>";
  }
  return xml + L"</security></MSM></WLANProfile>";
}

NetworkResult<WifiJoinResult> Join(WifiJoinRequest request) {
  using Result = NetworkResult<WifiJoinResult>;
  std::scoped_lock lock(wlan_operations);
  WlanClient client;
  auto status = client.Open();
  if (status != ERROR_SUCCESS) {
    return Result::Failure(Failure(NetworkErrorCode::WifiJoinFailed, status, "Could not open the system Wi-Fi adapter."));
  }
  const auto ssid = HexSsid(request.ssid);
  client.note.ssid = request.ssid;
  client.note.profile = L"HuxerUI-" + std::to_wstring(static_cast<int>(request.security)) + L"-" + ssid;
  const auto xml = Profile(request, client.note.profile, ssid);
  auto connected = Connect(client, WLAN_CONNECTION_PARAMETERS{
      .wlanConnectionMode = wlan_connection_mode_temporary_profile,
      .strProfile = xml.c_str(),
      .dot11BssType = dot11_BSS_type_infrastructure,
  });
  if (!connected.Succeeded()) return Result::Failure(std::move(connected).Error());
  if (request.mode == WifiJoinMode::Persistent) {
    DWORD reason = 0;
    status = WlanSetProfile(client.Handle(), &client.note.interface_id, WLAN_PROFILE_USER, xml.c_str(), nullptr,
                            TRUE, nullptr, &reason);
    if (status != ERROR_SUCCESS) {
      return Result::Failure(Failure(NetworkErrorCode::WifiJoinFailed, status, "Connected, but Windows could not save the profile."));
    }
  }
  return Result::Success({WifiJoinStatus::Associated, {}});
}

NetworkResult<WifiJoinResult> JoinProfile(std::string profile) {
  using Result = NetworkResult<WifiJoinResult>;
  const auto bytes = static_cast<int>(profile.size());
  const auto length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, profile.data(), bytes, nullptr, 0);
  if (length <= 0 || length >= WLAN_MAX_NAME_LENGTH) {
    return Result::Failure({NetworkErrorCode::InvalidWifiConfiguration, 0, "Invalid Windows WLAN profile name."});
  }
  std::scoped_lock lock(wlan_operations);
  WlanClient client;
  const auto status = client.Open();
  if (status != ERROR_SUCCESS) {
    return Result::Failure(Failure(NetworkErrorCode::WifiJoinFailed, status, "Could not open the system Wi-Fi adapter."));
  }
  client.note.profile.resize(length);
  MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, profile.data(), bytes, client.note.profile.data(), length);
  auto connected = Connect(client, WLAN_CONNECTION_PARAMETERS{
      .wlanConnectionMode = wlan_connection_mode_profile,
      .strProfile = client.note.profile.c_str(),
      .dot11BssType = dot11_BSS_type_infrastructure,
  });
  if (!connected.Succeeded()) return Result::Failure(std::move(connected).Error());
  return Result::Success({WifiJoinStatus::Associated, {}});
}

} // namespace

Task<NetworkResult<WifiScanResult>> ScanPlatformWifi() { return RunWorker(Scan); }
Task<NetworkResult<WifiJoinResult>> JoinPlatformWifi(WifiJoinRequest request) {
  return RunWorker(Join, std::move(request));
}
Task<NetworkResult<WifiJoinResult>> JoinPlatformWifiProfile(std::string profile) {
  return RunWorker(JoinProfile, std::move(profile));
}

} // namespace huxerui::localnetwork::detail
