# Lib-LocalNetwork Design

Lib-LocalNetwork provides local network selection, DNS-SD, bidirectional byte streams, and device authentication. It supports two connection paths that share address resolution, routing, connection lifecycle, and stream adapters.

- **HuxerUI peers** find each other through discovery, a manually entered address, or a QR invitation. After pairing, they use the same authenticated byte stream for file transfers, AgentKit calls, or an interactive terminal.
- **Existing accessories** use their own TCP, TLS, or HTTP protocol. The application can join an accessory's Wi-Fi network and require that its traffic use that network.

Applications link `HuxerUI::LocalNetwork` and use the `huxerui::localnetwork` namespace. Native platform adapters provide transport, discovery, and Wi-Fi operations. A local native bridge provides the browser path and exposes the identity and route verified at each hop. The application owns its file format, terminal protocol, and tool authorization. The public entry header gathers the available capabilities. Each capability also has its own header. [Build target](../CMakeLists.txt) · [Public entry header](../include/huxerui/local_network.h)

## Platform capabilities

The matrix describes the full design. Available operations depend on the OS version, host permissions, packaging, and active network. Manual address and QR connection are alternatives when service discovery is unavailable. An IP address still requires a reachable route and any applicable local network permission.

| Platform | Listen, connect, and exchange bytes | DNS-SD browse, resolve, and publish | Join a known Wi-Fi network | Permissions, limits, and fallback |
| --- | --- | --- | --- | --- |
| Windows | Winsock with TLS 1.3 for paired sessions. The system TLS backend targets Windows 11. | `DnsServiceBrowse`, `DnsServiceResolve`, and `DnsServiceRegister`. | Use Native Wi-Fi and prefer an existing WLAN profile. Select a temporary or persistent configuration explicitly and wait for the connection notification. | The firewall, network profile, and organizational policy can restrict inbound connections. Scanning and some Wi-Fi queries require location consent. Use system Wi-Fi settings when programmatic association is unavailable. [DNS-SD](https://learn.microsoft.com/en-us/windows/win32/api/windns/nf-windns-dnsservicebrowse) · [WlanConnect](https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlanconnect) · [Wi-Fi and location](https://learn.microsoft.com/en-us/windows/win32/nativewifi/wi-fi-access-location-changes) · [Schannel protocol support](https://learn.microsoft.com/en-us/windows/win32/secauthn/protocols-in-tls-ssl--schannel-ssp-) |
| macOS | Network.framework with TLS. Constrain a listener or connection to an available interface or local address when supported. | Bonjour with `NWBrowser` and `NWListener`. Use `dnssd` when the caller needs an explicit address list. | CoreWLAN associates with the known network. Run the blocking operation off the application thread and verify the resulting association. | Local Network privacy applies from macOS 15. Sandboxed hosts configure the incoming and outgoing network entitlements for their roles. CoreWLAN association can require administrator authorization. System Wi-Fi settings provide a fallback. [Network.framework](https://developer.apple.com/documentation/network) · [CoreWLAN association](https://developer.apple.com/documentation/corewlan/cwinterface/associate%28to%3Apassword%3A%29) · [Local Network privacy](https://developer.apple.com/documentation/technotes/tn3179-understanding-local-network-privacy?changes=_9%2C_9) · [App Sandbox](https://developer.apple.com/documentation/security/app-sandbox) |
| Linux | POSIX sockets and a maintained TLS implementation. Strict route selection depends on the interface constraints the system exposes. | Avahi for browsing, resolving, and registration. | Activate an existing profile through NetworkManager D-Bus or create a temporary configuration when explicitly requested. | Availability depends on the distribution, network manager, polkit, firewall, and packaging sandbox. Use an address or QR invitation without Avahi. Use desktop network settings if NetworkManager is unavailable. [Avahi examples](https://avahi.org/doxygen/html/examples.html) · [NetworkManager D-Bus](https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.html) |
| Android | TCP with platform TLS. Bind each accessory socket to its selected `Network`. A system hotspot host listens on an actual downstream address. | `NsdManager` with API- and SDK-extension-specific discovery and resolution. Preserve the network scope of results. | On API 29+, use `WifiNetworkSpecifier` and the system confirmation flow. The library can also use a verified Wi-Fi route after the user joins in system settings. | The host declares `INTERNET` and the permissions for its Wi-Fi and connectivity APIs. Wi-Fi permissions depend on OS and target SDK, including `NEARBY_WIFI_DEVICES` and legacy location permission. Acquire `MulticastLock` for legacy NSD when required. On Android 17, apps targeting API 37+ need `ACCESS_LOCAL_NETWORK` for general inbound and direct-address access. The system NSD picker can authorize a client to access one selected service. [Wi-Fi request](https://developer.android.com/develop/connectivity/wifi/wifi-bootstrap) · [Wi-Fi permissions](https://developer.android.com/develop/connectivity/wifi/wifi-permissions) · [Local network permission](https://developer.android.com/privacy-and-security/local-network-permission) · [NSD](https://developer.android.com/reference/android/net/nsd/NsdManager) |
| iOS | `NWListener` and `NWConnection` with TLS. Support foreground listening and transfer. Qualify Personal Hotspot hosting by device and OS version. | System Bonjour. The host declares the service types it uses. | Use `NEHotspotConfigurationManager` with the Hotspot Configuration entitlement and system confirmation. Prefer `joinOnce` for temporary accessory networks and verify association after the configuration callback. | Declare `NSLocalNetworkUsageDescription` and `NSBonjourServices`. Bonjour and outbound local TCP require Local Network access. The OS applies different rules to accepting an inbound TCP connection. Use system Wi-Fi settings when configuration cannot complete. [Local Network privacy](https://developer.apple.com/documentation/technotes/tn3179-understanding-local-network-privacy?changes=__3) · [iOS Wi-Fi APIs](https://developer.apple.com/documentation/technotes/tn3111-ios-wifi-api-overview?language=objc) · [App lifecycle](https://developer.apple.com/documentation/uikit/preparing-your-ui-to-run-in-the-background?changes=_3%2C_3) |
| Web | The browser opens a WSS connection to a local native bridge. The bridge can listen on behalf of the browser. | The bridge browses, resolves, and publishes registered services on behalf of the browser. | The user joins Wi-Fi in system settings. A user-operated native companion can also use its platform Wi-Fi APIs. | A standard web page cannot open raw TCP sockets, listen directly, run DNS-SD, or manage Wi-Fi. The bridge requires a browser-trusted certificate, a secure context, and any local network permission enforced by the browser. Use the native client when browser trust or permission cannot be established. [WebSocket standard](https://websockets.spec.whatwg.org/) · [Chrome Local Network Access](https://developer.chrome.com/docs/modern-web-guidance/guides/security/local-network-access?hl=en) |

## Public API sketch

The common server path is `ListenAsync` followed by `AcceptAsync`. The client can pass a discovered service directly to `ConnectAsync`, or use an endpoint from manual entry or an invitation. `ResolveAsync` is available to callers that need to inspect candidate addresses or integrate an existing protocol. The signatures below omit supporting type definitions.

```cpp
namespace huxerui::localnetwork {

struct Connection {
  AsyncInputStream input;
  AsyncOutputStream output;
  SecurityInfo security;
  ConnectionPath path;

  Task<NetResult<void>> ShutdownWriteAsync();
  Task<NetResult<void>> CloseAsync();
};

class Discovery {
public:
  Task<NetResult<DiscoveryEvent>> NextAsync();
};

class Listener {
public:
  Task<NetResult<Publication>> AdvertiseAsync(ServiceInfo service);
  Task<NetResult<Invite>> CreateInviteAsync(InviteOptions options);
  Task<NetResult<Connection>> AcceptAsync();
};

class LocalNetwork {
public:
  Capabilities GetCapabilities() const;

  Task<NetResult<WifiJoinResult>> JoinKnownWifiAsync(WifiJoinRequest request);
  Task<NetResult<NetworkLease>> SelectWifiRouteAsync(WifiSelector selector);

  Task<NetResult<Discovery>> BrowseAsync(ServiceType type, NetworkScope scope);
  Task<NetResult<ResolvedService>> ResolveAsync(ServiceRef service);

  Task<NetResult<Listener>> ListenAsync(ListenOptions options);
  Task<NetResult<Connection>> ConnectAsync(
      Target target, PeerCredential credential, ConnectOptions options);
  Task<NetResult<Connection>> DialAsync(Endpoint endpoint, DialOptions options);
};

} // namespace huxerui::localnetwork
```

- **Connection mode.** `Target` holds a `ServiceRef` or an `Endpoint`. `PeerCredential` holds a trusted `PeerId` or a fresh invitation. `ConnectAsync` establishes an authenticated HuxerUI session. `DialAsync` uses the existing accessory protocol, defaults to TLS with system trust, and requires explicit selection of plain TCP. A listener defaults to paired sessions. An application serving an existing protocol can explicitly select TLS or TCP. Configure the incoming pairing policy when creating the listener.
- **Routing and diagnostics.** Connection and dial options can require a `NetworkLease`. The operation fails if it cannot satisfy that requirement. `ConnectionPath` reports the actual local and remote endpoints, interface and network identifier when available, and whether the connection used a bridge. `GetCapabilities()` distinguishes available operations, operations that require permission or user action, and unsupported operations. Errors identify the failed phase and retain the native cause. Report a timeout as a timeout when the platform cannot determine its cause.
- **Listening and publication.** Bind to the selected LAN interface by default and expose the actual bound endpoints. A listener can accept manual or QR connections even if publication fails. Closing the listener stops new accepts and revokes its publications. Accepted connections have their own lifetimes. Network loss or application shutdown closes affected connections.
- **Discovery.** `Discovery` reports additions, updates, and removals. A service reference retains the instance, type, domain, and interface or network scope. Resolved results include the port, candidate addresses, and TXT data. Preserve the scope of IPv6 link-local addresses and try candidates on the original network. Resolve again after relevant address changes. Preview can use `_huxer-lan._tcp`. Applications can configure their own service types. TXT records carry only public metadata, such as the protocol version. [DNS-SD specification](https://www.rfc-editor.org/info/rfc6763/)

### Stream contract

Adapt platform I/O through HuxerUI's `AsyncInputStream::FromReader` and `AsyncOutputStream::FromWriter`. A connection supports one outstanding read and one outstanding write concurrently. Reads return bounded chunks. A successful empty read indicates orderly end of input. A successful write accepts the complete chunk. The application protocol confirms receipt. Implement incremental I/O, bounded buffering, and backpressure. If an in-flight operation is cancelled after bytes may have moved and the stream position is uncertain, close the connection so the application can handle the interrupted exchange.

`output.CloseAsync()` finalizes local output and releases the output stream. `ShutdownWriteAsync()` explicitly signals end of output to the peer while allowing further reads. Advertise that capability only on backends that have verified their orderly half-close behavior. `Connection::CloseAsync()` closes the full connection and settles pending I/O. A premature disconnection or truncated application payload is an error. File transfer uses its own length and receipt acknowledgement, so the base transport needs no custom end-of-stream frame. [TLS closure alerts](https://www.rfc-editor.org/rfc/rfc8446.html#section-6.1)

The installed HuxerUI SDK 0.4.0 headers lack the public callback-backed stream factories. Implementation requires a matching SDK that exposes both factories. Lib-PluginKit already uses that contract. [HuxerUI stream API](https://github.com/HuxerUI/HuxerUI/blob/main/include/huxerui/stream.h) · [Lib-PluginKit stream adapter](https://github.com/HuxerUI/Lib-PluginKit/blob/main/include/huxerui/pluginkit/detail/streams.h)

## Known Wi-Fi networks and Android routing

`WifiJoinRequest` carries the exact SSID, security mode, credentials or an existing system profile reference, and the requested temporary or persistent mode. Use an existing OS profile for enterprise Wi-Fi. Pass credentials to the OS and omit them from logs and diagnostics. Joining can change the device's current Wi-Fi network. Release temporary configurations that the library owns. For user-managed networks, release only the borrowed route handle.

`WifiJoinResult` distinguishes confirmed association with a usable address, an accepted configuration that still needs verification, and a required visit to system settings. A confirmed association and a strictly bindable `NetworkLease` are separate capabilities. For example, iOS can constrain a connection to a Wi-Fi interface while the ability to confirm the requested SSID depends on the information the OS exposes.

### Android accessory traffic

1. Request the exact accessory network with `WifiNetworkSpecifier`. Take the `Network` from `onAvailable` and wait for the corresponding `LinkProperties` to establish the interface and usable address configuration before issuing a lease. After a user joins through system settings, acquire a lease only after identifying the corresponding Wi-Fi `Network`.
2. Resolve ordinary hostnames with `Network.getAllByName()` or its NDK equivalent. Open sockets through the network's `SocketFactory`, or call `android_setsocknetwork()` before a native `connect()`. TLS uses that bound socket. An accessory HTTP adapter uses the same route for DNS, connection pooling, and subsequent dials, including any redirect it follows.
3. Scope DNS-SD to the selected network where supported and verify the scope of returned results. If the selected network cannot be established for a discovery result, use a numeric endpoint or a QR invitation and still dial on the required lease. `onLost` invalidates the lease, associated endpoints, and active connections. Rejoining creates a new lease. Socket-level binding leaves the process default network available for ordinary internet traffic.
4. Treat hotspot hosting separately. A system hotspot's downstream interface may have no `Network` object. The host uses an observable downstream address for its listener. Verify the actual local endpoint of an accepted connection on the physical device. Apply the same endpoint check to an iOS Personal Hotspot host.

[Android Network API](https://developer.android.com/reference/android/net/Network) · [NDK network binding](https://developer.android.com/ndk/reference/group/networking) · [NSD downstream interface behavior](https://developer.android.com/reference/android/net/nsd/NsdServiceInfo)

## Pairing, device identity, and protocol versioning

An address locates a device. A public key identifies it. Each installation holds a persistent private key and derives its `PeerId` from the certificate's Subject Public Key Info (SPKI). The library handles handshakes, credential validation, pairing state, and revocation. The host supplies the approval UI and integration with the platform's secure storage.

| Phase | Behavior |
| --- | --- |
| Issue an invitation | The host opens a short pairing window on a ready listener. The invitation carries the version, target endpoints, service purpose, host public-key fingerprint, and a high-entropy single-use credential. A QR code can carry the full invitation. For manual address entry, the user obtains a copyable pairing code from the host. Wi-Fi credentials are entered separately through the join flow. |
| Pair | The client verifies the host's fingerprint in a TLS 1.3 handshake. The host requires the client to prove possession of its own persistent private key. An unpaired connection has access only to a time-limited pairing flow. The client submits the invitation after verifying the host. The host validates it, asks the user to approve the requesting device, then stores trust, redeems the invitation, and returns the result. Application bytes become available only after authentication. |
| Recover an interrupted pairing | Store the approval result against the invitation and requesting public key. If the approval reply is lost, only a device proving possession of the same private key can retrieve the result during the validity window. The client commits trust after receiving the authenticated approval. |
| Reconnect or revoke | A peer may move to a new address. Both sides verify the stored public keys when reconnecting. A certificate renewal can retain the same public key. A changed key requires new pairing. Local revocation closes relevant sessions and denies subsequent connections from that peer. |

TLS provides encryption and proof of key possession. The library protocol defines version negotiation, connection purpose, and pairing control messages. Negotiate the major version through ALPN for native sessions. Apply limits to message size, handshake and approval deadlines, and the number of unauthenticated connections. Report incompatible versions explicitly. Run protocol contract tests against native and bridge implementations. File metadata, terminal messages, and AgentKit calls carry their own application protocol versions. [TLS 1.3 specification](https://www.rfc-editor.org/info/rfc9846/)

## Web bridge

The full design includes a user-enabled local native bridge. The browser uses WSS to reach the bridge on the same machine or LAN. The bridge can browse, resolve, and dial within explicitly granted scope, or accept incoming sessions for a registered service. The browser adapter exposes the existing async streams. A control connection manages services and grants. Each session uses a separate data connection. Bound the size of binary messages and use receiver-granted credits so that a slow reader applies backpressure. [WebSocket interface](https://websockets.spec.whatwg.org/#the-websocket-interface)

- **Deployment.** For offline use, the bridge can serve the page over HTTPS and provide WSS on the same origin with a preconfigured trusted certificate and a hostname resolvable on the LAN. An external HTTPS origin can connect when browser policy, trust, and applicable local network permissions permit it. Offer the native client when those requirements cannot be met. [Chrome Local Network Access](https://developer.chrome.com/docs/modern-web-guidance/guides/security/local-network-access?hl=en)
- **Authorization and identity.** Validate the browser `Origin` and have the local user approve the services, devices, and operations available to that page session. WSS authenticates the bridge. The bridge separately verifies the downstream peer, and the API identifies that verification as bridge-mediated. An application that requires browser-to-peer end-to-end encryption can add a WebRTC DataChannel with authenticated signaling. Both endpoints must bind the DTLS fingerprints to their verified invitation or device identities. [WebRTC specification](https://www.w3.org/TR/webrtc/)

## Physical device acceptance

For each combination, record Wi-Fi association, discovery and resolution, direct connection and pairing, and file transfer separately. Run the discovery list, manual `IP:port`, and QR entry paths. Turn off browsing and clear cached discovery for the manual and QR runs. Use a fresh invitation for each. Verify Wi-Fi association and address configuration independently of internet access.

For every successful connection path, transfer two distinct 64 MiB files concurrently over the same session, one in each direction. Preview sends length and SHA-256 before the bytes. The receiver streams the file to temporary storage, verifies the length and checksum, and acknowledges receipt. Both sides wait for receipt acknowledgements before closing the connection. The sender can use `File::OpenReadAsync()` and `CopyToAsync()` to stream the file. Verify slow receivers, rejected pairing, wrong fingerprints, expired invitations, revoked trust, and mid-transfer network loss. Only verified files appear as complete.

### Group 1 · Phone and computer on the same router Wi-Fi

| Check | Procedure and passing result |
| --- | --- |
| Device coverage | Pair Android and iOS with each of Windows, macOS, and Linux. Both devices join the same normal Wi-Fi SSID. Start with the computer listening and repeat with the roles reversed to verify mobile listening on ordinary Wi-Fi. |
| Discovery | Publish from the listening device. The other device discovers and resolves the actual address and port for this run. Stop publication and verify that the service disappears. With publication disabled, complete pairing and transfer through both manual and QR entry. |
| Network and permissions | On guest Wi-Fi or with AP client isolation, confirm that association can succeed while the direct connection reports a timeout or unreachable peer. Exercise Windows inbound firewall behavior, Apple Local Network permissions, and Android target API 37 permission denial and recovery. |

### Group 2 · Phone A hosts a system hotspot and phone B joins

Exercise all four directions. A always listens. B always initiates the connection to A.

| Hotspot host and listener A | Wi-Fi client and dialer B | Additional checks |
| --- | --- | --- |
| Android | Android | Cover at least two Android vendors. Join through system settings and through `WifiNetworkSpecifier`. |
| Android | iOS | Join through system Wi-Fi settings and through `NEHotspotConfiguration`. Record the configuration callback and the actual Wi-Fi association separately. |
| iOS | Android | Keep A on the Personal Hotspot settings screen until B joins. Return A to the foreground and start its listener. Record results with the default settings and with Maximize Compatibility when needed. |
| iOS | iOS | Use different Apple accounts to exercise ordinary Wi-Fi joining. Verify an inbound connection after A returns to the foreground. |

After B joins, disable discovery and dial A's actual hotspot-side listening address. Then exercise discovery, QR entry, pairing, and file transfer independently. Avoid fixed gateway addresses. Record device models, OS versions, hotspot band, and the local endpoint that accepted the session on A. Turn off the hotspot and verify that the session ends. A combination that passes direct transfer but fails DNS-SD can be listed as supporting manual and QR connections. Confirm a supported hotspot combination only after B reaches A's listener. Record any Personal Hotspot carrier or plan requirements. [Apple Personal Hotspot](https://support.apple.com/en-ca/111785) · [Personal Hotspot compatibility](https://support.apple.com/en-us/119837)

### Additional checks for the full design

- **Android accessory routing.** Use an accessory AP without internet access while cellular or another Wi-Fi network remains the default route. Verify that accessory DNS, TCP, and HTTP use the bound network and that ordinary internet traffic still uses the default. Shut down the AP and verify that requests on the old lease fail. Rejoin and verify that traffic uses only the new lease.
- **Web bridge.** Verify browser permissions, local certificates, approved origins, bridge-mediated discovery and connection, refusal of unapproved page sessions, and offline bidirectional transfer. Publish support by browser and deployment configuration after those checks pass.

## AgentKit and terminal integration

For an AgentKit request to run `git status --short` on a computer, Lib-LocalNetwork authenticates the devices and establishes the encrypted stream. The application on the computer resolves the request to a registered tool. Its approval UI shows the target computer, working directory, executable, and arguments. Bind approval to the specific invocation. After approval, the computer executes the tool and returns output, exit status, and execution state. If the connection drops after execution may have started, look up the result by call ID. Report an unknown result when the host cannot confirm it. [AgentKit tool interface](https://github.com/HuxerUI/Lib-AgentKit/blob/main/include/huxerui/agentkit/tool.h) · [AgentKit execution and approval](https://github.com/HuxerUI/Lib-AgentKit/blob/main/src/tool_execution.cpp)

For an interactive terminal, the application starts a PTY or ConPTY on the computer after user approval. The remote terminal view connects through a `TerminalBackend` supplied to `OpenTransportAsync()`. Terminal resize messages, cancellation, exit status, session limits, and audit records belong to the application protocol. Device pairing establishes communication identity. The executing host authorizes each command or terminal session separately. [Lib-Terminal transport interface](https://github.com/HuxerUI/Lib-Terminal/blob/main/include/huxerui/terminal.h)

## Delivery sequence

| Stage | Acceptance scope |
| --- | --- |
| Validate platform constraints | Confirm that the SDK exposes both stream factories. Test direct inbound TCP on all four hotspot directions and per-socket Android route binding on physical devices. Use the outcome to qualify hotspot support. |
| Initial native release | Deliver foreground direct connections, bidirectional streams, DNS-SD, pairing and revocation, manual and QR entry, known hotspot joining on mobile, Android accessory routing, and the Preview file-transfer scenarios. Desktop clients can join Wi-Fi through system settings. Use Windows 11, macOS 12+, Linux with Avahi, Android 10+, and iOS 15+ as the initial functional baselines. A target API 37 Android permission test needs an SDK 37 build. [Android build configuration](../platform/android/build.gradle) · [iOS package](../platform/ios/Package.swift) |
| Complete cross-platform release | Finish the desktop known Wi-Fi adapters and the browser WSS bridge. Expose write shutdown on qualified backends. Verify platform permissions and fallback paths, with the same connection, authenticated identity, and stream contracts. |

### Windows and Android manual transfer

Both platforms provide `ListenTcpAsync` and `DialTcpAsync` with HuxerUI byte streams. On Android, the caller can supply a system network handle for DNS resolution and socket binding, and owns the system request that keeps it available. The pairing API adds TLS 1.3 with persistent P-256 identities, a short-lived invitation, and an application approval callback. It uses Mbed TLS 3.6.7 as a private dependency. [Public TCP API](../include/huxerui/local_network_tcp.h) · [Public pairing API](../include/huxerui/local_network_pairing.h) · [Mbed TLS release](https://github.com/Mbed-TLS/mbedtls/releases/tag/mbedtls-3.6.7)

In Preview, choose a file on each device or create the 64 MiB sample. On the listening device, enter its bind address and port and select **Listen**. On the dialing device, enter that address and port, paste the displayed pairing code, and select **Connect**. Approve the requesting device on the listener. Preview streams both files concurrently and enables **Save received file** after both devices acknowledge receipt. Leave the code empty to reconnect using the last paired device. Preview protects its saved key with DPAPI on Windows and app-private storage on Android. [Preview entry point](../examples/preview/src/app.cpp)

On 2026-11-16, a Windows 11 client dialed an Android 16 listener over the same Wi-Fi network. A modified public-key fingerprint was rejected before approval. With a fresh invitation and approval on Android, both devices sent and received 67,108,864 bytes in one TLS session. The SHA-256 hashes of the received files matched the corresponding source files on disk.

### Windows and Android discovery and QR entry

The library uses the Windows DNS Service API and Android NSD to publish and discover TCP services in the local DNS-SD domain. Keep the publication alive for the duration of the listener. Browsing returns a snapshot, and selecting an instance resolves its current numeric addresses and port. Windows publishes on the interface that owns the bound address. On Android, pass the network handle returned by resolution to the TCP dial options when the system supplies one. Manual address entry remains available when multicast discovery is blocked. [Public discovery API](../include/huxerui/local_network_discovery.h)

Preview advertises the listener as `_huxer-lan._tcp`. To pair from the device list, enter the invitation displayed on the listener and select the discovered device. Leave the invitation field empty to reconnect with the saved device identity. The announcement contains service details only. With a concrete address, Preview also displays a QR invitation containing the endpoint and short-lived pairing code. Both platforms can scan a saved PNG or JPEG with the Preview's ZXing-C++ decoder. Android can also capture the code with the system camera. Both entries use the existing TLS public-key check, listener approval, and bidirectional file exchange.

On 2026-11-16, two Preview instances on one Windows 11 computer tested the device list and a saved invitation image. Each entry completed pairing and exchanged 64 MiB per direction with SHA-256 verification. A fresh browse after the list test returned no services. An Android 16 device successfully registered a Preview service through system NSD before it disconnected from the test host. The Windows–Android Wi-Fi checks for the device list and QR entry remain pending, including optical capture on Android.
