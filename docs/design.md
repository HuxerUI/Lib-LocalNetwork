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
  Task<NetResult<void>> AdvertiseAsync(std::string name, std::string type, ServiceTxt txt = {});
  NetResult<PairingOffer> CreateInvite();
  Task<NetResult<Connection>> AcceptAsync();
};

Capabilities GetCapabilities() noexcept;

class LocalNetwork {
public:
  Task<NetResult<WifiJoinResult>> JoinKnownWifiAsync(WifiJoinRequest request);
  Task<NetResult<NetworkLease>> SelectWifiRouteAsync(WifiSelector selector);

  Task<NetResult<Discovery>> BrowseAsync(ServiceType type, NetworkScope scope);
  Task<NetResult<ResolvedService>> ResolveAsync(ServiceRef service);

  Task<NetResult<Listener>> ListenAsync(ListenOptions options);
  Task<NetResult<Connection>> ConnectAsync(
      Target target, DeviceIdentity identity, PeerCredential credential, TcpDialOptions options);
  Task<NetResult<Connection>> DialAsync(Target target, DialOptions options);
};

} // namespace huxerui::localnetwork
```

- **Connection mode.** `Target` holds a `ServiceRef` or an `Endpoint`. `PeerCredential` holds a trusted `PeerId` or a fresh invitation. `ConnectAsync` establishes an authenticated HuxerUI session. `DialAsync` uses the existing accessory protocol, defaults to TLS with system trust, and requires explicit selection of plain TCP. A listener defaults to paired sessions. An application serving an existing protocol can explicitly select TLS or TCP. Configure the incoming pairing policy when creating the listener.
- **Routing and diagnostics.** Connection and dial options can require a `NetworkLease`. The operation fails if it cannot satisfy that requirement. `ConnectionPath` reports the actual local and remote endpoints, interface and network identifier when available, and whether the connection used a bridge. `GetCapabilities()` distinguishes available operations, operations that require permission or user action, and unsupported operations. Errors identify the failed phase and retain the native cause. Report a timeout as a timeout when the platform cannot determine its cause.
- **Listening and publication.** Bind to the selected LAN interface by default and expose the actual bound endpoints. A listener can accept manual or QR connections even if publication fails. Closing the listener stops new accepts and revokes its publications. Accepted connections have their own lifetimes. Network loss or application shutdown closes affected connections.
- **Discovery.** `Discovery` reports additions, updates, and removals. A service reference retains the instance, type, domain, and interface or network scope. Resolved results include the port, candidate addresses, and TXT data. Preserve the scope of IPv6 link-local addresses and try candidates on the original network. Resolve again after relevant address changes. Preview can use `_huxer-lan._tcp`. Applications can configure their own service types. TXT records carry only public metadata, such as the protocol version. [DNS-SD specification](https://www.rfc-editor.org/info/rfc6763/)

`NetworkError::code` identifies the portable error category. `diagnostic_code` retains a system or TLS library
error number when one is available.

### Capability and route diagnostics

Call `GetCapabilities()` without opening a connection to discover which operations this build and platform
provide. `Available` means the operation can be attempted. `RequiresPermission` and `RequiresUserAction`
identify platform prerequisites such as local network access, an Android service picker, or bridge approval.
NetworkManager can require authorization for a fresh Wi-Fi scan even when it can return cached results.
`Unsupported` means the operation has no implementation on that build or system version. This query does
not inspect current grants, system service health, hardware, or reachability. Existing `Is*Supported()`
queries remain available for checking individual backends. [Capability API](../include/huxerui/local_network_common.h)

`Path()` captures the local and remote socket endpoints after TCP setup, including for direct and paired TLS.
The interface index comes from the IPv6 scope or a unique match for the local socket address. It is empty if
the platform cannot identify a unique interface for that address. On Android, the path records the network
handle used for an explicit binding, including a handle obtained from a Wi-Fi lease or DNS-SD. It does not
infer a handle for a default-route socket. Browser streams report `via_bridge` through
`WebBridgeConnection::Path()`. Their TCP endpoints and interface are unavailable to the browser.
[Connection path API](../include/huxerui/local_network_common.h)

### Stream contract

Adapt platform I/O through HuxerUI's `AsyncInputStream::FromReader` and `AsyncOutputStream::FromWriter`. A connection supports one outstanding read and one outstanding write concurrently. Reads return bounded chunks. A successful empty read indicates orderly end of input. A successful write accepts the complete chunk. The application protocol confirms receipt. Implement incremental I/O, bounded buffering, and backpressure. If an in-flight operation is cancelled after bytes may have moved and the stream position is uncertain, close the connection so the application can handle the interrupted exchange.

`output.CloseAsync()` finalizes local output and releases the output stream. `ShutdownWriteAsync()` explicitly signals end of output to the peer while allowing further reads. Advertise that capability only on backends that have verified their orderly half-close behavior. `Connection::CloseAsync()` closes the full connection and settles pending I/O. A premature disconnection or truncated application payload is an error. File transfer uses its own length and receipt acknowledgement, so the base transport needs no custom end-of-stream frame. [TLS closure alerts](https://www.rfc-editor.org/rfc/rfc8446.html#section-6.1)

The installed HuxerUI SDK 0.4.0 headers lack the public callback-backed stream factories. Implementation requires a matching SDK that exposes both factories. Lib-PluginKit already uses that contract. [HuxerUI stream API](https://github.com/HuxerUI/HuxerUI/blob/main/include/huxerui/stream.h) · [Lib-PluginKit stream adapter](https://github.com/HuxerUI/Lib-PluginKit/blob/main/include/huxerui/pluginkit/detail/streams.h)

### Unified listening and outbound connections

`ListenAsync()` defaults to paired TLS. Pass the device identity and the incoming pairing policy, then use
`CreateInvite()` to open a pairing window if the listener should accept new peers. Select `ListenMode::Tls` for
an application-supplied certificate or `ListenMode::Tcp` for plain TCP. In all three modes `AcceptAsync()`
returns an owning `Connection` after the selected transport is ready. Existing transport-specific APIs remain
available.

`AdvertiseAsync()` publishes the actual bound endpoint, including the system-assigned port. Keep the listener
open to keep its registrations active. A registration failure leaves manual address and QR entry available.
Closing the listener withdraws its registrations and ends a pending accept. Connections already returned to
the application retain their streams. Preview uses the common listener and dials manual, scanned, and discovered
targets through `ConnectAsync()`. [Unified connection API](../include/huxerui/local_network_connection.h)

The library exposes free functions `ConnectAsync()` and `DialAsync()`. Both accept an `Endpoint` or a
`DiscoveredService`. `ConnectAsync()` uses a local device identity and a remembered key or pairing code.
`DialAsync()` defaults to platform-trusted TLS. Select `DialMode::Tcp` for a plain TCP accessory.

For TLS over DNS-SD, supply the expected certificate name through `DialOptions::server_name`. Obtain it from the
user or application configuration. Discovery supplies the candidate addresses. The dial keeps their scope,
checks any Android network constraint, and tries other addresses after connection failures or timeouts. An
authentication or pairing error ends the operation. The TCP timeout applies to each resolved endpoint.

The owning `Connection` exposes the existing input and output streams, the actual TCP endpoints, the security
mode, and the authenticated peer identifier for paired TLS. `ShutdownWriteAsync()` finishes the output stream
while input stays available. `CloseAsync()` closes both directions when the task runs. Existing applications
can use the original connection types or transfer them into a `Connection`. [Unified connection API](../include/huxerui/local_network_connection.h)

### Accessory TLS client

Use `DialTlsAsync()` for a TLS 1.2 or TLS 1.3 accessory that uses platform trust. The connection exposes the
same input and output streams as the paired transport. The dial checks a DNS or IP subject alternative name
before exposing application bytes. When a numeric address locates an accessory with a DNS certificate, set
`TlsDialOptions::server_name` to the expected DNS name. [TLS service identity](https://www.rfc-editor.org/rfc/rfc9525.html)

The TLS engine must parse the certificate chain before platform trust evaluation. An unsupported critical
extension, such as name constraints in the current Mbed TLS backend, fails the handshake.

Windows uses the system certificate chain engine, macOS and iOS use Security framework trust, Linux uses the
distribution's CA bundle, and Android uses the application's default Android trust manager. On Android,
register `Install()` and pass any required Wi-Fi lease through `TlsDialOptions::tcp`. DNS lookup, TCP, and TLS
traffic then use that lease. [TLS client API](../include/huxerui/local_network_tls.h)

### Direct TLS listener

`ListenTlsAsync()` binds a numeric address and negotiates TLS 1.2 or TLS 1.3 before returning each connection
from `AcceptAsync()`. The application supplies a PEM leaf certificate, its intermediate certificates in issuer
order, and an unencrypted matching PEM private key. The library checks the key against the leaf when opening
the listener. The dialing application establishes trust in the server certificate through its own trust policy.

An accepted connection presents the server certificate without authenticating the client. Applications authorize
requests on the resulting byte streams. `Connection::Security()` reports `ServerTls` when wrapping an accepted
connection. Closing the listener ends a pending accept, including a TLS handshake in progress. Established
connections stay open. TLS 1.3 supports independent output shutdown. For TLS 1.2, finish the application
exchange before sending `close_notify`, which initiates closure of the entire session. Web builds return
`Unsupported` for direct TLS listeners. [TLS listener API](../include/huxerui/local_network_tls.h) ·
[TLS closure alerts](https://www.rfc-editor.org/rfc/rfc8446.html#section-6.1)

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

### Paired-session bridge

The desktop application establishes an authenticated native session with `ConnectPairedAsync()` or
`AcceptPairedAsync()`. After the user approves sharing that session, the application opens
`ListenWebBridgeAsync()` with a browser-trusted PEM certificate chain, its private key, and the exact page origin.
The listener binds to loopback by default. To use it from another device, choose a local interface address and use
a hostname covered by the certificate. Deliver the WSS URL and `Grant()` to the approved page and pass the unused
paired connection to `RelayAsync()`. Keep the listener and its task scope alive while forwarding.

The Web build opens `ConnectWebBridgeAsync()` with that URL, the one-time grant, and optionally the expected
downstream `PeerId`. Use `Input()` and `Output()` with the application's existing stream protocol, and await
`Output().CloseAsync()` to end the sending direction. The WSS bridge uses a separate certificate from native
pairing. It authenticates the native peer on the page's behalf and can inspect relayed bytes. The grant is sent
inside WSS and consumed once. Keep it out of URLs, logs, and persistence.

This path hands one existing connection to the browser through `RelayAsync()`.

### Scoped browser control

Use `ServeAsync()` with a `WebBridgePolicy` after the desktop user approves a page. Provide the approved DNS-SD
types and optional interface, the exact numeric address and public-key combinations the page may dial, and the
local address and incoming pairing policy for any registered listeners. Publication can use only approved types
and the actual endpoint of a listener owned by the page. The desktop application supplies its existing pairing
identity, approves incoming invitations, and shares any invitation code through its own UI.

On Web, redeem the one-time control grant through `ConnectWebBridgeControlAsync()`. Browse an approved type,
resolve an entry from its latest snapshot, and dial an approved endpoint and peer. To receive a connection,
call the control channel's `ListenAsync()` and retain the `WebBridgeListenerRegistration` with its listener ID
and endpoint. Publish the endpoint when discovery is needed, and await `AcceptAsync()`. Withdraw a
publication independently or close its listener to stop new accepts. Closing a listener leaves established
sessions available while the control connection remains open.

The control socket handles one request at a time. Each dial or accept redeems a separate short-lived grant on
another WSS socket and exposes the same asynchronous byte streams as the paired-session bridge. An accept waiting
for a peer leaves the control connection available. Losing the control connection ends the registered listeners,
publications, pending grants, and data connections. The desktop app can close its WSS listener to revoke the
entire control session.

Windows, macOS, and Linux builds can host the bridge. Set `HUXERUI_LOCALNETWORK_BUILD_WEB_BRIDGE=OFF` to omit the
desktop listener. The host application supplies page hosting and certificate provisioning.

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

The library uses the Windows DNS Service API and Android NSD to publish and discover TCP services in the local DNS-SD domain. Keep the publication alive for the duration of the listener. Browsing returns a snapshot. Show each `DiscoveredService::display_name` and keep its `instance_id`, type, and scope for resolution. Selecting an entry resolves its current numeric addresses and port. Windows publishes on the interface that owns the bound address. When dialing a resolved endpoint on Android without a Wi-Fi lease, pass `ResolvedService::android_network_handle` as `TcpDialOptions::android_network_handle` if available. Manual address entry remains available when multicast discovery is blocked. [Public discovery API](../include/huxerui/local_network_discovery.h)

Preview advertises the listener as `_huxer-lan._tcp`. To pair from the device list, enter the invitation displayed on the listener and select the discovered device. Leave the invitation field empty to reconnect with the saved device identity. The announcement contains service details only. With a concrete address, Preview also displays a QR invitation containing the endpoint and short-lived pairing code. Both platforms can scan a saved PNG or JPEG with the Preview's ZXing-C++ decoder. Android can also capture the code with the system camera. Both entries use the existing TLS public-key check, listener approval, and bidirectional file exchange.

On 2026-11-16, two Preview instances on one Windows 11 computer tested the device list and a saved invitation image. Each entry completed pairing and exchanged 64 MiB per direction with SHA-256 verification. A fresh browse after the list test returned no services. An Android 16 device successfully registered a Preview service through system NSD before it disconnected from the test host. The Windows–Android Wi-Fi checks for the device list and QR entry remain pending, including optical capture on Android.

### Android 17 local network permission and service picker

Preview targets API 37. On Android 17 and later it checks `ACCESS_LOCAL_NETWORK` before listening, browsing
the device list, or connecting by a listed service, manual address, or QR invitation. If the user denies access,
they can retry the operation or use **App permission settings** to grant access and retry after returning.
Earlier Android releases keep their previous permission and discovery flow. The host application owns the
permission declaration and request UI. [Android local network permission](https://developer.android.com/privacy-and-security/local-network-permission)

Select **Choose device in Android** to use `PickServiceAsync()` without requesting general access. Enter the
pairing code first when connecting to a new peer. The system picker authorizes one service and provides its
resolved addresses on a specific Android network. Preview dials those addresses on that network and uses the
same TLS pairing and file exchange as the other connection paths. If a Wi-Fi lease is selected, the picker is
scoped to that lease and Preview keeps it through the connection. Dismissing or canceling the picker leaves
Preview idle. [Android NSD picker](https://developer.android.com/reference/android/net/nsd/NsdManager)

### Linux discovery and QR entry

The Linux build enables DNS-SD when `pkg-config` finds the Avahi client development package. Browse, resolve, and publish use the system Avahi service. Preview publishes on the interface that owns its numeric bind address and keeps the interface index in each browse result for resolution. Direct address entry and QR invitations remain available without Avahi. Linux Preview can generate a pairing QR code, save it as a PNG, and open a PNG or JPEG through its file picker. Decoded invitations use the same TLS public-key check and approval as the other platforms.

On 2026-11-17, Windows 11 and Ubuntu 24.04 under WSL2 used the same virtual network. Windows browsed and resolved the Linux service, paired, and transferred files. Linux then browsed and resolved the Windows service and reconnected using the saved peer identity. In a separate session, Linux opened a Windows-generated QR image through a test file chooser on the WSL desktop bus, and Windows approved the new pairing. Each session transferred 64 MiB in each direction and both received files matched the source SHA-256 hashes.

### macOS and iOS discovery and QR entry

macOS and iOS each implement the library's DNS-SD API with the system Bonjour service. Browse results retain the interface that reported each instance. Resolution looks up the service's host and port, then obtains its IPv4 and IPv6 addresses through Bonjour on that interface. Publication requires a concrete listener address on an active multicast interface and ends when the owning registration closes. Preview declares `_huxer-lan._tcp` and its local network usage in each application bundle. Users can dial a known address when discovery is unavailable and local network access is permitted. [Bonjour DNS-SD API](https://developer.apple.com/documentation/dnssd) · [Local Network privacy](https://developer.apple.com/documentation/technotes/tn3179-understanding-local-network-privacy)

Both Preview apps can open a saved PNG or JPEG pairing invitation. On iOS, users can also photograph the QR code through the system camera and grant access when prompted. The discovery list and decoded invitations use the same TLS identity checks, listener approval, and bidirectional transfer as direct address entry.

### Wi-Fi scanning and joining

Use `ScanWifiAsync()` to list nearby visible networks. Each row contains the exact UTF-8 SSID and its reported security. The result indicates whether the scan refreshed during the call, so an app can identify cached results. Use `JoinWifiAsync()` with an SSID, security, and passphrase from the user or accessory configuration. Joining does not depend on first calling the scan API. Hidden networks and enterprise profiles can be configured in system Wi-Fi settings. [Public Wi-Fi API](../include/huxerui/local_network_wifi.h)

| Platform | Nearby Wi-Fi list | Join a known hotspot |
| --- | --- | --- |
| Windows | Windows WLAN AutoConfig scans the first Wi-Fi adapter and reports completion. Recent Windows releases can require precise location access. | Use a temporary WLAN profile for open, WPA2-Personal, or WPA3-Personal if the adapter supports it. An explicit persistent request saves a per-user profile after association. [Windows Wi-Fi location access](https://learn.microsoft.com/en-us/windows/win32/nativewifi/wi-fi-access-location-changes) |
| macOS | CoreWLAN scans the system Wi-Fi interface. The host requests Location authorization and provides the applicable usage description in its bundle. | Use CoreWLAN for a visible open, WPA2-Personal, or WPA3-Personal hotspot. The system manages configuration lifetime and can require administrator authorization. Explicit temporary or persistent requests use system settings. [CoreWLAN](https://developer.apple.com/documentation/corewlan) |
| Linux | When built with GIO, use NetworkManager on the system bus. The Wi-Fi adapter must be managed by NetworkManager. | Activate a visible open, WPA2-Personal, or WPA3-Personal hotspot using NetworkManager and system authorization. The default profile is volatile and is removed on disconnection. Explicit persistent mode saves it to disk. [NetworkManager D-Bus API](https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.html) |
| Android | Android 10+ uses `WifiManager`. The app declares and requests precise location for a scan and the user enables system Location. The system can throttle scan requests. | An app-scoped system request joins a visible open, WPA2-Personal, or WPA3-Personal hotspot. The app declares and requests `NEARBY_WIFI_DEVICES` on Android 13+ or the applicable location permission on older releases. The user saves persistent networks through Wi-Fi settings. [Android scan permissions](https://developer.android.com/develop/connectivity/wifi/wifi-scan) · [Android Wi-Fi permissions](https://developer.android.com/develop/connectivity/wifi/wifi-permissions) |
| iOS | Show the system Wi-Fi settings for a general list. | The foreground app uses `NEHotspotConfiguration` for an open or personal passphrase hotspot. The host enables the Hotspot Configuration entitlement and links NetworkExtension in Xcode. The library uses Wi-Fi Information access when available to confirm the SSID, and otherwise reports accepted configuration separately. The default is `joinOnce`. Set persistent mode to save the configuration. Use Wi-Fi settings to require WPA3-Personal explicitly. [iOS Wi-Fi API](https://developer.apple.com/documentation/technotes/tn3111-ios-wifi-api-overview) · [Current network and entitlement](https://developer.apple.com/documentation/networkextension/nehotspotnetwork/fetchcurrent(completionhandler:)) |
| Web | Show instructions for opening system Wi-Fi settings. | The user joins through system settings. |

After an Android join succeeds, pass the returned `WifiJoinResult::lease` as `TcpDialOptions::wifi_lease` to `DialTcpAsync()` or `ConnectPairedAsync()`. The library retains the request during the dial and during the connection. DNS and socket setup use only the leased Android network. After network loss, dials and subsequent stream operations report failure and the app can request a fresh lease. Applications can skip DNS-SD and dial a manually entered or scanned invitation address through that same lease. [Android network request API](https://developer.android.com/develop/connectivity/wifi/wifi-bootstrap) · [TCP dial options](../include/huxerui/local_network_tcp.h)

When the user joins via Android settings, call `SelectWifiRouteAsync()` with the exact SSID on Android 12 or later. With precise Location access and system Location enabled, the library observes available Wi-Fi networks and requires a unique, usable match. Releasing this lease leaves the system association in place. Pass its handle as the scope for DNS-SD browsing on Android 13 or later. If scoped discovery is unavailable, use a numeric address or QR invitation with the same lease. [Android network callback](https://developer.android.com/reference/android/net/ConnectivityManager.NetworkCallback) · [Android DNS-SD](https://developer.android.com/reference/android/net/nsd/NsdManager)

Use `JoinSavedWifiProfileAsync()` for an existing Windows WLAN profile name or Linux NetworkManager profile UUID. The operating system manages the profile and its credentials, including enterprise authentication. Other platforms use system Wi-Fi settings for saved profiles. [Windows WLAN connection parameters](https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/ns-wlanapi-wlan_connection_parameters) · [NetworkManager D-Bus API](https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.html)

For accessory HTTP on Android, `SendWifiHttpAsync()` in the Wi-Fi API accepts the same lease and a HuxerUI `HttpRequest`. It uses Android's network-scoped HTTP connection and certificate validation. The API buffers up to 1 MiB per body and returns redirect responses to the caller, which can validate the target and submit another request on the same lease. [Public Wi-Fi API](../include/huxerui/local_network_wifi.h) · [Android network-scoped HTTP](https://developer.android.com/reference/android/net/Network)

### Wi-Fi setup in Preview

Open **Wi-Fi setup** and select **Scan Wi-Fi** where supported. Select a listed network to populate its SSID and security, or enter the exact SSID and choose its security manually. Enter the password in the secure field and select **Join hotspot**. Preview clears the field when submitting. Android requests precise Location for scanning and asks for Nearby Devices for joining on Android 13 or later. On older Android releases and on macOS, joining uses Location permission. Use **Permission settings** to recover from a denied grant. iOS uses its system join confirmation and the entitlements in the Preview Xcode target. Its nearby list is available in **Settings > Wi-Fi**.

On Android, keep the returned route selected while connecting by address or QR invitation. Discovered devices can be used when DNS-SD identifies them on that same network. Select **Release Wi-Fi route** to return to system routing. To verify the route, join a hotspot with no internet while Android retains a separate default network, pair with a listener on the hotspot, exchange a file in both directions, and check the reported local address and SHA-256 results. Disable the hotspot and verify that a new dial on the held route fails. [Android Wi-Fi network request API](https://developer.android.com/develop/connectivity/wifi/wifi-bootstrap)

### Revocation and discovery events

Keep a shared `DeviceIdentity` across the application's listeners and dialers. `RevokePeer()` closes the peer's active sessions and rejects further pairing and reconnect attempts on that identity. Remove the peer from stored trust and reapply its revocation when restoring the identity from disk. [Public pairing API](../include/huxerui/local_network_pairing.h)

`BrowseServiceChanges()` exposes `Added`, `DisplayNameChanged`, and `Removed` events through a single-consumer `NextAsync()` reader. Each pending read draws from bounded system observations. Resolve a service reference to obtain its current addresses and public TXT attributes, including text or address changes that do not change the browse entry. TXT publication and resolution use lowercase keys and portable UTF-8 values. [Public discovery API](../include/huxerui/local_network_discovery.h)
