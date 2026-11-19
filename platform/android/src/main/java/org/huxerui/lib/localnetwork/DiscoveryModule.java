package org.huxerui.lib.localnetwork;

import android.annotation.TargetApi;
import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.nsd.DiscoveryRequest;
import android.net.nsd.NsdManager;
import android.net.nsd.NsdServiceInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.ext.SdkExtensions;
import android.system.Os;
import android.system.OsConstants;

import org.huxerui.HuxerUIPlatformChannel;
import org.huxerui.HuxerUIPlatformModule;
import org.huxerui.PlatformPayload;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class DiscoveryModule implements HuxerUIPlatformModule.Factory {
    @Override
    public HuxerUIPlatformModule create(Context context, PlatformPayload options, HuxerUIPlatformChannel.Events events) {
        return new Session(context);
    }

    private static final class Session implements HuxerUIPlatformModule {
        private final NsdManager manager;
        private final ConnectivityManager connectivity;
        private final WifiManager wifi;
        private final Handler main = new Handler(Looper.getMainLooper());
        private NsdManager.DiscoveryListener discovery;
        private NsdManager.RegistrationListener registration;
        private NsdManager.ResolveListener resolution;
        private NsdManager.ServiceInfoCallback picker;
        private WifiManager.MulticastLock multicast;
        private Runnable timeout;
        private boolean disposed;

        Session(Context context) {
            manager = context.getSystemService(NsdManager.class);
            connectivity = context.getSystemService(ConnectivityManager.class);
            wifi = context.getApplicationContext().getSystemService(WifiManager.class);
        }

        @Override
        public HuxerUIPlatformChannel.Cancellation invoke(
                String method, PlatformPayload arguments, HuxerUIPlatformChannel.Result result) {
            if (disposed || manager == null) {
                fail(result, "System DNS-SD is unavailable.");
                return null;
            }
            try {
                switch (method) {
                    case "browse":
                        browse(arguments.requireField("type").requireString(),
                                arguments.requireField("milliseconds").requireInt64(),
                                arguments.requireField("network").requireInt64(), result);
                        break;
                    case "pick":
                        if (Build.VERSION.SDK_INT < 37) {
                            result.fail("localnetwork/discovery-unsupported", "The DNS-SD picker requires Android 17.",
                                    PlatformPayload.nullValue());
                            return null;
                        }
                        pick(arguments.requireField("type").requireString(),
                                arguments.requireField("network").requireInt64(), result);
                        break;
                    case "resolve": resolve(arguments, result); break;
                    case "publish": publish(arguments, result); break;
                    default: fail(result, "Unknown DNS-SD operation."); return null;
                }
                return this::dispose;
            } catch (SecurityException denied) {
                dispose();
                permissionDenied(result);
            } catch (RuntimeException error) {
                dispose();
                fail(result, "The system could not start the DNS-SD operation.");
            }
            return null;
        }

        private void browse(String type, long observation, long network, HuxerUIPlatformChannel.Result result) {
            if (network != 0 && Build.VERSION.SDK_INT < 33) {
                result.fail("localnetwork/discovery-unsupported", "Wi-Fi-scoped discovery requires Android 13 or later.",
                        PlatformPayload.nullValue());
                return;
            }
            final Map<String, PlatformPayload> found = new LinkedHashMap<>();
            // Older NSD implementations require an application multicast lock during Wi-Fi browsing.
            if (wifi != null && (Build.VERSION.SDK_INT < 33 || SdkExtensions.getExtensionVersion(33) < 7)) {
                multicast = wifi.createMulticastLock("HuxerUI LocalNetwork DNS-SD");
                multicast.acquire();
            }
            discovery = new NsdManager.DiscoveryListener() {
                @Override public void onDiscoveryStarted(String serviceType) {}

                @Override public void onServiceFound(NsdServiceInfo service) {
                    main.post(() -> {
                        if (discovery != this || found.size() >= 128) return;
                        Map<String, PlatformPayload> fields = new LinkedHashMap<>();
                        fields.put("name", PlatformPayload.string(service.getServiceName()));
                        fields.put("network", PlatformPayload.int64(networkHandle(service)));
                        found.put(key(service), PlatformPayload.object(fields));
                    });
                }

                @Override public void onServiceLost(NsdServiceInfo service) {
                    main.post(() -> { if (discovery == this) found.remove(key(service)); });
                }

                @Override public void onStartDiscoveryFailed(String serviceType, int error) {
                    main.post(() -> {
                        if (discovery != this) return;
                        stopBrowse();
                        failNsd(result, "DNS-SD browsing", error);
                    });
                }

                @Override public void onStopDiscoveryFailed(String serviceType, int error) {}
                @Override public void onDiscoveryStopped(String serviceType) {}
            };
            if (Build.VERSION.SDK_INT >= 37) {
                // Snapshot browsing stays separate from the explicit single-service picker.
                manager.discoverServices(discoveryRequest(type, network, DiscoveryRequest.FLAG_NO_PICKER),
                        main::post, discovery);
            } else if (Build.VERSION.SDK_INT >= 33 && network != 0) {
                manager.discoverServices(type, NsdManager.PROTOCOL_DNS_SD, Network.fromNetworkHandle(network),
                        main::post, discovery);
            } else {
                manager.discoverServices(type, NsdManager.PROTOCOL_DNS_SD, discovery);
            }
            timeout = () -> {
                if (discovery == null) return;
                stopBrowse();
                result.complete(PlatformPayload.list(new ArrayList<>(found.values())));
            };
            main.postDelayed(timeout, observation);
        }

        @TargetApi(37)
        private static DiscoveryRequest discoveryRequest(String type, long network, long flags) {
            DiscoveryRequest.Builder request = new DiscoveryRequest.Builder(type).setFlags(flags);
            if (network != 0) request.setNetwork(Network.fromNetworkHandle(network));
            return request.build();
        }

        @TargetApi(37)
        private void pick(String type, long network, HuxerUIPlatformChannel.Result result) {
            picker = new NsdManager.ServiceInfoCallback() {
                @Override public void onServiceUpdated(NsdServiceInfo service) {
                    if (picker != this) return;
                    // Android unregisters the one-shot callback after delivering the approved service.
                    picker = null;
                    result.complete(resolvedPayload(service));
                }

                @Override public void onServiceInfoCallbackRegistrationFailed(int error) {
                    if (picker != this) return;
                    picker = null;
                    failNsd(result, "DNS-SD service selection", error);
                }

                @Override public void onServiceInfoCallbackUnregistered() {
                    if (picker != this) return;
                    picker = null;
                    result.complete(PlatformPayload.nullValue());
                }

                @Override public void onServiceLost() {}
            };
            manager.registerServiceInfoCallback(discoveryRequest(type, network, DiscoveryRequest.FLAG_SHOW_PICKER),
                    main::post, picker);
        }

        @SuppressWarnings("deprecation")
        private void resolve(PlatformPayload arguments, HuxerUIPlatformChannel.Result result) {
            NsdServiceInfo requested = fromArguments(arguments);
            long network = arguments.requireField("network").requireInt64();
            if (Build.VERSION.SDK_INT >= 33 && network != 0) requested.setNetwork(Network.fromNetworkHandle(network));
            resolution = new NsdManager.ResolveListener() {
                @Override public void onResolveFailed(NsdServiceInfo service, int error) {
                    main.post(() -> {
                        if (resolution != this) return;
                        resolution = null;
                        clearTimeout();
                        failNsd(result, "DNS-SD resolution", error);
                    });
                }

                @Override public void onServiceResolved(NsdServiceInfo service) {
                    main.post(() -> {
                        if (resolution != this) return;
                        resolution = null;
                        clearTimeout();
                        result.complete(resolvedPayload(service));
                    });
                }
            };
            manager.resolveService(requested, resolution);
            timeout = () -> {
                stopResolve();
                fail(result, "DNS-SD resolution timed out.");
            };
            main.postDelayed(timeout, 8000);
        }

        @SuppressWarnings("deprecation")
        private static PlatformPayload resolvedPayload(NsdServiceInfo service) {
            List<InetAddress> hosts = Build.VERSION.SDK_INT >= 34 ? service.getHostAddresses()
                    : Collections.singletonList(service.getHost());
            List<PlatformPayload> addresses = new ArrayList<>();
            for (InetAddress address : hosts) {
                if (address != null) addresses.add(PlatformPayload.string(address.getHostAddress()));
            }
            Map<String, PlatformPayload> attributes = new LinkedHashMap<>();
            // Keep incoming bytes intact so the common adapter can reject non-text attributes.
            for (Map.Entry<String, byte[]> entry : service.getAttributes().entrySet()) {
                byte[] value = entry.getValue();
                attributes.put(entry.getKey(), PlatformPayload.bytes(value == null ? new byte[0] : value));
            }
            Map<String, PlatformPayload> fields = new LinkedHashMap<>();
            fields.put("port", PlatformPayload.int64(service.getPort()));
            fields.put("network", PlatformPayload.int64(networkHandle(service)));
            fields.put("addresses", PlatformPayload.list(addresses));
            fields.put("txt", PlatformPayload.object(attributes));
            return PlatformPayload.object(fields);
        }

        private void publish(PlatformPayload arguments, HuxerUIPlatformChannel.Result result) {
            NsdServiceInfo service = fromArguments(arguments);
            service.setPort((int) arguments.requireField("port").requireInt64());
            for (Map.Entry<String, PlatformPayload> attr : arguments.requireField("txt").fields().entrySet()) {
                service.setAttribute(attr.getKey(), attr.getValue().requireString());
            }
            String host = arguments.requireField("host").requireString();
            Network bound = networkForAddress(host);
            if (bound == null) {
                fail(result, "DNS-SD publication requires a concrete address on an active network.");
                return;
            }
            if (Build.VERSION.SDK_INT >= 33) service.setNetwork(bound);
            registration = new NsdManager.RegistrationListener() {
                @Override public void onServiceRegistered(NsdServiceInfo info) {
                    main.post(() -> {
                        if (registration != this) return;
                        clearTimeout();
                        result.complete(PlatformPayload.nullValue());
                    });
                }

                @Override public void onRegistrationFailed(NsdServiceInfo info, int error) {
                    main.post(() -> {
                        if (registration != this) return;
                        registration = null;
                        clearTimeout();
                        failNsd(result, "DNS-SD publication", error);
                    });
                }

                @Override public void onServiceUnregistered(NsdServiceInfo info) {}
                @Override public void onUnregistrationFailed(NsdServiceInfo info, int error) {}
            };
            manager.registerService(service, NsdManager.PROTOCOL_DNS_SD, registration);
            timeout = () -> {
                dispose();
                fail(result, "DNS-SD publication timed out.");
            };
            main.postDelayed(timeout, 8000);
        }

        private static NsdServiceInfo fromArguments(PlatformPayload fields) {
            NsdServiceInfo info = new NsdServiceInfo();
            info.setServiceName(fields.requireField("name").requireString());
            info.setServiceType(fields.requireField("type").requireString());
            return info;
        }

        private Network networkForAddress(String host) {
            if (connectivity == null) return null;
            int zone = host.indexOf('%');
            String numeric = zone < 0 ? host : host.substring(0, zone);
            String scope = zone < 0 ? "" : host.substring(zone + 1);
            int family = numeric.indexOf(':') < 0 ? OsConstants.AF_INET : OsConstants.AF_INET6;
            InetAddress bindAddress = Os.inet_pton(family, numeric);
            if (bindAddress == null || bindAddress.isAnyLocalAddress() || bindAddress.isLoopbackAddress()) return null;
            for (Network network : connectivity.getAllNetworks()) {
                LinkProperties links = connectivity.getLinkProperties(network);
                if (links == null) continue;
                for (LinkAddress address : links.getLinkAddresses()) {
                    InetAddress candidate = address.getAddress();
                    if (!bindAddress.equals(candidate)) continue;
                    if (zone < 0 || (candidate instanceof Inet6Address &&
                            (scope.equals(links.getInterfaceName()) ||
                             scope.equals(Integer.toString(((Inet6Address) candidate).getScopeId()))))) return network;
                }
            }
            return null;
        }

        private static long networkHandle(NsdServiceInfo service) {
            if (Build.VERSION.SDK_INT < 33) return 0;
            Network network = service.getNetwork();
            return network == null ? 0 : network.getNetworkHandle();
        }

        private static String key(NsdServiceInfo service) {
            return service.getServiceName() + '\n' + networkHandle(service);
        }

        private static void fail(HuxerUIPlatformChannel.Result result, String message) {
            result.fail("localnetwork/discovery", message, PlatformPayload.nullValue());
        }

        private static void permissionDenied(HuxerUIPlatformChannel.Result result) {
            result.fail("localnetwork/permission", "The system denied local network access.", PlatformPayload.nullValue());
        }

        private static void failNsd(HuxerUIPlatformChannel.Result result, String operation, int error) {
            if (Build.VERSION.SDK_INT >= 37 && error == NsdManager.FAILURE_PERMISSION_DENIED) permissionDenied(result);
            else fail(result, operation + " failed (" + error + ").");
        }

        private void clearTimeout() {
            if (timeout == null) return;
            main.removeCallbacks(timeout);
            timeout = null;
        }

        private void stopBrowse() {
            NsdManager.DiscoveryListener listener = discovery;
            discovery = null;
            clearTimeout();
            if (listener != null) {
                try { manager.stopServiceDiscovery(listener); } catch (RuntimeException ignored) {}
            }
            if (multicast != null) {
                if (multicast.isHeld()) multicast.release();
                multicast = null;
            }
        }

        private void stopResolve() {
            NsdManager.ResolveListener listener = resolution;
            resolution = null;
            if (listener != null && Build.VERSION.SDK_INT >= 34) {
                try { manager.stopServiceResolution(listener); } catch (RuntimeException ignored) {}
            }
        }

        private void stopPicker() {
            if (Build.VERSION.SDK_INT < 37 || picker == null) return;
            NsdManager.ServiceInfoCallback callback = picker;
            picker = null;
            try { manager.unregisterServiceInfoCallback(callback); } catch (RuntimeException ignored) {}
        }

        @Override public void dispose() {
            if (disposed) return;
            disposed = true;
            stopBrowse();
            stopResolve();
            stopPicker();
            NsdManager.RegistrationListener listener = registration;
            registration = null;
            if (listener != null) {
                try { manager.unregisterService(listener); } catch (RuntimeException ignored) {}
            }
        }
    }
}
