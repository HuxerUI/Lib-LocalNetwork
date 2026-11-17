package org.huxerui.lib.localnetwork;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.location.LocationManager;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.net.wifi.WifiNetworkSpecifier;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;

import org.huxerui.HuxerUIPlatformChannel;
import org.huxerui.HuxerUIPlatformModule;
import org.huxerui.PlatformPayload;

import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class WifiModule implements HuxerUIPlatformModule.Factory {
    @Override
    public HuxerUIPlatformModule create(Context context, PlatformPayload options, HuxerUIPlatformChannel.Events events) {
        return new Session(context.getApplicationContext(), events);
    }

    private static final class Session implements HuxerUIPlatformModule {
        private final Context context;
        private final WifiManager wifi;
        private final ConnectivityManager connectivity;
        private final HuxerUIPlatformChannel.Events events;
        private final Handler main = new Handler(Looper.getMainLooper());
        private BroadcastReceiver scan;
        private Runnable timeout;
        private ConnectivityManager.NetworkCallback request;
        private Network selected;
        private boolean joined;

        Session(Context context, HuxerUIPlatformChannel.Events events) {
            this.context = context;
            this.events = events;
            wifi = context.getSystemService(WifiManager.class);
            connectivity = context.getSystemService(ConnectivityManager.class);
        }

        @Override
        public HuxerUIPlatformChannel.Cancellation invoke(
                String method, PlatformPayload arguments, HuxerUIPlatformChannel.Result result) {
            if (wifi == null || connectivity == null || Build.VERSION.SDK_INT < 29) {
                fail(result, "unsupported", "Wi-Fi operations require Android 10 or later and a Wi-Fi adapter.");
                return null;
            }
            try {
                if ("scan".equals(method)) scan(result);
                else if ("join".equals(method)) join(arguments, result);
                else fail(result, "unsupported", "Unknown Wi-Fi operation.");
            } catch (SecurityException denied) {
                dispose();
                fail(result, "permission", "Check the app's Wi-Fi permissions and system location settings.");
            } catch (RuntimeException error) {
                dispose();
                fail(result, "failed", "The system could not start the Wi-Fi operation.");
            }
            return this::dispose;
        }

        @SuppressWarnings("deprecation")
        private void scan(HuxerUIPlatformChannel.Result result) {
            LocationManager location = context.getSystemService(LocationManager.class);
            if (location == null || !location.isLocationEnabled()) {
                fail(result, "permission", "Enable system Location to obtain the Wi-Fi list.");
                return;
            }
            if (!wifi.isWifiEnabled()) {
                fail(result, "failed", "Enable Wi-Fi in system settings.");
                return;
            }
            wifi.getScanResults(); // Check access before waiting for a broadcast.
            scan = new BroadcastReceiver() {
                @Override public void onReceive(Context ignored, Intent intent) {
                    if (scan != this) return;
                    completeScan(result, intent.getBooleanExtra(WifiManager.EXTRA_RESULTS_UPDATED, false));
                }
            };
            IntentFilter filter = new IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION);
            try {
                if (Build.VERSION.SDK_INT >= 33) context.registerReceiver(scan, filter, Context.RECEIVER_NOT_EXPORTED);
                else context.registerReceiver(scan, filter);
            } catch (RuntimeException error) {
                scan = null;
                throw error;
            }
            if (!wifi.startScan()) {
                completeScan(result, false);
                return;
            }
            timeout = () -> completeScan(result, false);
            main.postDelayed(timeout, 7000);
        }

        @SuppressWarnings("deprecation")
        private void completeScan(HuxerUIPlatformChannel.Result result, boolean refreshed) {
            stopScan();
            List<PlatformPayload> networks = new ArrayList<>();
            try {
                for (ScanResult row : wifi.getScanResults()) {
                    String name = ssid(row);
                    if (name == null || name.isEmpty()) continue;
                    Map<String, PlatformPayload> fields = new LinkedHashMap<>();
                    fields.put("ssid", PlatformPayload.string(name));
                    fields.put("security", PlatformPayload.string(security(row)));
                    networks.add(PlatformPayload.object(fields));
                }
            } catch (SecurityException denied) {
                fail(result, "permission", "The system denied access to Wi-Fi scan results.");
                return;
            }
            Map<String, PlatformPayload> snapshot = new LinkedHashMap<>();
            snapshot.put("networks", PlatformPayload.list(networks));
            snapshot.put("refreshed", PlatformPayload.booleanValue(refreshed));
            result.complete(PlatformPayload.object(snapshot));
        }

        @SuppressWarnings("deprecation")
        private static String ssid(ScanResult row) {
            if (Build.VERSION.SDK_INT >= 33 && row.getWifiSsid() != null) {
                try {
                    return StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(row.getWifiSsid().getBytes())).toString();
                } catch (CharacterCodingException invalid) {
                    return null;
                }
            }
            // Older releases give a display string rather than the original SSID bytes.
            return row.SSID == null || row.SSID.indexOf('\uFFFD') >= 0 ? null : row.SSID;
        }

        private static String security(ScanResult row) {
            if (Build.VERSION.SDK_INT >= 33) {
                boolean wpa3 = false;
                for (int type : row.getSecurityTypes()) {
                    if (type == WifiInfo.SECURITY_TYPE_PSK) return "wpa2";
                    if (type == WifiInfo.SECURITY_TYPE_OPEN) return "open";
                    if (type == WifiInfo.SECURITY_TYPE_SAE) wpa3 = true;
                }
                return wpa3 ? "wpa3" : "other";
            }
            String flags = row.capabilities;
            if (flags.contains("PSK") && (flags.contains("RSN") || flags.contains("WPA2"))) return "wpa2";
            if (flags.contains("SAE")) return "wpa3";
            if (flags.equals("[ESS]") || flags.equals("[WPS][ESS]")) return "open";
            return "other";
        }

        private void join(PlatformPayload fields, HuxerUIPlatformChannel.Result result) {
            WifiNetworkSpecifier.Builder specifier = new WifiNetworkSpecifier.Builder()
                    .setSsid(fields.requireField("ssid").requireString());
            String security = fields.requireField("security").requireString();
            String passphrase = fields.requireField("passphrase").requireString();
            if ("wpa2".equals(security)) specifier.setWpa2Passphrase(passphrase);
            if ("wpa3".equals(security)) specifier.setWpa3Passphrase(passphrase);
            NetworkRequest network = new NetworkRequest.Builder()
                    .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                    .removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .setNetworkSpecifier(specifier.build())
                    .build();
            request = new ConnectivityManager.NetworkCallback() {
                @Override public void onAvailable(Network available) {
                    if (request == this) selected = available;
                }

                @Override public void onLinkPropertiesChanged(Network available, LinkProperties links) {
                    // onAvailable can precede DHCP. Wait for an interface and a usable source address.
                    if (request != this || joined || !available.equals(selected) ||
                            links.getInterfaceName() == null || !hasAddress(links)) return;
                    joined = true;
                    clearTimeout();
                    result.complete(PlatformPayload.int64(available.getNetworkHandle()));
                }

                @Override public void onUnavailable() {
                    if (request != this) return;
                    dispose();
                    fail(result, "failed", "Wi-Fi connection was declined, unavailable, or timed out.");
                }

                @Override public void onLost(Network lost) {
                    if (request != this || !lost.equals(selected)) return;
                    boolean held = joined;
                    dispose();
                    if (held) events.emit("lost", PlatformPayload.nullValue());
                    else fail(result, "lost", "The requested Wi-Fi network was lost before address assignment.");
                }
            };
            connectivity.requestNetwork(network, request, main, 40000);
            // The platform request timer stops at onAvailable, so bound the address wait separately.
            timeout = () -> {
                dispose();
                fail(result, "timeout", "The requested Wi-Fi network did not assign an address.");
            };
            main.postDelayed(timeout, 50000);
        }

        private static boolean hasAddress(LinkProperties links) {
            for (LinkAddress assigned : links.getLinkAddresses()) {
                InetAddress address = assigned.getAddress();
                if (!address.isAnyLocalAddress() && !address.isLinkLocalAddress() && !address.isLoopbackAddress()) return true;
            }
            return false;
        }

        private static void fail(HuxerUIPlatformChannel.Result result, String reason, String message) {
            result.fail("localnetwork/wifi-" + reason, message, PlatformPayload.nullValue());
        }

        private void clearTimeout() {
            if (timeout != null) main.removeCallbacks(timeout);
            timeout = null;
        }

        private void stopScan() {
            clearTimeout();
            if (scan != null) context.unregisterReceiver(scan);
            scan = null;
        }

        @Override public void dispose() {
            stopScan();
            ConnectivityManager.NetworkCallback callback = request;
            request = null;
            selected = null;
            joined = false;
            if (callback != null) {
                try { connectivity.unregisterNetworkCallback(callback); }
                catch (IllegalArgumentException ignored) { /* The system may already have released it. */ }
            }
        }
    }
}
