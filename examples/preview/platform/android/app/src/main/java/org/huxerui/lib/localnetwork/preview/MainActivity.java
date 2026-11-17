package org.huxerui.lib.localnetwork.preview;

import android.Manifest;
import android.content.pm.PackageManager;

import org.huxerui.HuxerUIActivity;
import org.huxerui.HuxerUIPlatformChannel;
import org.huxerui.PlatformPayload;

public final class MainActivity extends HuxerUIActivity {
    private static final int NEARBY_WIFI_REQUEST = 0x5700;
    private HuxerUIPlatformChannel.Result nearbyWifiResult;
    private boolean nearbyWifiPending;

    HuxerUIPlatformChannel.Cancellation requestNearbyWifi(HuxerUIPlatformChannel.Result result) {
        String permission = Manifest.permission.NEARBY_WIFI_DEVICES;
        if (checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED) {
            result.complete(PlatformPayload.string("granted"));
            return null;
        }
        if (nearbyWifiPending) {
            result.complete(PlatformPayload.string("unavailable"));
            return null;
        }
        nearbyWifiPending = true;
        nearbyWifiResult = result;
        try {
            requestPermissions(new String[]{permission}, NEARBY_WIFI_REQUEST);
        } catch (RuntimeException unavailable) {
            completeNearbyWifi("unavailable");
            return null;
        }
        // Android owns the prompt. Keep its request code reserved until it returns, even after task cancellation.
        return () -> {
            if (nearbyWifiResult == result) nearbyWifiResult = null;
        };
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] results) {
        if (requestCode == NEARBY_WIFI_REQUEST) {
            boolean granted = results.length > 0 && results[0] == PackageManager.PERMISSION_GRANTED;
            completeNearbyWifi(granted ? "granted" : "denied");
            return;
        }
        super.onRequestPermissionsResult(requestCode, permissions, results);
    }

    @Override
    protected void onDestroy() {
        completeNearbyWifi("unavailable");
        super.onDestroy();
    }

    private void completeNearbyWifi(String status) {
        HuxerUIPlatformChannel.Result result = nearbyWifiResult;
        nearbyWifiResult = null;
        nearbyWifiPending = false;
        if (result != null) result.complete(PlatformPayload.string(status));
    }
}
