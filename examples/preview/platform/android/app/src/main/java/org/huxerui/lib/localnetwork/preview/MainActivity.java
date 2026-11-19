package org.huxerui.lib.localnetwork.preview;

import android.Manifest;
import android.content.pm.PackageManager;
import android.os.Build;

import org.huxerui.HuxerUIActivity;
import org.huxerui.HuxerUIPlatformChannel;
import org.huxerui.PlatformPayload;

public final class MainActivity extends HuxerUIActivity {
    private static final int NEARBY_WIFI_REQUEST = 0x5700;
    private static final int LOCAL_NETWORK_REQUEST = 0x5701;
    private HuxerUIPlatformChannel.Result permissionResult;
    private int pendingPermissionRequest;

    HuxerUIPlatformChannel.Cancellation requestNearbyWifi(HuxerUIPlatformChannel.Result result) {
        return requestNetworkPermission(Manifest.permission.NEARBY_WIFI_DEVICES, NEARBY_WIFI_REQUEST, result);
    }

    HuxerUIPlatformChannel.Cancellation requestLocalNetwork(HuxerUIPlatformChannel.Result result) {
        if (Build.VERSION.SDK_INT < 37 || getApplicationInfo().targetSdkVersion < 37) {
            result.complete(PlatformPayload.string("granted"));
            return null;
        }
        return requestNetworkPermission(Manifest.permission.ACCESS_LOCAL_NETWORK, LOCAL_NETWORK_REQUEST, result);
    }

    private HuxerUIPlatformChannel.Cancellation requestNetworkPermission(
            String permission, int requestCode, HuxerUIPlatformChannel.Result result) {
        if (checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED) {
            result.complete(PlatformPayload.string("granted"));
            return null;
        }
        if (pendingPermissionRequest != 0) {
            result.complete(PlatformPayload.string("unavailable"));
            return null;
        }
        pendingPermissionRequest = requestCode;
        permissionResult = result;
        try {
            requestPermissions(new String[]{permission}, requestCode);
        } catch (RuntimeException unavailable) {
            completePermission("unavailable");
            return null;
        }
        // Android owns the prompt. Keep its request code reserved until it returns, even after task cancellation.
        return () -> {
            if (permissionResult == result) permissionResult = null;
        };
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] results) {
        if (requestCode == NEARBY_WIFI_REQUEST || requestCode == LOCAL_NETWORK_REQUEST) {
            if (pendingPermissionRequest == requestCode) {
                boolean granted = results.length > 0 && results[0] == PackageManager.PERMISSION_GRANTED;
                completePermission(granted ? "granted" : "denied");
            }
            return;
        }
        super.onRequestPermissionsResult(requestCode, permissions, results);
    }

    @Override
    protected void onDestroy() {
        completePermission("unavailable");
        super.onDestroy();
    }

    private void completePermission(String status) {
        HuxerUIPlatformChannel.Result result = permissionResult;
        permissionResult = null;
        pendingPermissionRequest = 0;
        if (result != null) result.complete(PlatformPayload.string(status));
    }
}
