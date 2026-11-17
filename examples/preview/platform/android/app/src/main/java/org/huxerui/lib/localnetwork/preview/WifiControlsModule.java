package org.huxerui.lib.localnetwork.preview;

import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.os.Build;
import android.provider.Settings;

import org.huxerui.HuxerUIPlatformChannel;
import org.huxerui.HuxerUIPlatformModule;
import org.huxerui.HuxerUIView;
import org.huxerui.PlatformPayload;

public final class WifiControlsModule implements HuxerUIPlatformModule.WindowFactory {
    @Override
    public HuxerUIPlatformModule create(HuxerUIView window, PlatformPayload options,
                                        HuxerUIPlatformChannel.Events events) {
        return new Controls((MainActivity) window.getContext());
    }

    private static final class Controls implements HuxerUIPlatformModule {
        private final MainActivity activity;

        Controls(MainActivity activity) {
            this.activity = activity;
        }

        @Override
        public HuxerUIPlatformChannel.Cancellation invoke(String method, PlatformPayload arguments,
                                                          HuxerUIPlatformChannel.Result result) {
            if ("joinPermission".equals(method)) {
                if (Build.VERSION.SDK_INT >= 33) return activity.requestNearbyWifi(result);
                result.complete(PlatformPayload.string("location"));
            } else if ("wifiSettings".equals(method)) {
                boolean opened = false;
                try {
                    activity.startActivity(new Intent(Settings.ACTION_WIFI_SETTINGS));
                    opened = true;
                } catch (ActivityNotFoundException | SecurityException ignored) {
                    // Preview will show the manual path to the system Wi-Fi settings.
                }
                result.complete(PlatformPayload.booleanValue(opened));
            } else {
                result.fail("localnetwork/wifi-controls", "Unknown Wi-Fi control.", PlatformPayload.nullValue());
            }
            return null;
        }

        @Override public void dispose() {}
    }
}
