package org.huxerui.lib.localnetwork.preview;

import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.net.Uri;
import android.provider.Settings;

import org.huxerui.HuxerUIPlatformChannel;
import org.huxerui.HuxerUIPlatformModule;
import org.huxerui.HuxerUIView;
import org.huxerui.PlatformPayload;

public final class LocalNetworkPermissionsModule implements HuxerUIPlatformModule.WindowFactory {
    @Override
    public HuxerUIPlatformModule create(HuxerUIView window, PlatformPayload options,
                                        HuxerUIPlatformChannel.Events events) {
        return new Permissions((MainActivity) window.getContext());
    }

    private static final class Permissions implements HuxerUIPlatformModule {
        private final MainActivity activity;

        Permissions(MainActivity activity) {
            this.activity = activity;
        }

        @Override
        public HuxerUIPlatformChannel.Cancellation invoke(String method, PlatformPayload arguments,
                                                          HuxerUIPlatformChannel.Result result) {
            if ("request".equals(method)) return activity.requestLocalNetwork(result);
            if ("settings".equals(method)) {
                boolean opened = false;
                try {
                    Uri app = Uri.fromParts("package", activity.getPackageName(), null);
                    activity.startActivity(new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, app));
                    opened = true;
                } catch (ActivityNotFoundException | SecurityException ignored) {
                    // Preview shows how to open the app's permissions manually.
                }
                result.complete(PlatformPayload.booleanValue(opened));
            } else {
                result.fail("localnetwork/permission", "Unknown local network permission operation.",
                        PlatformPayload.nullValue());
            }
            return null;
        }

        @Override public void dispose() {}
    }
}
