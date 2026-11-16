package org.huxerui.lib.localnetwork.preview;

import android.app.Activity;
import android.content.ClipData;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.provider.MediaStore;

import androidx.core.content.FileProvider;

import org.huxerui.HuxerUIActivityResultLauncher;
import org.huxerui.HuxerUIPlatformChannel;
import org.huxerui.HuxerUIPlatformModule;
import org.huxerui.HuxerUIView;
import org.huxerui.PlatformPayload;

import java.io.File;

public final class QrCameraModule implements HuxerUIPlatformModule.WindowFactory {
    @Override
    public HuxerUIPlatformModule create(HuxerUIView window, PlatformPayload options,
                                        HuxerUIPlatformChannel.Events events) {
        return new Camera(window.getContext(), window.getActivityResultLauncher());
    }

    private static final class Camera implements HuxerUIPlatformModule {
        private final Context context;
        private final HuxerUIActivityResultLauncher launcher;

        Camera(Context context, HuxerUIActivityResultLauncher launcher) {
            this.context = context;
            this.launcher = launcher;
        }

        @Override
        public HuxerUIPlatformChannel.Cancellation invoke(String method, PlatformPayload arguments,
                                                          HuxerUIPlatformChannel.Result result) {
            if (!"capture".equals(method)) {
                result.fail("localnetwork/camera", "Unknown QR camera operation.", PlatformPayload.nullValue());
                return null;
            }
            try {
                File output = new File(arguments.requireString());
                Uri uri = FileProvider.getUriForFile(context, context.getPackageName() + ".qrimages", output);
                Intent intent = new Intent(MediaStore.ACTION_IMAGE_CAPTURE);
                intent.putExtra(MediaStore.EXTRA_OUTPUT, uri);
                // Provide a single writable output instead of asking the camera for a low-resolution thumbnail.
                intent.setClipData(ClipData.newRawUri("QR capture", uri));
                intent.addFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION | Intent.FLAG_GRANT_READ_URI_PERMISSION);
                return launcher.launch(intent, new HuxerUIActivityResultLauncher.Callback() {
                    @Override public void onResult(int resultCode, Intent data) {
                        result.complete(PlatformPayload.booleanValue(resultCode == Activity.RESULT_OK && output.length() > 0));
                    }

                    @Override public void onFailure(RuntimeException error) {
                        result.fail("localnetwork/camera", "Could not open the system camera.", PlatformPayload.nullValue());
                    }
                });
            } catch (RuntimeException error) {
                result.fail("localnetwork/camera", "Could not prepare the QR capture.", PlatformPayload.nullValue());
                return null;
            }
        }

        @Override public void dispose() {}
    }
}
