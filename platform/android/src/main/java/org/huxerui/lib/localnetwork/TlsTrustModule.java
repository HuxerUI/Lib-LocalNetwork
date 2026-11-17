package org.huxerui.lib.localnetwork;

import android.content.Context;
import android.net.http.X509TrustManagerExtensions;
import android.os.Handler;
import android.os.Looper;

import org.huxerui.HuxerUIPlatformChannel;
import org.huxerui.HuxerUIPlatformModule;
import org.huxerui.PlatformPayload;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.FutureTask;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public final class TlsTrustModule implements HuxerUIPlatformModule.Factory {
    private static final ThreadPoolExecutor workers = new ThreadPoolExecutor(
            0, 2, 30, TimeUnit.SECONDS, new ArrayBlockingQueue<>(8));

    @Override
    public HuxerUIPlatformModule create(Context context, PlatformPayload options, HuxerUIPlatformChannel.Events events) {
        return new Session();
    }

    private static final class Session implements HuxerUIPlatformModule {
        private final Handler main = new Handler(Looper.getMainLooper());

        @Override
        public HuxerUIPlatformChannel.Cancellation invoke(
                String method, PlatformPayload arguments, HuxerUIPlatformChannel.Result result) {
            if (!"verify".equals(method)) {
                result.fail("localnetwork/tls-trust", "Unknown TLS trust operation.", PlatformPayload.nullValue());
                return null;
            }
            try {
                FutureTask<Void> work = new FutureTask<>(() -> {
                    try {
                        verify(arguments);
                        main.post(() -> result.complete(PlatformPayload.nullValue()));
                    } catch (GeneralSecurityException | RuntimeException invalid) {
                        main.post(() -> result.fail("localnetwork/tls-trust",
                                "Android did not trust the TLS server certificate chain.", PlatformPayload.nullValue()));
                    }
                }, null);
                workers.execute(work);
                return () -> {
                    work.cancel(true);
                    workers.remove(work);
                };
            } catch (RejectedExecutionException full) {
                result.fail("localnetwork/tls-busy", "Too many TLS certificate checks are pending.", PlatformPayload.nullValue());
                return null;
            }
        }

        @Override public void dispose() {}
    }

    private static void verify(PlatformPayload arguments) throws GeneralSecurityException {
        List<PlatformPayload> encoded = arguments.requireField("chain").elements();
        CertificateFactory parser = CertificateFactory.getInstance("X.509");
        X509Certificate[] chain = new X509Certificate[encoded.size()];
        for (int index = 0; index < chain.length; ++index) {
            chain[index] = (X509Certificate) parser.generateCertificate(
                    new ByteArrayInputStream(encoded.get(index).requireBytes()));
        }
        String algorithm = chain[0].getPublicKey().getAlgorithm();
        String authType = algorithm.equals("EC") ? "ECDSA" : algorithm;
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init((KeyStore) null);
        for (TrustManager manager : factory.getTrustManagers()) {
            if (manager instanceof X509TrustManager) {
                // Passing the name selects the app's trust configuration for this server.
                new X509TrustManagerExtensions((X509TrustManager) manager).checkServerTrusted(
                        chain, authType, arguments.requireField("host").requireString());
                return;
            }
        }
        throw new GeneralSecurityException("Android does not provide a default X.509 trust manager.");
    }
}
