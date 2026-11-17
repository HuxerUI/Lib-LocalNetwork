package org.huxerui.lib.localnetwork;

import android.net.Network;
import android.os.Handler;

import org.huxerui.HuxerUIPlatformChannel;
import org.huxerui.PlatformPayload;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

final class WifiHttpRequest implements Runnable {
    private static final int MAX_BODY = 1024 * 1024;
    private static final ThreadPoolExecutor requests = new ThreadPoolExecutor(
            0, 4, 30, TimeUnit.SECONDS, new ArrayBlockingQueue<>(4));

    private final Network network;
    private final PlatformPayload arguments;
    private final HuxerUIPlatformChannel.Result result;
    private final Handler main;
    private final Consumer<WifiHttpRequest> finished;
    private final int timeout;
    private final Runnable deadline = () -> fail("timeout", "The accessory HTTP request timed out.");
    private final AtomicReference<HttpURLConnection> connection = new AtomicReference<>();
    private volatile boolean stopped;

    WifiHttpRequest(Network network, PlatformPayload arguments, HuxerUIPlatformChannel.Result result,
                    Handler main, Consumer<WifiHttpRequest> finished) {
        this.network = network;
        this.arguments = arguments;
        this.result = result;
        this.main = main;
        this.finished = finished;
        this.timeout = (int) arguments.requireField("timeout").requireInt64();
    }

    void start() {
        try {
            requests.execute(this);
            main.postDelayed(deadline, timeout);
        } catch (RejectedExecutionException full) {
            fail("failed", "Too many accessory HTTP requests are pending.");
        }
    }

    void cancel() {
        if (!stop()) return;
        // Disconnect on a worker. Canceled I/O must not block the application thread.
        HttpURLConnection active = connection.getAndSet(null);
        if (active != null) new Thread(active::disconnect, "LocalNetwork HTTP disconnect").start();
    }

    void networkLost() {
        fail("lost", "The selected Wi-Fi network was lost.");
    }

    private boolean stop() {
        if (stopped) return false;
        stopped = true;
        main.removeCallbacks(deadline);
        requests.remove(this);
        finished.accept(this);
        return true;
    }

    private void fail(String reason, String message) {
        if (stopped) return;
        cancel();
        result.fail("localnetwork/wifi-" + reason, message, PlatformPayload.nullValue());
    }

    @Override public void run() {
        if (stopped) return;
        HttpURLConnection active = null;
        try {
            URL url = new URL(arguments.requireField("url").requireString());
            if (url.getHost().isEmpty() || url.getUserInfo() != null) throw new IOException("Invalid HTTP target");
            // Use only this Network's DNS and connection factory. Leave redirects to the caller.
            active = (HttpURLConnection) network.openConnection(url, Proxy.NO_PROXY);
            connection.set(active);
            if (stopped) return;
            active.setConnectTimeout(timeout);
            active.setReadTimeout(timeout);
            active.setUseCaches(false);
            active.setInstanceFollowRedirects(false);
            active.setRequestMethod(arguments.requireField("method").requireString());
            for (PlatformPayload field : arguments.requireField("headers").elements()) {
                active.addRequestProperty(field.requireField("name").requireString(),
                        field.requireField("value").requireString());
            }
            byte[] upload = arguments.requireField("body").requireBytes();
            if (upload.length > 0) {
                active.setDoOutput(true);
                active.setFixedLengthStreamingMode(upload.length);
                try (OutputStream out = active.getOutputStream()) {
                    out.write(upload);
                }
            }
            int status = active.getResponseCode();
            if (status < 100 || status > 599) throw new IOException("Invalid HTTP status");
            Map<String, PlatformPayload> response = new LinkedHashMap<>();
            response.put("status", PlatformPayload.int64(status));
            response.put("headers", PlatformPayload.list(responseHeaders(active)));
            response.put("body", PlatformPayload.bytes(responseBody(active, status)));
            PlatformPayload payload = PlatformPayload.object(response);
            main.post(() -> { if (stop()) result.complete(payload); });
        } catch (SocketTimeoutException expired) {
            main.post(() -> fail("timeout", "The accessory HTTP request timed out."));
        } catch (IOException | RuntimeException failed) {
            main.post(() -> fail("failed", "The accessory HTTP request failed or exceeded the response limits."));
        } finally {
            if (active != null && connection.compareAndSet(active, null)) active.disconnect();
        }
    }

    private static List<PlatformPayload> responseHeaders(HttpURLConnection active) throws IOException {
        List<PlatformPayload> headers = new ArrayList<>();
        int size = 0;
        for (Map.Entry<String, List<String>> entry : active.getHeaderFields().entrySet()) {
            if (entry.getKey() == null) continue;
            for (String text : entry.getValue()) {
                size += entry.getKey().length() + text.length();
                if (size > 65536 || headers.size() == 128) throw new IOException("HTTP headers exceed the limit");
                Map<String, PlatformPayload> header = new LinkedHashMap<>();
                header.put("name", PlatformPayload.string(entry.getKey()));
                header.put("value", PlatformPayload.string(text));
                headers.add(PlatformPayload.object(header));
            }
        }
        return headers;
    }

    private byte[] responseBody(HttpURLConnection active, int status) throws IOException {
        if (arguments.requireField("method").requireString().equals("HEAD") || status == 204 || status == 304) {
            return new byte[0];
        }
        if (active.getContentLengthLong() > MAX_BODY) throw new IOException("HTTP body exceeds the limit");
        try (InputStream input = status < 400 ? active.getInputStream() : active.getErrorStream();
             ByteArrayOutputStream body = new ByteArrayOutputStream()) {
            if (input == null) return new byte[0];
            byte[] buffer = new byte[8192];
            int count;
            while (!stopped && (count = input.read(buffer)) != -1) {
                if (count > MAX_BODY - body.size()) throw new IOException("HTTP body exceeds the limit");
                body.write(buffer, 0, count);
            }
            return body.toByteArray();
        }
    }
}
