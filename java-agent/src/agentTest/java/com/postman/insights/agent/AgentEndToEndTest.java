package com.postman.insights.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Runs in a JVM started with {@code -javaagent:postman-java-agent.jar=cap=4096}
 * and the frame log (see build.gradle.kts), and checks the frames the agent
 * writes for real TLS traffic through the JDK's own SSLEngine.
 */
class AgentEndToEndTest {
    private static final int CAP = 4096;
    private static final byte OP_SEND = 1;
    private static final byte OP_RECV = 2;
    private static final short ROLE_KNOWN = 0x1;
    private static final short CLIENT_MODE = 0x2;

    @TempDir
    static File dir;
    private static SSLContext tls;
    private static File log;
    private long logStart;

    static final class LoggedFrame {
        byte op;
        short flags;
        long connId;
        int totalLen;
        byte[] payload;

        String text() {
            return new String(payload, StandardCharsets.ISO_8859_1);
        }
    }

    @BeforeAll
    static void setUp() throws Exception {
        log = new File(System.getProperty("frames.log"));
        tls = selfSignedContext(dir);
    }

    @BeforeEach
    void markLog() {
        logStart = log.exists() ? log.length() : 0;
    }

    @Test
    void agentIsLoadedOnce() {
        assertNotNull(System.getProperty("postman.insights.agent.version"));
        assertNull(System.getProperty("postman.insights.agent.failed"));
        // The agent's internals are invisible to application code.
        assertThrows(ClassNotFoundException.class,
                () -> Class.forName("com.postman.insights.agent.installer.Installer"));
        assertThrows(ClassNotFoundException.class, () -> Class.forName("net.bytebuddy.ByteBuddy"));
        // Byte Buddy's Nexus must not be injected into the application class loader.
        assertThrows(ClassNotFoundException.class, () -> Class.forName("net.bytebuddy.dynamic.Nexus"));
        assertNull(System.getProperty("net.bytebuddy.nexus.disabled"));
    }

    @Test
    void engineTrafficBothRoles() throws Exception {
        SSLEngine client = tls.createSSLEngine("localhost", 443);
        client.setUseClientMode(true);
        SSLEngine server = tls.createSSLEngine();
        server.setUseClientMode(false);
        Pair p = new Pair(client, server);
        p.handshake();

        String request = "GET /hello HTTP/1.1\r\nHost: localhost\r\n\r\n";
        String response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
        assertEquals(request, p.send(client, server, request));
        assertEquals(response, p.send(server, client, response));

        List<LoggedFrame> frames = appData(newFrames());
        LoggedFrame clientSend = find(frames, OP_SEND, request);
        LoggedFrame serverRecv = find(frames, OP_RECV, request);
        LoggedFrame serverSend = find(frames, OP_SEND, response);
        LoggedFrame clientRecv = find(frames, OP_RECV, response);

        assertEquals(ROLE_KNOWN | CLIENT_MODE, clientSend.flags);
        assertEquals(ROLE_KNOWN, serverRecv.flags);
        assertEquals(clientSend.connId, clientRecv.connId);
        assertEquals(serverSend.connId, serverRecv.connId);
        assertNotEquals(clientSend.connId, serverSend.connId);
    }

    @Test
    void largeWritesAreCappedWithTotalKept() throws Exception {
        SSLEngine client = tls.createSSLEngine("localhost", 443);
        client.setUseClientMode(true);
        SSLEngine server = tls.createSSLEngine();
        server.setUseClientMode(false);
        Pair p = new Pair(client, server);
        p.handshake();

        char[] big = new char[10000];
        Arrays.fill(big, 'b');
        String body = "POST /upload HTTP/1.1\r\nContent-Length: 10000\r\n\r\n" + new String(big);
        assertEquals(body, p.send(client, server, body));

        boolean sawCapped = false;
        for (LoggedFrame f : newFrames()) {
            assertTrue(f.payload.length <= CAP, "payload above the cap");
            assertTrue(f.totalLen >= f.payload.length);
            if (f.op == OP_SEND && f.text().startsWith("POST /upload") && f.totalLen > CAP) {
                assertEquals(CAP, f.payload.length);
                sawCapped = true;
            }
        }
        assertTrue(sawCapped, "no capped frame for the large request");
    }

    @Test
    void httpsServerRequestAndResponse() throws Exception {
        HttpsServer server = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(tls));
        server.createContext("/hello", ex -> {
            byte[] out = "{\"hello\":\"world\"}".getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("Content-Type", "application/json");
            ex.sendResponseHeaders(200, out.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(out);
            }
        });
        server.start();
        try {
            HttpsURLConnection conn = (HttpsURLConnection) new URL(
                    "https://localhost:" + server.getAddress().getPort() + "/hello?x=1").openConnection();
            conn.setSSLSocketFactory(tls.getSocketFactory());
            conn.setHostnameVerifier((host, session) -> true);
            assertEquals(200, conn.getResponseCode());
            try (InputStream in = conn.getInputStream()) {
                assertEquals("{\"hello\":\"world\"}", new String(readAll(in), StandardCharsets.UTF_8));
            }
        } finally {
            server.stop(0);
        }

        // HttpsServer uses SSLEngine; the client (SSLSocket) is not hooked yet.
        List<LoggedFrame> frames = newFrames();
        LoggedFrame req = findPrefix(frames, OP_RECV, "GET /hello?x=1 HTTP/1.1");
        LoggedFrame resp = findPrefix(frames, OP_SEND, "HTTP/1.1 200 OK");
        assertEquals(req.connId, resp.connId);
        assertEquals(ROLE_KNOWN, req.flags);
        boolean sawBody = false;
        for (LoggedFrame f : frames) {
            sawBody |= f.op == OP_SEND && f.connId == resp.connId && f.text().contains("{\"hello\":\"world\"}");
        }
        assertTrue(sawBody, "response body not captured");
    }

    // --- helpers ---

    /** Drives two engines against each other in memory. */
    private static final class Pair {
        final SSLEngine a;
        final SSLEngine b;
        final ByteBuffer aToB;
        final ByteBuffer bToA;

        Pair(SSLEngine a, SSLEngine b) {
            this.a = a;
            this.b = b;
            SSLSession s = a.getSession();
            aToB = ByteBuffer.allocate(s.getPacketBufferSize() * 4);
            bToA = ByteBuffer.allocate(s.getPacketBufferSize() * 4);
        }

        void handshake() throws Exception {
            a.beginHandshake();
            b.beginHandshake();
            ByteBuffer empty = ByteBuffer.allocate(0);
            ByteBuffer sink = ByteBuffer.allocate(a.getSession().getApplicationBufferSize() * 2);
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
            while (!done(a) || !done(b)) {
                assertTrue(System.nanoTime() < deadline, "handshake did not finish");
                step(a, empty, aToB, bToA, sink);
                step(b, empty, bToA, aToB, sink);
            }
        }

        private static boolean done(SSLEngine e) {
            SSLEngineResult.HandshakeStatus hs = e.getHandshakeStatus();
            return hs == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING
                    || hs == SSLEngineResult.HandshakeStatus.FINISHED;
        }

        private static void step(SSLEngine e, ByteBuffer empty, ByteBuffer out, ByteBuffer in, ByteBuffer sink)
                throws Exception {
            switch (e.getHandshakeStatus()) {
                case NEED_WRAP:
                    e.wrap(empty, out);
                    break;
                case NEED_UNWRAP:
                    in.flip();
                    e.unwrap(in, sink);
                    in.compact();
                    break;
                case NEED_TASK:
                    for (Runnable r; (r = e.getDelegatedTask()) != null; ) {
                        r.run();
                    }
                    break;
                default:
                    break;
            }
        }

        /**
         * Sends text from one engine to the other and returns what arrived.
         * Uses the same in-flight buffers as the handshake, so records still
         * queued from it (such as TLS 1.3 session tickets) are delivered first,
         * in order.
         */
        String send(SSLEngine from, SSLEngine to, String text) throws Exception {
            ByteBuffer out = from == a ? aToB : bToA;
            ByteBuffer src = ByteBuffer.wrap(text.getBytes(StandardCharsets.ISO_8859_1));
            ByteBuffer dst = ByteBuffer.allocate(text.length() + to.getSession().getApplicationBufferSize());
            while (src.hasRemaining()) {
                from.wrap(src, out);
                out.flip();
                while (out.hasRemaining()) {
                    SSLEngineResult r = to.unwrap(out, dst);
                    if (r.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                        break;
                    }
                    for (Runnable task; (task = to.getDelegatedTask()) != null; ) {
                        task.run();
                    }
                }
                out.compact();
            }
            dst.flip();
            byte[] got = new byte[dst.remaining()];
            dst.get(got);
            return new String(got, StandardCharsets.ISO_8859_1);
        }
    }

    private List<LoggedFrame> newFrames() throws Exception {
        byte[] all = Files.readAllBytes(log.toPath());
        ByteBuffer b = ByteBuffer.wrap(all).order(ByteOrder.LITTLE_ENDIAN);
        b.position((int) logStart);
        List<LoggedFrame> out = new ArrayList<LoggedFrame>();
        while (b.remaining() >= 40) {
            int start = b.position();
            assertEquals(1, b.get(start), "frame version");
            LoggedFrame f = new LoggedFrame();
            f.op = b.get(start + 1);
            f.flags = b.getShort(start + 2);
            int len = b.getInt(start + 4);
            f.connId = b.getLong(start + 8);
            f.totalLen = b.getInt(start + 36);
            f.payload = Arrays.copyOfRange(all, start + 40, start + 40 + len);
            b.position(start + 40 + len);
            out.add(f);
        }
        assertEquals(0, b.remaining(), "trailing bytes in the frame log");
        return out;
    }

    /** Drops frames that carry no application data (none expected, but be explicit). */
    private static List<LoggedFrame> appData(List<LoggedFrame> frames) {
        List<LoggedFrame> out = new ArrayList<LoggedFrame>();
        for (LoggedFrame f : frames) {
            if (f.payload.length > 0) {
                out.add(f);
            }
        }
        assertFalse(out.isEmpty(), "no frames written");
        return out;
    }

    private static LoggedFrame find(List<LoggedFrame> frames, byte op, String text) {
        for (LoggedFrame f : frames) {
            if (f.op == op && f.text().equals(text)) {
                return f;
            }
        }
        throw new AssertionError("no op " + op + " frame with " + text.trim() + " in " + frames.size() + " frames");
    }

    private static LoggedFrame findPrefix(List<LoggedFrame> frames, byte op, String prefix) {
        for (LoggedFrame f : frames) {
            if (f.op == op && f.text().startsWith(prefix)) {
                return f;
            }
        }
        throw new AssertionError("no op " + op + " frame starting with " + prefix + " in " + frames.size() + " frames");
    }

    private static byte[] readAll(InputStream in) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        for (int n; (n = in.read(buf)) > 0; ) {
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    /** A self-signed localhost certificate, made with the running JDK's keytool. */
    private static SSLContext selfSignedContext(File dir) throws Exception {
        File ks = new File(dir, "test.p12");
        char[] pw = "changeit".toCharArray();
        String keytool = new File(System.getProperty("java.home"), "bin/keytool").getAbsolutePath();
        Process p = new ProcessBuilder(keytool, "-genkeypair", "-alias", "test", "-keyalg", "RSA", "-keysize", "2048",
                "-dname", "CN=localhost", "-ext", "SAN=dns:localhost,ip:127.0.0.1", "-validity", "2",
                "-storetype", "PKCS12", "-keystore", ks.getAbsolutePath(), "-storepass", "changeit")
                .redirectErrorStream(true).start();
        String output = new String(readAll(p.getInputStream()), StandardCharsets.UTF_8);
        assertEquals(0, p.waitFor(), "keytool failed: " + output);

        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = new FileInputStream(ks)) {
            store.load(in, pw);
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(store, pw);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(store);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return ctx;
    }
}
