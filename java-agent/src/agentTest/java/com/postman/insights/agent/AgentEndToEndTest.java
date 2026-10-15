package com.postman.insights.agent;

import static com.postman.insights.agent.Frames.CLIENT_MODE;
import static com.postman.insights.agent.Frames.OP_CLOSE;
import static com.postman.insights.agent.Frames.OP_HEARTBEAT;
import static com.postman.insights.agent.Frames.OP_RECV;
import static com.postman.insights.agent.Frames.OP_SEND;
import static com.postman.insights.agent.Frames.ROLE_KNOWN;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLEngine;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.postman.insights.agent.Frames.Frame;

/**
 * Runs in a JVM started with {@code -javaagent:postman-java-agent.jar=cap=4096},
 * the frame log and a control file that enables capture (see
 * build.gradle.kts), and checks the frames the agent writes for real TLS
 * traffic through the JDK's own SSLEngine.
 */
class AgentEndToEndTest {
    private static final int CAP = 4096;
    private final Frames frames = new Frames();

    @BeforeEach
    void setUp() throws Exception {
        Control.enable();
        frames.mark();
    }

    private static EnginePair jdkPair() throws Exception {
        SSLEngine client = Tls.get().context.createSSLEngine("localhost", 443);
        client.setUseClientMode(true);
        SSLEngine server = Tls.get().context.createSSLEngine();
        server.setUseClientMode(false);
        return new EnginePair(client, server).handshake();
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
    void agentThreadIsADaemon() {
        boolean found = false;
        for (Thread t : Thread.getAllStackTraces().keySet()) {
            if (t.getName().equals("postman-insights-agent")) {
                found = true;
                assertTrue(t.isDaemon(), "the agent thread would keep the JVM alive");
                assertNull(t.getContextClassLoader());
            }
        }
        assertTrue(found, "agent thread not running");
    }

    @Test
    void heartbeatAtStart() throws Exception {
        Frame heartbeat = null;
        for (Frame f : Frames.all()) {
            if (f.op == OP_HEARTBEAT) {
                heartbeat = f;
                break;
            }
        }
        assertNotNull(heartbeat, "no HEARTBEAT frame");
        assertEquals(0, heartbeat.connId);
        String text = new String(heartbeat.payload, StandardCharsets.UTF_8);
        assertTrue(text.startsWith("agent_version=" + System.getProperty("postman.insights.agent.version") + "\n"
                + "java_version=" + System.getProperty("java.version") + "\n"), text);
        assertTrue(text.contains("\nsource=static\nstate=active\n"), text);
    }

    @Test
    void engineTrafficBothRoles() throws Exception {
        EnginePair p = jdkPair();
        String request = "GET /hello HTTP/1.1\r\nHost: localhost\r\n\r\n";
        String response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
        assertEquals(request, p.send(p.client, request));
        assertEquals(response, p.send(p.server, response));

        List<Frame> got = frames.traffic();
        Frame clientSend = Frames.find(got, OP_SEND, request);
        Frame serverRecv = Frames.find(got, OP_RECV, request);
        Frame serverSend = Frames.find(got, OP_SEND, response);
        Frame clientRecv = Frames.find(got, OP_RECV, response);
        assertEquals(4, got.size(), got.toString());

        assertEquals(ROLE_KNOWN | CLIENT_MODE, clientSend.flags);
        assertEquals(ROLE_KNOWN, serverRecv.flags);
        assertEquals(clientSend.connId, clientRecv.connId);
        assertEquals(serverSend.connId, serverRecv.connId);
        assertNotEquals(clientSend.connId, serverSend.connId);
    }

    /**
     * The server closing the connection sends one CLOSE per engine: the
     * server's once its outbound side is closed, the client's once the
     * server's close_notify arrives.
     */
    @Test
    void closeFramesWhenTheServerCloses() throws Exception {
        EnginePair p = jdkPair();
        String request = "GET /bye HTTP/1.1\r\nHost: localhost\r\n\r\n";
        String response = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nbye";
        p.send(p.client, request);
        p.send(p.server, response);
        List<Frame> traffic = frames.traffic();
        long serverConn = Frames.find(traffic, OP_RECV, request).connId;
        long clientConn = Frames.find(traffic, OP_SEND, request).connId;

        assertEquals(javax.net.ssl.SSLEngineResult.Status.CLOSED, p.closeOutbound(p.server).getStatus());
        List<Frame> closes = new java.util.ArrayList<Frame>();
        for (Frame f : frames.read()) {
            if (f.op == OP_CLOSE) {
                closes.add(f);
            }
        }
        assertEquals(2, closes.size(), closes.toString());
        assertEquals(serverConn, closes.get(0).connId);
        assertEquals(ROLE_KNOWN, closes.get(0).flags);
        assertEquals(clientConn, closes.get(1).connId);
        assertEquals(ROLE_KNOWN | CLIENT_MODE, closes.get(1).flags);
        assertEquals(0, closes.get(1).payload.length);

        // Later calls on the closed engines send nothing more.
        frames.mark();
        p.server.wrap(java.nio.ByteBuffer.allocate(0), java.nio.ByteBuffer.allocate(p.server.getSession().getPacketBufferSize()));
        assertEquals(0, frames.read().size());
    }

    @Test
    void largeWritesAreCappedWithTotalKept() throws Exception {
        EnginePair p = jdkPair();
        char[] big = new char[10000];
        Arrays.fill(big, 'b');
        String body = "POST /upload HTTP/1.1\r\nContent-Length: 10000\r\n\r\n" + new String(big);
        assertEquals(body, p.send(p.client, body));

        boolean sawCapped = false;
        for (Frame f : frames.traffic()) {
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
        server.setHttpsConfigurator(new HttpsConfigurator(Tls.get().context));
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
            conn.setSSLSocketFactory(Tls.get().context.getSocketFactory());
            conn.setHostnameVerifier((host, session) -> true);
            assertEquals(200, conn.getResponseCode());
            try (InputStream in = conn.getInputStream()) {
                assertEquals("{\"hello\":\"world\"}", new String(Tls.readAll(in), StandardCharsets.UTF_8));
            }
        } finally {
            server.stop(0);
        }

        // HttpsServer uses SSLEngine; the client (SSLSocket) is not hooked yet.
        List<Frame> got = frames.traffic();
        Frame req = Frames.findPrefix(got, OP_RECV, "GET /hello?x=1 HTTP/1.1");
        Frame resp = Frames.findPrefix(got, OP_SEND, "HTTP/1.1 200 OK");
        assertEquals(req.connId, resp.connId);
        assertEquals(ROLE_KNOWN, req.flags);
        assertEquals(1, Frames.count(got, OP_RECV, "GET /hello?x=1"), got.toString());
        boolean sawBody = false;
        for (Frame f : got) {
            sawBody |= f.op == OP_SEND && f.connId == resp.connId && f.text().contains("{\"hello\":\"world\"}");
        }
        assertTrue(sawBody, "response body not captured");
    }

    /**
     * Without an enabling control file the agent is dormant, and it resumes
     * once the file enables it again. The agent checks the file every 5 s.
     */
    @Test
    void dormantWhileDisabled() throws Exception {
        EnginePair p = jdkPair();
        try {
            Control.disable();
            assertTrue(waitFor(() -> !captured(p, "probe")), "still capturing 12 s after enabled=0");
            for (int i = 0; i < 3; i++) {
                assertFalse(captured(p, "dormant-" + i));
            }

            Control.enable();
            assertTrue(waitFor(() -> captured(p, "probe")), "not capturing 12 s after enabled=1");
        } finally {
            Control.enable();
        }
    }

    /** Sends text from the client and says whether the agent captured it. */
    private static boolean captured(EnginePair p, String text) throws Exception {
        Frames f = new Frames().mark();
        assertEquals(text, p.send(p.client, text));
        return Frames.count(f.traffic(), OP_SEND, text) > 0;
    }

    interface Condition {
        boolean holds() throws Exception;
    }

    private static boolean waitFor(Condition c) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(12);
        while (System.nanoTime() < deadline) {
            if (c.holds()) {
                return true;
            }
            Thread.sleep(250);
        }
        return false;
    }
}
