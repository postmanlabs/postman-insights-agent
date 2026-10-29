package com.postman.insights.agent;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;

/** Drives a client and a server engine against each other in memory. */
final class EnginePair {
    final SSLEngine client;
    final SSLEngine server;
    /** Records in flight from the client to the server, ready for writing. */
    final ByteBuffer toServer;
    /** Records in flight from the server to the client, ready for writing. */
    final ByteBuffer toClient;

    EnginePair(SSLEngine client, SSLEngine server) {
        this.client = client;
        this.server = server;
        int size = Math.max(client.getSession().getPacketBufferSize(), server.getSession().getPacketBufferSize());
        toServer = ByteBuffer.allocate(size * 4);
        toClient = ByteBuffer.allocate(size * 4);
    }

    EnginePair handshake() throws Exception {
        client.beginHandshake();
        server.beginHandshake();
        ByteBuffer empty = ByteBuffer.allocate(0);
        ByteBuffer sink = ByteBuffer.allocate(64 * 1024);
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (!done(client) || !done(server)) {
            assertTrue(System.nanoTime() < deadline, "handshake did not finish");
            step(client, empty, toServer, toClient, sink);
            step(server, empty, toClient, toServer, sink);
        }
        // Deliver what the server sent after its handshake (TLS 1.3 session
        // tickets), so later records arrive in a clean buffer.
        drain(toClient, client, sink);
        return this;
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
                runTasks(e);
                break;
            default:
                break;
        }
    }

    private static void runTasks(SSLEngine e) {
        for (Runnable r; (r = e.getDelegatedTask()) != null; ) {
            r.run();
        }
    }

    private static void drain(ByteBuffer in, SSLEngine to, ByteBuffer sink) throws Exception {
        in.flip();
        while (in.hasRemaining()) {
            SSLEngineResult r = to.unwrap(in, sink);
            runTasks(to);
            if (r.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                break;
            }
        }
        in.compact();
        sink.clear();
    }

    /**
     * Closes {@code from}'s outbound side and delivers its close_notify to
     * the peer. Returns the peer's unwrap result.
     */
    SSLEngineResult closeOutbound(SSLEngine from) throws Exception {
        SSLEngine to = peer(from);
        ByteBuffer out = outbound(from);
        from.closeOutbound();
        SSLEngineResult r = from.wrap(ByteBuffer.allocate(0), out);
        assertTrue(r.getStatus() == SSLEngineResult.Status.CLOSED, "wrap after closeOutbound: " + r);
        out.flip();
        SSLEngineResult got = to.unwrap(out, ByteBuffer.allocate(to.getSession().getApplicationBufferSize()));
        out.compact();
        return got;
    }

    /** The in-flight buffer for records sent by {@code from}. */
    ByteBuffer outbound(SSLEngine from) {
        return from == client ? toServer : toClient;
    }

    SSLEngine peer(SSLEngine e) {
        return e == client ? server : client;
    }

    /** Sends text from one engine to the other with the 2-arg forms and returns what arrived. */
    String send(SSLEngine from, String text) throws Exception {
        SSLEngine to = peer(from);
        ByteBuffer out = outbound(from);
        ByteBuffer src = ByteBuffer.wrap(text.getBytes(StandardCharsets.ISO_8859_1));
        ByteBuffer dst = ByteBuffer.allocate(text.length() + to.getSession().getApplicationBufferSize());
        while (src.hasRemaining()) {
            from.wrap(src, out);
            out.flip();
            while (out.hasRemaining()) {
                SSLEngineResult r = to.unwrap(out, dst);
                runTasks(to);
                if (r.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                    break;
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
