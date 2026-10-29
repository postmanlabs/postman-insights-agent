package com.postman.insights.agent;

import static com.postman.insights.agent.Frames.BEFORE_WRITE;
import static com.postman.insights.agent.Frames.CLIENT_MODE;
import static com.postman.insights.agent.Frames.OP_RECV;
import static com.postman.insights.agent.Frames.OP_SEND;
import static com.postman.insights.agent.Frames.ROLE_KNOWN;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;

import javax.net.ssl.SSLEngine;

import com.postman.insights.agent.Frames.Frame;

/**
 * Calls one wrap or unwrap shape once and checks the agent wrote exactly one
 * frame with exactly the plaintext of that call: nothing missed, nothing
 * emitted twice by the overloads that delegate to each other.
 */
final class ShapeChecks {
    interface WrapCall {
        void wrap(SSLEngine e, ByteBuffer[] srcs, ByteBuffer dst) throws Exception;
    }

    interface UnwrapCall {
        void unwrap(SSLEngine e, ByteBuffer src, ByteBuffer[] dsts) throws Exception;
    }

    private final EnginePair pair;
    private final boolean direct;

    /** @param direct use direct buffers for the plaintext, as Netty does */
    ShapeChecks(EnginePair pair, boolean direct) {
        this.pair = pair;
        this.direct = direct;
    }

    private ByteBuffer buffer(int capacity) {
        return direct ? ByteBuffer.allocateDirect(capacity) : ByteBuffer.allocate(capacity);
    }

    private ByteBuffer text(String s) {
        ByteBuffer b = buffer(s.length());
        b.put(s.getBytes(StandardCharsets.ISO_8859_1));
        b.flip();
        return b;
    }

    /**
     * The client sends parts through the shape, one call at a time until all
     * are consumed (Netty's OpenSSL engine takes one source buffer per call);
     * the server receives them with the 2-arg unwrap. Each call must produce
     * one frame with what it consumed. Returns the client's last frame.
     */
    Frame wrap(String name, WrapCall call, String... parts) throws Exception {
        ByteBuffer[] srcs = new ByteBuffer[parts.length];
        StringBuilder all = new StringBuilder();
        for (int i = 0; i < parts.length; i++) {
            srcs[i] = text(parts[i]);
            all.append(parts[i]);
        }
        StringBuilder sent = new StringBuilder();
        Frame f = null;
        for (int calls = 0; srcs[srcs.length - 1].hasRemaining(); calls++) {
            assertTrue(calls < parts.length, name + ": sources not consumed");
            Frames frames = new Frames().mark();
            call.wrap(pair.client, srcs, pair.toServer);
            List<Frame> got = frames.traffic();
            assertEquals(1, got.size(), name + ": " + got);
            f = got.get(0);
            assertEquals(OP_SEND, f.op, name);
            // A wrap's output is written to the socket after the frame.
            assertEquals(ROLE_KNOWN | CLIENT_MODE | BEFORE_WRITE, f.flags, name);
            sent.append(f.text());
        }
        assertEquals(all.toString(), sent.toString(), name);

        assertEquals(all.toString(), receive(), name + ": delivered");
        return f;
    }

    /**
     * The client sends text with the 2-arg wrap; the server receives it
     * through one call of the shape. Returns the server's frame.
     */
    Frame unwrap(String name, UnwrapCall call, String text) throws Exception {
        pair.client.wrap(ByteBuffer.wrap(text.getBytes(StandardCharsets.ISO_8859_1)), pair.toServer);
        Frames frames = new Frames().mark();
        ByteBuffer[] dsts = {buffer(64 * 1024)};
        pair.toServer.flip();
        call.unwrap(pair.server, pair.toServer, dsts);
        pair.toServer.compact();
        assertEquals(0, pair.toServer.position(), name + ": the record was not unwrapped in one call");

        List<Frame> got = frames.traffic();
        assertEquals(1, got.size(), name + ": " + got);
        Frame f = got.get(0);
        assertEquals(OP_RECV, f.op, name);
        assertEquals(text, f.text(), name);
        assertEquals(ROLE_KNOWN, f.flags, name);
        return f;
    }

    private String receive() throws Exception {
        ByteBuffer dst = ByteBuffer.allocate(64 * 1024);
        ByteBuffer in = pair.toServer;
        in.flip();
        while (in.hasRemaining()) {
            pair.server.unwrap(in, dst);
        }
        in.compact();
        dst.flip();
        byte[] got = new byte[dst.remaining()];
        dst.get(got);
        return new String(got, StandardCharsets.ISO_8859_1);
    }

    /** The shapes of the SSLEngine API, which every engine has. */
    void apiShapes() throws Exception {
        long sends = wrap("wrap(src, dst)", (e, s, d) -> e.wrap(s[0], d), "GET /single HTTP/1.1\r\n\r\n").connId;
        assertEquals(sends, wrap("wrap(srcs, dst)", (e, s, d) -> e.wrap(s, d), "GET /all ", "HTTP/1.1\r\n\r\n").connId);
        assertEquals(sends, wrap("wrap(srcs, off, len, dst)", (e, s, d) -> {
            ByteBuffer[] padded = {text("not this"), s[0], s[1], text("nor this")};
            e.wrap(padded, 1, 2, d);
        }, "GET /range ", "HTTP/1.1\r\n\r\n").connId);

        long recvs = unwrap("unwrap(src, dst)", (e, s, d) -> e.unwrap(s, d[0]), "unwrap single").connId;
        assertEquals(recvs, unwrap("unwrap(src, dsts)", (e, s, d) -> e.unwrap(s, d), "unwrap all").connId);
        assertEquals(recvs, unwrap("unwrap(src, dsts, off, len)", (e, s, d) -> {
            ByteBuffer[] padded = {buffer(16), d[0], buffer(16)};
            e.unwrap(s, padded, 1, 1);
        }, "unwrap range").connId);
    }
}
