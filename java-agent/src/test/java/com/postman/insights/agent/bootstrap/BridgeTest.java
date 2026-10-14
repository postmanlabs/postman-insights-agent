package com.postman.insights.agent.bootstrap;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Drives the bridge the way the advice does, with frames going to a log file.
 * The tests share the bridge's static state, so each reads only the frames
 * written after it started.
 */
class BridgeTest {
    private static final int CAP = 16;
    private static File log;
    private long logStart;

    static final class LoggedFrame {
        byte op;
        short flags;
        long connId;
        int totalLen;
        byte[] payload;
    }

    @BeforeAll
    static void startBridge() throws Exception {
        log = File.createTempFile("bridge-test", ".frames");
        log.deleteOnExit();
        Bridge.start(CAP, log.getAbsolutePath());
    }

    @BeforeEach
    void markLog() {
        logStart = log.length();
    }

    private List<LoggedFrame> newFrames() throws Exception {
        byte[] all = Files.readAllBytes(log.toPath());
        ByteBuffer b = ByteBuffer.wrap(all, (int) logStart, all.length - (int) logStart).order(ByteOrder.LITTLE_ENDIAN);
        List<LoggedFrame> out = new ArrayList<LoggedFrame>();
        while (b.remaining() >= Frame.HEADER_SIZE) {
            int start = b.position();
            assertEquals(Frame.VERSION_1, b.get(start));
            LoggedFrame f = new LoggedFrame();
            f.op = b.get(start + 1);
            f.flags = b.getShort(start + 2);
            int len = b.getInt(start + 4);
            f.connId = b.getLong(start + 8);
            f.totalLen = b.getInt(start + 36);
            f.payload = Arrays.copyOfRange(all, start + Frame.HEADER_SIZE, start + Frame.HEADER_SIZE + len);
            b.position(start + Frame.HEADER_SIZE + len);
            out.add(f);
        }
        assertEquals(0, b.remaining(), "trailing bytes in the frame log");
        return out;
    }

    private static ByteBuffer[] bufs(String... parts) {
        ByteBuffer[] out = new ByteBuffer[parts.length];
        for (int i = 0; i < parts.length; i++) {
            out[i] = ByteBuffer.wrap(parts[i].getBytes(StandardCharsets.US_ASCII));
        }
        return out;
    }

    private static SSLEngine engine(boolean client) throws Exception {
        SSLEngine e = SSLContext.getDefault().createSSLEngine();
        e.setUseClientMode(client);
        return e;
    }

    /** What wrap does to its sources: consume n bytes from each buffer in turn. */
    private static void consume(ByteBuffer[] bs, int n) {
        for (ByteBuffer b : bs) {
            int k = Math.min(n, b.remaining());
            b.position(b.position() + k);
            n -= k;
        }
    }

    @Test
    void sendEmitsConsumedBytesWithRole() throws Exception {
        SSLEngine client = engine(true);
        ByteBuffer[] srcs = bufs("GET /a ", "HTTP/1.1");
        int[] pos = Bridge.enter(srcs, 0, 2);
        consume(srcs, 12);
        Bridge.exit(client, Frame.OP_SEND, srcs, 0, 2, pos);

        List<LoggedFrame> frames = newFrames();
        assertEquals(1, frames.size());
        LoggedFrame f = frames.get(0);
        assertEquals(Frame.OP_SEND, f.op);
        assertEquals(Frame.FLAG_ROLE_KNOWN | Frame.FLAG_CLIENT_MODE, f.flags);
        assertEquals(12, f.totalLen);
        assertArrayEquals("GET /a HTTP/".getBytes(StandardCharsets.US_ASCII), f.payload);
    }

    @Test
    void recvRespectsOffsetAndLength() throws Exception {
        SSLEngine server = engine(false);
        ByteBuffer[] dsts = {ByteBuffer.allocate(8), ByteBuffer.allocate(8), ByteBuffer.allocate(8)};
        int[] pos = Bridge.enter(dsts, 1, 1);
        dsts[1].put("OK".getBytes(StandardCharsets.US_ASCII));
        dsts[0].put("no".getBytes(StandardCharsets.US_ASCII)); // outside [off, off+len)
        Bridge.exit(server, Frame.OP_RECV, dsts, 1, 1, pos);

        LoggedFrame f = newFrames().get(0);
        assertEquals(Frame.OP_RECV, f.op);
        assertEquals(Frame.FLAG_ROLE_KNOWN, f.flags);
        assertArrayEquals("OK".getBytes(StandardCharsets.US_ASCII), f.payload);
    }

    @Test
    void truncatesToCapAndKeepsTotal() throws Exception {
        ByteBuffer[] srcs = bufs("0123456789", "abcdefghij");
        int[] pos = Bridge.enter(srcs, 0, 2);
        consume(srcs, 20);
        Bridge.exit(engine(true), Frame.OP_SEND, srcs, 0, 2, pos);

        LoggedFrame f = newFrames().get(0);
        assertEquals(20, f.totalLen);
        assertArrayEquals("0123456789abcdef".getBytes(StandardCharsets.US_ASCII), f.payload);
    }

    @Test
    void nothingConsumedNothingEmitted() throws Exception {
        ByteBuffer[] srcs = bufs("pending");
        int[] pos = Bridge.enter(srcs, 0, 1);
        Bridge.exit(engine(true), Frame.OP_SEND, srcs, 0, 1, pos);
        assertTrue(newFrames().isEmpty());
    }

    @Test
    void nestedCallEmitsOnce() throws Exception {
        SSLEngine wrapper = engine(true);
        SSLEngine inner = engine(true);
        ByteBuffer[] srcs = bufs("hello");
        int[] outer = Bridge.enter(srcs, 0, 1);
        int[] in = Bridge.enter(srcs, 0, 1);
        consume(srcs, 5);
        Bridge.exit(inner, Frame.OP_SEND, srcs, 0, 1, in);
        Bridge.exit(wrapper, Frame.OP_SEND, srcs, 0, 1, outer);

        List<LoggedFrame> frames = newFrames();
        assertEquals(1, frames.size());
        assertArrayEquals("hello".getBytes(StandardCharsets.US_ASCII), frames.get(0).payload);
    }

    @Test
    void connectionIdsPerEngine() throws Exception {
        SSLEngine a = engine(false);
        SSLEngine b = engine(false);
        for (SSLEngine e : new SSLEngine[] {a, b, a}) {
            ByteBuffer[] srcs = bufs("x");
            int[] pos = Bridge.enter(srcs, 0, 1);
            consume(srcs, 1);
            Bridge.exit(e, Frame.OP_SEND, srcs, 0, 1, pos);
        }
        List<LoggedFrame> f = newFrames();
        assertEquals(3, f.size());
        assertNotEquals(f.get(0).connId, f.get(1).connId);
        assertEquals(f.get(0).connId, f.get(2).connId);
    }

    @Test
    void badArgumentsAreIgnored() throws Exception {
        long errors = Bridge.errors();
        ByteBuffer[] srcs = bufs("x");
        Bridge.exit(engine(true), Frame.OP_SEND, srcs, 0, 1, Bridge.enter(srcs, 0, 5));
        Bridge.exit(engine(true), Frame.OP_SEND, null, 0, 1, Bridge.enter(null, 0, 1));
        Bridge.exit(engine(true), Frame.OP_SEND, srcs, -1, 1, Bridge.enter(srcs, -1, 1));
        assertTrue(newFrames().isEmpty());
        assertEquals(errors, Bridge.errors());
    }

    @Test
    void interruptedThreadSkipsAndKeepsInterrupt() throws Exception {
        ByteBuffer[] srcs = bufs("x");
        int[] pos = Bridge.enter(srcs, 0, 1);
        consume(srcs, 1);
        Thread.currentThread().interrupt();
        try {
            Bridge.exit(engine(true), Frame.OP_SEND, srcs, 0, 1, pos);
            assertTrue(Thread.currentThread().isInterrupted());
        } finally {
            Thread.interrupted();
        }
        assertTrue(newFrames().isEmpty());

        // The channel still works afterwards.
        srcs = bufs("y");
        pos = Bridge.enter(srcs, 0, 1);
        consume(srcs, 1);
        Bridge.exit(engine(true), Frame.OP_SEND, srcs, 0, 1, pos);
        assertEquals(1, newFrames().size());
    }
}
