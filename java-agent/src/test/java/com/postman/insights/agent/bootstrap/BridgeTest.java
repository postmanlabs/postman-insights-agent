package com.postman.insights.agent.bootstrap;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.lang.management.ManagementFactory;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.postman.insights.agent.bootstrap.FrameLog.LoggedFrame;

/** Drives the bridge the way the advice does, with frames going to a log file. */
class BridgeTest {
    private static final int CAP = 16;
    private static FrameLog log;

    @BeforeAll
    static void createLog() throws Exception {
        log = new FrameLog("bridge-test");
    }

    @BeforeEach
    void startBridge() {
        Bridge.start(CAP, log.path());
        Bridge.control(true, CAP);
        log.mark();
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    private static ByteBuffer[] bufs(String... parts) {
        ByteBuffer[] out = new ByteBuffer[parts.length];
        for (int i = 0; i < parts.length; i++) {
            out[i] = ByteBuffer.wrap(ascii(parts[i]));
        }
        return out;
    }

    private static ByteBuffer direct(String s) {
        ByteBuffer b = ByteBuffer.allocateDirect(s.length());
        b.put(ascii(s));
        b.flip();
        return b;
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

    /** One hooked wrap call that consumes n bytes. */
    private static void send(Object engine, ByteBuffer[] srcs, int n) {
        Bridge.Call c = Bridge.enter(srcs, 0, srcs.length);
        consume(srcs, n);
        Bridge.exit(c, engine, Frame.OP_SEND);
    }

    @Test
    void sendEmitsConsumedBytesWithRole() throws Exception {
        send(engine(true), bufs("GET /a ", "HTTP/1.1"), 12);

        List<LoggedFrame> frames = log.frames();
        assertEquals(1, frames.size());
        LoggedFrame f = frames.get(0);
        assertEquals(Frame.OP_SEND, f.op);
        assertEquals(Frame.FLAG_ROLE_KNOWN | Frame.FLAG_CLIENT_MODE, f.flags);
        assertEquals(12, f.totalLen);
        assertArrayEquals(ascii("GET /a HTTP/"), f.payload);
    }

    @Test
    void recvRespectsOffsetAndLength() throws Exception {
        ByteBuffer[] dsts = {ByteBuffer.allocate(8), ByteBuffer.allocate(8), ByteBuffer.allocate(8)};
        Bridge.Call c = Bridge.enter(dsts, 1, 1);
        dsts[1].put(ascii("OK"));
        dsts[0].put(ascii("no")); // outside [off, off+len)
        Bridge.exit(c, engine(false), Frame.OP_RECV);

        LoggedFrame f = log.frames().get(0);
        assertEquals(Frame.OP_RECV, f.op);
        assertEquals(Frame.FLAG_ROLE_KNOWN, f.flags);
        assertArrayEquals(ascii("OK"), f.payload);
    }

    @Test
    void singleBuffer() throws Exception {
        ByteBuffer dst = ByteBuffer.allocate(16);
        dst.put(ascii("old"));
        Bridge.Call c = Bridge.enter(dst);
        dst.put(ascii("new"));
        Bridge.exit(c, engine(false), Frame.OP_RECV);

        ByteBuffer src = direct("direct bytes");
        c = Bridge.enter(src);
        src.position(6);
        Bridge.exit(c, engine(true), Frame.OP_SEND);

        List<LoggedFrame> frames = log.frames();
        assertEquals(2, frames.size());
        assertArrayEquals(ascii("new"), frames.get(0).payload);
        assertArrayEquals(ascii("direct"), frames.get(1).payload);
    }

    /** Direct and read-only buffers have no array to copy from; they are left as they were. */
    @Test
    void directAndReadOnlyBuffers() throws Exception {
        ByteBuffer a = direct("0123456789");
        a.position(2);
        a.mark();
        ByteBuffer b = ByteBuffer.wrap(ascii("abc")).asReadOnlyBuffer();
        ByteBuffer[] srcs = {a, b};
        send(engine(true), srcs, 11);

        assertArrayEquals(ascii("23456789abc"), log.frames().get(0).payload);
        assertEquals(10, a.position());
        assertEquals(10, a.limit());
        a.reset();
        assertEquals(2, a.position(), "mark lost");
    }

    @Test
    void truncatesToCapAndKeepsTotal() throws Exception {
        send(engine(true), bufs("0123456789", "abcdefghij"), 20);

        LoggedFrame f = log.frames().get(0);
        assertEquals(20, f.totalLen);
        assertArrayEquals(ascii("0123456789abcdef"), f.payload);
    }

    @Test
    void nothingConsumedNothingEmitted() throws Exception {
        send(engine(true), bufs("pending"), 0);
        assertTrue(log.frames().isEmpty());
    }

    @Test
    void nestedCallEmitsOnce() throws Exception {
        SSLEngine wrapper = engine(true);
        SSLEngine inner = engine(true);
        ByteBuffer[] srcs = bufs("hello");
        Bridge.Call outer = Bridge.enter(srcs, 0, 1);
        Bridge.Call in = Bridge.enter(srcs[0]);
        consume(srcs, 5);
        Bridge.exit(in, inner, Frame.OP_SEND);
        Bridge.exit(outer, wrapper, Frame.OP_SEND);

        List<LoggedFrame> frames = log.frames();
        assertEquals(1, frames.size());
        assertArrayEquals(ascii("hello"), frames.get(0).payload);

        // The depth is back to zero: the next call emits.
        send(inner, bufs("again"), 5);
        assertEquals(2, log.frames().size());
    }

    @Test
    void connectionIdsPerEngine() throws Exception {
        SSLEngine a = engine(false);
        SSLEngine b = engine(false);
        for (SSLEngine e : new SSLEngine[] {a, b, a}) {
            send(e, bufs("x"), 1);
        }
        List<LoggedFrame> f = log.frames();
        assertEquals(3, f.size());
        assertNotEquals(f.get(0).connId, f.get(1).connId);
        assertEquals(f.get(0).connId, f.get(2).connId);
    }

    @Test
    void badArgumentsAreIgnored() throws Exception {
        long errors = Bridge.errors();
        ByteBuffer[] srcs = bufs("x");
        Bridge.exit(Bridge.enter(srcs, 0, 5), engine(true), Frame.OP_SEND);
        Bridge.exit(Bridge.enter((ByteBuffer[]) null), engine(true), Frame.OP_SEND);
        Bridge.exit(Bridge.enter((ByteBuffer) null), engine(true), Frame.OP_SEND);
        Bridge.exit(Bridge.enter(srcs, -1, 1), engine(true), Frame.OP_SEND);
        Bridge.exit(null, engine(true), Frame.OP_SEND);
        assertTrue(log.frames().isEmpty());
        assertEquals(errors, Bridge.errors());
    }

    @Test
    void interruptedThreadSkipsAndKeepsInterrupt() throws Exception {
        long dropped = Bridge.framesDropped();
        Thread.currentThread().interrupt();
        try {
            send(engine(true), bufs("x"), 1);
            assertTrue(Thread.currentThread().isInterrupted());
        } finally {
            Thread.interrupted();
        }
        assertTrue(log.frames().isEmpty());
        assertEquals(dropped + 1, Bridge.framesDropped());

        send(engine(true), bufs("y"), 1);
        assertEquals(1, log.frames().size());
    }

    @Test
    void dormantUntilEnabled() throws Exception {
        Bridge.start(CAP, log.path());
        assertEquals(Contract.HEARTBEAT_STATE_DORMANT, Bridge.state());
        assertNull(Bridge.enter(bufs("x")), "dormant hooks must return at once");
        send(engine(true), bufs("dormant"), 7);
        assertTrue(log.frames().isEmpty());

        Bridge.control(true, CAP);
        assertEquals(Contract.HEARTBEAT_STATE_ACTIVE, Bridge.state());
        send(engine(true), bufs("active"), 6);
        assertEquals(1, log.frames().size());

        Bridge.control(false, CAP);
        send(engine(true), bufs("off again"), 9);
        assertEquals(1, log.frames().size());
    }

    @Test
    void switchedOffDuringTheCall() throws Exception {
        ByteBuffer[] srcs = bufs("abc");
        Bridge.Call c = Bridge.enter(srcs, 0, 1);
        consume(srcs, 3);
        Bridge.control(false, CAP);
        Bridge.exit(c, engine(true), Frame.OP_SEND);
        assertTrue(log.frames().isEmpty());

        // The nesting depth was still unwound.
        Bridge.control(true, CAP);
        send(engine(true), bufs("d"), 1);
        assertEquals(1, log.frames().size());
    }

    @Test
    void controlChangesTheCap() throws Exception {
        Bridge.control(true, 4);
        send(engine(true), bufs("0123456789"), 10);
        Bridge.control(true, 64);
        send(engine(true), bufs("0123456789"), 10);

        List<LoggedFrame> f = log.frames();
        assertArrayEquals(ascii("0123"), f.get(0).payload);
        assertArrayEquals(ascii("0123456789"), f.get(1).payload);
    }

    @Test
    void busyPoolDropsAndCounts() throws Exception {
        assertTrue(Bridge.poolSize() >= Bridge.MIN_POOL_SIZE && Bridge.poolSize() <= Bridge.MAX_POOL_SIZE);
        long dropped = Bridge.framesDropped();
        Bridge.holdAllBuffers(true);
        try {
            send(engine(true), bufs("x"), 1);
        } finally {
            Bridge.holdAllBuffers(false);
        }
        assertTrue(log.frames().isEmpty());
        assertEquals(dropped + 1, Bridge.framesDropped());

        send(engine(true), bufs("y"), 1);
        assertEquals(1, log.frames().size());
    }

    /** Every frame is either written whole or dropped and counted. */
    @Test
    void concurrentCallers() throws Exception {
        final int threads = 16;
        final int calls = 300;
        long written = Bridge.framesWritten();
        long dropped = Bridge.framesDropped();
        final SSLEngine e = engine(true);
        final CountDownLatch go = new CountDownLatch(1);
        List<Thread> ts = new ArrayList<Thread>();
        for (int t = 0; t < threads; t++) {
            final String text = "thread-" + (char) ('a' + t);
            Thread th = new Thread(() -> {
                try {
                    go.await();
                } catch (InterruptedException ignored) {
                    return;
                }
                for (int i = 0; i < calls; i++) {
                    send(e, bufs(text), text.length());
                }
            });
            th.start();
            ts.add(th);
        }
        go.countDown();
        for (Thread th : ts) {
            th.join();
        }

        List<LoggedFrame> frames = log.frames();
        assertEquals(Bridge.framesWritten() - written, frames.size());
        assertEquals(threads * calls, frames.size() + Bridge.framesDropped() - dropped);
        for (LoggedFrame f : frames) {
            assertTrue(f.text().matches("thread-[a-p]"), f.text());
        }
    }

    @Test
    void errorBudgetSwitchesOff() throws Exception {
        for (int i = 0; i < Bridge.ERROR_BUDGET; i++) {
            Bridge.error();
        }
        assertEquals(Contract.HEARTBEAT_STATE_OFF, Bridge.state());
        Bridge.control(true, CAP); // the control file cannot switch it back on
        send(engine(true), bufs("x"), 1);
        assertTrue(log.frames().isEmpty());
    }

    @Test
    void heartbeatIsSentWhileDormant() throws Exception {
        Bridge.control(false, CAP);
        Bridge.heartbeat(ascii("agent_version=1\n"));

        List<LoggedFrame> frames = log.frames();
        assertEquals(1, frames.size());
        LoggedFrame f = frames.get(0);
        assertEquals(Frame.OP_HEARTBEAT, f.op);
        assertEquals(0, f.connId);
        assertEquals(16, f.totalLen);
        assertArrayEquals(ascii("agent_version=1\n"), f.payload);
    }

    /**
     * A hooked call allocates nothing once warmed up, in the production
     * write path (to /dev/null at MAGIC). HotSpot only.
     */
    @Test
    void noAllocationPerCall() throws Exception {
        java.lang.management.ThreadMXBean mx = ManagementFactory.getThreadMXBean();
        assumeTrue(mx instanceof com.sun.management.ThreadMXBean);
        com.sun.management.ThreadMXBean hs = (com.sun.management.ThreadMXBean) mx;
        assumeTrue(hs.isThreadAllocatedMemorySupported());
        hs.setThreadAllocatedMemoryEnabled(true);

        Bridge.start(CAP, null);
        Bridge.control(true, CAP);
        SSLEngine e = engine(true);
        boolean directWithoutCopy = !System.getProperty("java.specification.version").startsWith("1.")
                && Integer.parseInt(System.getProperty("java.specification.version")) >= 16;
        ByteBuffer[] srcs = {ByteBuffer.wrap(ascii("heap bytes")),
                directWithoutCopy ? direct("direct") : ByteBuffer.wrap(ascii("heap2"))};
        Runnable call = () -> {
            srcs[0].rewind();
            srcs[1].rewind();
            Bridge.Call c = Bridge.enter(srcs, 0, 2);
            srcs[0].position(srcs[0].limit());
            srcs[1].position(srcs[1].limit());
            Bridge.exit(c, e, Frame.OP_SEND);
        };
        for (int i = 0; i < 20_000; i++) {
            call.run();
        }
        long tid = Thread.currentThread().getId();
        long before = hs.getThreadAllocatedBytes(tid);
        for (int i = 0; i < 10_000; i++) {
            call.run();
        }
        long allocated = hs.getThreadAllocatedBytes(tid) - before;
        assertTrue(allocated < 10_000, allocated + " bytes allocated by 10000 calls");
    }
}
