package com.postman.insights.agent.bootstrap;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.lang.management.ManagementFactory;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLSocket;

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
        Bridge.exit(c, engine, Frame.OP_SEND, null);
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
        Bridge.exit(c, engine(false), Frame.OP_RECV, null);

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
        Bridge.exit(c, engine(false), Frame.OP_RECV, null);

        ByteBuffer src = direct("direct bytes");
        c = Bridge.enter(src);
        src.position(6);
        Bridge.exit(c, engine(true), Frame.OP_SEND, null);

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
        Bridge.exit(in, inner, Frame.OP_SEND, null);
        Bridge.exit(outer, wrapper, Frame.OP_SEND, null);

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
        Bridge.exit(Bridge.enter(srcs, 0, 5), engine(true), Frame.OP_SEND, null);
        Bridge.exit(Bridge.enter((ByteBuffer[]) null), engine(true), Frame.OP_SEND, null);
        Bridge.exit(Bridge.enter((ByteBuffer) null), engine(true), Frame.OP_SEND, null);
        Bridge.exit(Bridge.enter(srcs, -1, 1), engine(true), Frame.OP_SEND, null);
        Bridge.exit(null, engine(true), Frame.OP_SEND, null);
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
        Bridge.exit(c, engine(true), Frame.OP_SEND, null);
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

    /** 100 errors within any 10 minutes, however they line up with the first error. */
    @Test
    void errorBudgetIsARollingWindow() throws Exception {
        long minute = java.util.concurrent.TimeUnit.MINUTES.toNanos(1);
        long t0 = System.nanoTime();
        // Errors spread out: never 100 within 10 minutes.
        for (int i = 0; i < 3 * Bridge.ERROR_BUDGET; i++) {
            Bridge.error(t0 + i * minute / 9);
        }
        assertEquals(Contract.HEARTBEAT_STATE_ACTIVE, Bridge.state());

        // One error, then a burst that straddles the 10-minute mark after it.
        Bridge.start(CAP, log.path());
        Bridge.control(true, CAP);
        Bridge.error(t0);
        for (int i = 0; i < Bridge.ERROR_BUDGET - 2; i++) {
            Bridge.error(t0 + 9 * minute + 59 * minute / 60);
        }
        assertEquals(Contract.HEARTBEAT_STATE_ACTIVE, Bridge.state());
        Bridge.error(t0 + 10 * minute + minute / 60);
        assertEquals(Contract.HEARTBEAT_STATE_ACTIVE, Bridge.state(), "99 errors in the last 10 minutes");
        Bridge.error(t0 + 10 * minute + minute / 60);
        assertEquals(Contract.HEARTBEAT_STATE_OFF, Bridge.state(), "100 errors within 2 minutes");
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
            Bridge.exit(c, e, Frame.OP_SEND, null);
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

    private static final SSLEngineResult CLOSED = new SSLEngineResult(
            SSLEngineResult.Status.CLOSED, SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, 0, 0);
    private static final SSLEngineResult OK = new SSLEngineResult(
            SSLEngineResult.Status.OK, SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING, 0, 0);

    /** One hooked call on engine with no bytes and the given result. */
    private static void result(Object engine, byte op, SSLEngineResult r) {
        Bridge.exit(Bridge.enter(bufs("")), engine, op, r);
    }

    private static List<LoggedFrame> closes() throws Exception {
        List<LoggedFrame> out = new ArrayList<LoggedFrame>();
        for (LoggedFrame f : log.frames()) {
            if (f.op == Frame.OP_CLOSE) {
                out.add(f);
            }
        }
        return out;
    }

    /**
     * A server's connection is done once its outbound side closes: it sends
     * no more responses. Its peer closing first is not enough, since the
     * server may still answer.
     */
    @Test
    void closeOnceServerOutboundCloses() throws Exception {
        SSLEngine server = engine(false);
        send(server, bufs("HTTP/1.1 200 OK"), 15);
        long id = log.frames().get(0).connId;
        result(server, Frame.OP_SEND, OK);
        result(server, Frame.OP_RECV, CLOSED);
        assertEquals(0, closes().size(), "CLOSE after only the client closed");

        result(server, Frame.OP_SEND, CLOSED);
        result(server, Frame.OP_SEND, CLOSED);
        List<LoggedFrame> closes = closes();
        assertEquals(1, closes.size());
        LoggedFrame f = closes.get(0);
        assertEquals(id, f.connId);
        assertEquals(Frame.FLAG_ROLE_KNOWN, f.flags);
        assertEquals(0, f.payload.length);
        assertEquals(0, f.totalLen);
    }

    /** A client's connection is done once its inbound side closes: no more responses arrive. */
    @Test
    void closeOnceClientInboundCloses() throws Exception {
        SSLEngine client = engine(true);
        result(client, Frame.OP_SEND, CLOSED);
        assertEquals(0, closes().size(), "CLOSE while a response can still arrive");
        result(client, Frame.OP_RECV, CLOSED);
        assertEquals(1, closes().size());
        assertEquals(Frame.FLAG_ROLE_KNOWN | Frame.FLAG_CLIENT_MODE, closes().get(0).flags);
    }

    /** With the role unknown, both sides must close. */
    @Test
    void closeWithUnknownRoleNeedsBothSides() throws Exception {
        Object notAnEngine = new Object();
        result(notAnEngine, Frame.OP_RECV, CLOSED);
        assertEquals(0, closes().size());
        result(notAnEngine, Frame.OP_SEND, CLOSED);
        assertEquals(1, closes().size());
        assertEquals(0, closes().get(0).flags);
    }

    /** Nothing is sent while dormant, nor for a call that threw. */
    @Test
    void noCloseWhileDormantOrOnThrow() throws Exception {
        SSLEngine server = engine(false);
        Bridge.control(false, CAP);
        result(server, Frame.OP_SEND, CLOSED);
        Bridge.control(true, CAP);
        Bridge.exit(Bridge.enter(bufs("")), server, Frame.OP_SEND, null);
        assertEquals(0, closes().size());
    }

    /**
     * A CLOSE that could not be written (here: the thread was interrupted)
     * is retried at the next CLOSED result, and sent once.
     */
    @Test
    void droppedCloseIsRetried() throws Exception {
        SSLEngine server = engine(false);
        Thread.currentThread().interrupt();
        try {
            result(server, Frame.OP_SEND, CLOSED);
        } finally {
            Thread.interrupted();
        }
        assertEquals(0, closes().size(), "CLOSE written from an interrupted thread");
        result(server, Frame.OP_SEND, CLOSED);
        result(server, Frame.OP_SEND, CLOSED);
        assertEquals(1, closes().size());
    }

    /** A handshake unwrap: TLS bytes consumed, no plaintext produced. */
    private static final SSLEngineResult HANDSHAKE_UNWRAP = new SSLEngineResult(
            SSLEngineResult.Status.OK, SSLEngineResult.HandshakeStatus.NEED_WRAP, 120, 0);

    /** One hooked unwrap call that produces nothing, as in a handshake. */
    private static void emptyRecv(Object engine) {
        ByteBuffer dst = ByteBuffer.allocate(8);
        Bridge.exit(Bridge.enter(dst), engine, Frame.OP_RECV, HANDSHAKE_UNWRAP);
    }

    /**
     * An unwrap that consumed no TLS bytes (BUFFER_UNDERFLOW, or it threw) is
     * no evidence the thread read the socket: it does not tie.
     */
    @Test
    void unwrapWithoutBytesDoesNotTie() throws Exception {
        SSLEngine server = engine(false);
        ByteBuffer dst = ByteBuffer.allocate(8);
        Bridge.exit(Bridge.enter(dst), server, Frame.OP_RECV, new SSLEngineResult(
                SSLEngineResult.Status.BUFFER_UNDERFLOW, SSLEngineResult.HandshakeStatus.NEED_UNWRAP, 0, 0));
        Bridge.exit(Bridge.enter(dst), server, Frame.OP_RECV, null);
        assertEquals(0, log.frames().size());
        emptyRecv(server);
        assertEquals(1, ops(Frame.OP_RECV).size());
    }

    private static List<LoggedFrame> ops(byte op) throws Exception {
        List<LoggedFrame> out = new ArrayList<LoggedFrame>();
        for (LoggedFrame f : log.frames()) {
            if (f.op == op) {
                out.add(f);
            }
        }
        return out;
    }

    /**
     * A connection's first unwrap sends an empty RECV frame, which ties the
     * connection to its socket in the kernel; later empty unwraps send
     * nothing, and neither do empty wraps.
     */
    @Test
    void firstUnwrapTiesTheConnection() throws Exception {
        SSLEngine server = engine(false);
        emptyRecv(server);
        emptyRecv(server);
        Bridge.exit(Bridge.enter(bufs("")), server, Frame.OP_SEND, OK);

        List<LoggedFrame> frames = log.frames();
        assertEquals(1, frames.size());
        LoggedFrame f = frames.get(0);
        assertEquals(Frame.OP_RECV, f.op);
        assertEquals(Frame.FLAG_ROLE_KNOWN, f.flags);
        assertEquals(0, f.payload.length);
        assertEquals(0, f.totalLen);

        // Another connection is tied on its own.
        emptyRecv(engine(true));
        assertEquals(2, ops(Frame.OP_RECV).size());
        assertTrue(ops(Frame.OP_RECV).get(1).connId != f.connId);
    }

    /** A connection whose first unwrap had plaintext was tied by that frame. */
    @Test
    void dataRecvTiesTheConnection() throws Exception {
        SSLEngine server = engine(false);
        ByteBuffer dst = ByteBuffer.allocate(8);
        Bridge.Call c = Bridge.enter(dst);
        dst.put(ascii("GET"));
        Bridge.exit(c, server, Frame.OP_RECV, OK);
        emptyRecv(server);

        List<LoggedFrame> recvs = ops(Frame.OP_RECV);
        assertEquals(1, recvs.size());
        assertArrayEquals(ascii("GET"), recvs.get(0).payload);
    }

    /** Dormant, nothing is sent, and the first unwrap once capturing ties the connection. */
    @Test
    void noTieWhileDormant() throws Exception {
        SSLEngine server = engine(false);
        Bridge.control(false, CAP);
        emptyRecv(server);
        assertEquals(0, log.frames().size());
        Bridge.control(true, CAP);
        emptyRecv(server);
        assertEquals(1, ops(Frame.OP_RECV).size());
    }

    /**
     * A tie frame that could not be written (here: the thread was
     * interrupted) is retried at the connection's next handshake unwrap.
     */
    @Test
    void droppedTieIsRetried() throws Exception {
        SSLEngine client = engine(true);
        Thread.currentThread().interrupt();
        try {
            emptyRecv(client);
        } finally {
            Thread.interrupted();
        }
        assertEquals(0, log.frames().size(), "a frame written from an interrupted thread");
        emptyRecv(client);
        emptyRecv(client);
        assertEquals(1, ops(Frame.OP_RECV).size());
    }

    /** One hooked SSLSocket stream call that read (RECV) or wrote (SEND) text. */
    private static void stream(Object socket, byte op, String text) {
        byte[] b = ascii(text);
        Bridge.Call c = Bridge.enterStream(socket);
        Bridge.exitStream(c, socket, op, b, 0, b.length);
    }

    /**
     * A blocking client socket connected to listener (the kernel completes
     * the connection in the listener's backlog), before its handshake.
     */
    private static SSLSocket connect(ServerSocket listener) throws Exception {
        SSLSocket socket = (SSLSocket) SSLContext.getDefault().getSocketFactory()
                .createSocket(InetAddress.getLoopbackAddress(), listener.getLocalPort());
        socket.setUseClientMode(true);
        return socket;
    }

    /**
     * A blocking socket's first frame is an ADDRESS frame with the socket's
     * own addresses, sent once; every frame of the connection is marked
     * SOCKET, so the kernel never ties it to its thread's reads.
     */
    @Test
    void socketSendsItsAddressesFirst() throws Exception {
        try (ServerSocket listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
             SSLSocket socket = connect(listener)) {
            stream(socket, Frame.OP_SEND, "GET / HTTP/1.1\r\n\r\n");
            stream(socket, Frame.OP_RECV, "HTTP/1.1 200 OK\r\n\r\n");

            List<LoggedFrame> got = log.frames();
            assertEquals(3, got.size());
            LoggedFrame address = got.get(0);
            assertEquals(Frame.OP_ADDRESS, address.op);
            assertEquals(Frame.ADDRESS_SIZE, address.totalLen);
            ByteBuffer want = Frame.allocate(Frame.ADDRESS_SIZE);
            Frame.putAddress(want, 0, socket.getLocalAddress(), socket.getLocalPort(),
                    InetAddress.getLoopbackAddress(), listener.getLocalPort());
            byte[] wantBytes = new byte[Frame.ADDRESS_SIZE];
            want.get(wantBytes);
            assertArrayEquals(wantBytes, address.payload);
            assertEquals(Frame.OP_SEND, got.get(1).op);
            assertEquals(Frame.OP_RECV, got.get(2).op);
            for (LoggedFrame f : got) {
                assertEquals(address.connId, f.connId);
                assertEquals(Frame.FLAG_ROLE_KNOWN | Frame.FLAG_CLIENT_MODE | Frame.FLAG_SOCKET, f.flags);
            }
        }
    }

    /**
     * An ADDRESS frame that could not be written (here: every buffer was
     * busy) is retried before the connection's next data frame.
     */
    @Test
    void droppedAddressIsRetried() throws Exception {
        try (ServerSocket listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
             SSLSocket socket = connect(listener)) {
            Bridge.holdAllBuffers(true);
            try {
                stream(socket, Frame.OP_SEND, "dropped");
            } finally {
                Bridge.holdAllBuffers(false);
            }
            assertEquals(0, log.frames().size());
            stream(socket, Frame.OP_SEND, "sent");
            stream(socket, Frame.OP_SEND, "sent again");
            List<LoggedFrame> got = log.frames();
            assertEquals(3, got.size());
            assertEquals(Frame.OP_ADDRESS, got.get(0).op);
            assertEquals(1, ops(Frame.OP_ADDRESS).size());
        }
    }

    /**
     * A socket in use sends its ADDRESS frame again after each heartbeat, so
     * one the kernel dropped or forgot comes back.
     */
    @Test
    void addressResentEachHeartbeat() throws Exception {
        try (ServerSocket listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
             SSLSocket socket = connect(listener)) {
            stream(socket, Frame.OP_SEND, "first");
            stream(socket, Frame.OP_SEND, "second");
            assertEquals(1, ops(Frame.OP_ADDRESS).size());
            Bridge.heartbeat(ascii("state=active\n"));
            stream(socket, Frame.OP_SEND, "after a heartbeat");
            stream(socket, Frame.OP_SEND, "again");
            assertEquals(2, ops(Frame.OP_ADDRESS).size());
        }
    }

    /**
     * A socket closed on one thread while a read on another has done its
     * I/O but not yet sent its frame: the CLOSE comes after the read's RECV,
     * sent by the read, so the Insights agent does not complete a response
     * before its last bytes.
     */
    @Test
    void closeWaitsForAReadInFlight() throws Exception {
        try (ServerSocket listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
             SSLSocket socket = connect(listener)) {
            stream(socket, Frame.OP_SEND, "GET / HTTP/1.1\r\n\r\n");
            CountDownLatch read = new CountDownLatch(1);
            CountDownLatch closed = new CountDownLatch(1);
            Thread reader = new Thread(() -> {
                Bridge.Call c = Bridge.enterStream(socket);
                read.countDown();
                try {
                    closed.await();
                } catch (InterruptedException e) {
                    return;
                }
                byte[] b = ascii("the last bytes");
                Bridge.exitStream(c, socket, Frame.OP_RECV, b, 0, b.length);
            });
            reader.start();
            read.await();
            Bridge.socketClosed(socket);
            assertTrue(ops(Frame.OP_CLOSE).isEmpty(), "CLOSE before the read in flight sent its frame");
            closed.countDown();
            reader.join();
            List<LoggedFrame> got = log.frames();
            assertEquals(Frame.OP_RECV, got.get(got.size() - 2).op, got.toString());
            assertEquals(Frame.OP_CLOSE, got.get(got.size() - 1).op, got.toString());
            assertEquals(1, ops(Frame.OP_CLOSE).size());

            // With nothing in flight, the close sends CLOSE itself (here none
            // again: one per connection).
            Bridge.socketClosed(socket);
            assertEquals(1, ops(Frame.OP_CLOSE).size());
        }
    }

    /** A socket closed with nothing in flight sends CLOSE at once. */
    @Test
    void closeWithNothingInFlight() throws Exception {
        try (ServerSocket listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
             SSLSocket socket = connect(listener)) {
            stream(socket, Frame.OP_SEND, "GET / HTTP/1.1\r\n\r\n");
            Bridge.socketClosed(socket);
            assertEquals(1, ops(Frame.OP_CLOSE).size());
        }
    }

    /** A socket that is not connected has no addresses to send yet. */
    @Test
    void unconnectedSocketSendsNoAddress() throws Exception {
        try (SSLSocket socket = (SSLSocket) SSLContext.getDefault().getSocketFactory().createSocket()) {
            stream(socket, Frame.OP_RECV, "plaintext");
            List<LoggedFrame> got = log.frames();
            assertEquals(1, got.size());
            assertEquals(Frame.OP_RECV, got.get(0).op);
            assertEquals(Frame.FLAG_SOCKET, got.get(0).flags & Frame.FLAG_SOCKET);
        }
    }
}
