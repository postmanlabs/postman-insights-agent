package com.postman.insights.agent.bootstrap;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.FileChannel;
import java.util.concurrent.atomic.AtomicLong;

import javax.net.ssl.SSLEngine;

/**
 * Called by the advice woven into {@link SSLEngine} implementations. Copies
 * the plaintext of each {@code wrap}/{@code unwrap} call into a frame and
 * hands it to the kernel with a positional write to {@code /dev/null} at
 * {@link Frame#MAGIC}; the Insights agent's eBPF programs read it on syscall
 * entry. Pure Java: no JNI, no {@code Unsafe}.
 *
 * <p>Loaded by the bootstrap class loader, because advice is inlined into JDK
 * classes such as {@code sun.security.ssl.SSLEngineImpl}, which can only see
 * bootstrap classes. Uses only JDK classes for the same reason.
 *
 * <p>Never throws into application code: every entry point catches
 * everything, and too many internal errors switch the bridge off.
 */
public final class Bridge {
    /** Internal errors after which the bridge switches itself off. */
    private static final int ERROR_BUDGET = 100;

    private static volatile boolean enabled;
    private static int captureCap = Contract.DEFAULT_CAPTURE_CAP;
    private static String frameLog;

    private static final Connections CONNECTIONS = new Connections();

    /**
     * Nesting depth of hooked calls on this thread. A wrapper engine (Netty's
     * JdkSslEngine, gRPC's SslEngineWrapper) delegates to another hooked
     * engine; only the outermost call emits, so bytes are sent once.
     */
    private static final ThreadLocal<int[]> DEPTH = new ThreadLocal<int[]>() {
        @Override
        protected int[] initialValue() {
            return new int[1];
        }
    };

    // One frame buffer and channel, used under LOCK.
    // TODO(INS-364): a bounded pool, so concurrent connections do not serialize.
    private static final Object LOCK = new Object();
    private static ByteBuffer frame;
    private static FileChannel channel;

    private static final AtomicLong FRAMES = new AtomicLong();
    private static final AtomicLong ERRORS = new AtomicLong();

    private Bridge() {}

    /**
     * Starts the bridge.
     *
     * @param cap      maximum payload bytes per frame
     * @param logPath  testing only: append frames to this file instead of the
     *                 kernel; null in production
     */
    public static void start(int cap, String logPath) {
        synchronized (LOCK) {
            captureCap = cap;
            frameLog = logPath;
            frame = Frame.allocate(cap);
        }
        enabled = true;
    }

    public static long framesWritten() {
        return FRAMES.get();
    }

    public static long errors() {
        return ERRORS.get();
    }

    /**
     * Advice entry for {@code wrap} (srcs) and {@code unwrap} (dsts): records
     * where each buffer's position was. Returns null when nothing should be
     * emitted at exit.
     */
    public static int[] enter(ByteBuffer[] bufs, int off, int len) {
        try {
            int depth = ++DEPTH.get()[0];
            if (!enabled || depth > 1 || bufs == null || off < 0 || len <= 0 || len > bufs.length - off) {
                return null;
            }
            int[] pos = new int[len];
            for (int i = 0; i < len; i++) {
                ByteBuffer b = bufs[off + i];
                pos[i] = b == null ? -1 : b.position();
            }
            return pos;
        } catch (Throwable t) {
            error();
            return null;
        }
    }

    /**
     * Advice exit: emits the bytes between each buffer's entry position and
     * its current position, which is the plaintext the call consumed (wrap)
     * or produced (unwrap).
     */
    public static void exit(Object engine, byte op, ByteBuffer[] bufs, int off, int len, int[] pos) {
        try {
            DEPTH.get()[0]--;
            if (pos == null || !enabled) {
                return;
            }
            long total = 0;
            for (int i = 0; i < len; i++) {
                ByteBuffer b = bufs[off + i];
                if (b != null && pos[i] >= 0 && b.position() > pos[i]) {
                    total += b.position() - pos[i];
                }
            }
            if (total == 0) {
                return;
            }
            // A FileChannel write from an interrupted thread fails and closes
            // the channel for every other thread too; skip this call instead.
            if (Thread.currentThread().isInterrupted()) {
                return;
            }
            Connections.Info conn = CONNECTIONS.get(engine);
            short flags = conn.roleFlags;
            if (flags == 0 && engine instanceof SSLEngine) {
                flags = (short) (Frame.FLAG_ROLE_KNOWN
                        | (((SSLEngine) engine).getUseClientMode() ? Frame.FLAG_CLIENT_MODE : 0));
                conn.roleFlags = flags;
            }
            emit(op, flags, conn.id, bufs, off, len, pos, (int) Math.min(total, Integer.MAX_VALUE));
        } catch (Throwable t) {
            error();
        }
    }

    private static void emit(byte op, short flags, long connId, ByteBuffer[] bufs, int off, int len,
                             int[] pos, int total) throws IOException {
        synchronized (LOCK) {
            ByteBuffer f = frame;
            f.clear();
            f.position(Frame.HEADER_SIZE);
            for (int i = 0; i < len && f.position() - Frame.HEADER_SIZE < captureCap; i++) {
                ByteBuffer b = bufs[off + i];
                if (b == null || pos[i] < 0 || b.position() <= pos[i]) {
                    continue;
                }
                ByteBuffer view = b.duplicate();
                view.limit(b.position());
                view.position(pos[i]);
                int room = captureCap - (f.position() - Frame.HEADER_SIZE);
                if (view.remaining() > room) {
                    view.limit(view.position() + room);
                }
                f.put(view);
            }
            int payload = f.position() - Frame.HEADER_SIZE;
            Frame.putHeader(f, op, flags, payload, connId, null, 0, total);
            f.flip();
            write(f);
        }
        FRAMES.incrementAndGet();
    }

    /** Caller holds LOCK. */
    private static void write(ByteBuffer f) throws IOException {
        for (int attempt = 0; ; attempt++) {
            try {
                FileChannel ch = channel;
                if (ch == null || !ch.isOpen()) {
                    ch = frameLog != null
                            ? new FileOutputStream(frameLog, true).getChannel()
                            : new FileOutputStream("/dev/null").getChannel();
                    channel = ch;
                }
                if (frameLog != null) {
                    while (f.hasRemaining()) {
                        ch.write(f);
                    }
                } else {
                    ch.write(f, Frame.MAGIC);
                }
                return;
            } catch (ClosedChannelException e) {
                // Closed by an interrupt on another thread; reopen once.
                f.rewind();
                if (attempt > 0) {
                    throw e;
                }
            }
        }
    }

    private static void error() {
        if (ERRORS.incrementAndGet() >= ERROR_BUDGET && enabled) {
            enabled = false;
            System.err.println("[postman-insights-agent] too many internal errors; HTTPS capture switched off for this JVM");
        }
    }
}
