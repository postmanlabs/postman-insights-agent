package com.postman.insights.agent.bootstrap;

import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedByInterruptException;
import java.nio.channels.FileChannel;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicIntegerArray;
import java.util.concurrent.atomic.LongAdder;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLSocket;

/**
 * Called by the advice woven into {@link SSLEngine} implementations and the
 * JDK's {@link SSLSocket} streams. Copies the plaintext of each
 * {@code wrap}/{@code unwrap} call, or socket read and write, into a frame and
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
 *
 * <p>A hooked call allocates nothing in the steady state on JDK 16+:
 * per-thread call state is reused, and frames are built in a small pool of
 * direct buffers shared by all threads (not one per thread, which virtual
 * threads would multiply). On JDK 8 to 15, copying from a direct or read-only
 * buffer needs a view of it, one small object per such buffer per call. When
 * every frame buffer is busy the frame is dropped and counted, rather than
 * making the application wait.
 */
public final class Bridge {
    /** Internal errors within any ERROR_WINDOW_NANOS after which the bridge switches itself off. */
    static final int ERROR_BUDGET = 100;
    private static final long ERROR_WINDOW_NANOS = TimeUnit.MINUTES.toNanos(10);

    /** Frame buffers: twice the CPUs, within these bounds. */
    static final int MIN_POOL_SIZE = 4;
    static final int MAX_POOL_SIZE = 32;

    /** Calls with more buffers than this are not captured (none are expected). */
    private static final int MAX_BUFFERS = 1024;

    /**
     * {@code ByteBuffer.put(int, ByteBuffer, int, int)} (JDK 16+), which copies
     * from a buffer without touching its position, so no view is needed; null
     * on older JDKs.
     */
    private static final MethodHandle ABSOLUTE_PUT = absolutePut();

    /** What the hooks check first: started, enabled by the control file, and not broken. */
    private static volatile boolean active;
    private static volatile boolean started;
    private static volatile boolean controlEnabled;
    private static volatile boolean broken;
    private static volatile int captureCap = Contract.DEFAULT_CAPTURE_CAP;
    private static volatile String frameLog;

    private static final Connections CONNECTIONS = new Connections();

    /**
     * Advanced at every heartbeat (every 30 s): a socket in use sends its
     * ADDRESS frame again once per epoch, so one the kernel dropped (rate cap,
     * netns not yet allowed) or forgot (LRU eviction, an Insights agent
     * restart) comes back. Written under HEARTBEAT_LOCK.
     */
    private static volatile int addressEpoch;

    private static final ThreadLocal<Call> CALL = new ThreadLocal<Call>() {
        @Override
        protected Call initialValue() {
            return new Call();
        }
    };

    private static volatile Pool pool = new Pool(0);

    /** Testing only: frames go to this file, under LOG_LOCK. */
    private static final Object LOG_LOCK = new Object();
    private static FileChannel logChannel;

    /** HEARTBEAT frames, written only by the agent's own thread. */
    private static final Object HEARTBEAT_LOCK = new Object();
    private static ByteBuffer heartbeatBuf;
    private static FileChannel heartbeatChannel;

    private static final LongAdder FRAMES = new LongAdder();
    private static final LongAdder DROPPED = new LongAdder();
    private static final LongAdder ERRORS = new LongAdder();
    private static final Object ERROR_LOCK = new Object();
    /** When the last ERROR_BUDGET errors happened (System.nanoTime); the oldest is at errorNext once full. */
    private static final long[] ERROR_TIMES = new long[ERROR_BUDGET];
    private static int errorNext;
    private static int errorCount;

    private Bridge() {}

    /**
     * Per-thread state of the outermost hooked call: where each buffer's
     * position was when it started. Reused for every call on the thread.
     */
    public static final class Call {
        /**
         * Nesting depth of hooked calls. A wrapper engine (Netty's
         * JdkSslEngine, gRPC's SslEngineWrapper) delegates to another hooked
         * engine, and an engine's convenience overloads delegate to its main
         * ones; only the outermost call emits, so bytes are sent once.
         */
        int depth;
        boolean recording;
        ByteBuffer[] bufs;
        int off;
        int len;
        int[] pos = new int[4];
        ByteBuffer single;
        int singlePos;
        /** A socket stream call's connection, counted in flight until its exit. */
        Connections.Info stream;
        /** A socket stream call's bytes: array[arrayOff, arrayOff + arrayLen). */
        byte[] array;
        int arrayOff;
        int arrayLen;
        int slotHint;
        final Connections.Lookup lookup = new Connections.Lookup();

        Call() {}

        private void clear() {
            recording = false;
            bufs = null;
            single = null;
            array = null;
            stream = null;
        }
    }

    /** Frame buffers, each with its own channel, so an interrupt closes only one. */
    private static final class Pool {
        final Slot[] slots;
        /** 1 while a thread owns the slot. */
        final AtomicIntegerArray busy;

        Pool(int size) {
            slots = new Slot[size];
            for (int i = 0; i < size; i++) {
                slots[i] = new Slot();
            }
            busy = new AtomicIntegerArray(size);
        }

        /**
         * Takes a free slot, trying the one this thread used last first.
         * Returns its index, or -1 when all are busy.
         */
        int acquire(Call c) {
            int n = slots.length;
            int hint = c.slotHint;
            for (int i = 0; i < n; i++) {
                int idx = (hint + i) % n;
                if (busy.compareAndSet(idx, 0, 1)) {
                    c.slotHint = idx;
                    return idx;
                }
            }
            return -1;
        }

        void release(int idx) {
            busy.set(idx, 0);
        }
    }

    private static final class Slot {
        ByteBuffer buf;
        FileChannel channel;
    }

    /**
     * Starts the bridge, dormant until {@link #control} enables it. Calling it
     * again resets it, for tests.
     *
     * @param cap      maximum payload bytes per frame
     * @param logPath  testing only: append frames to this file instead of the
     *                 kernel; null in production
     */
    public static synchronized void start(int cap, String logPath) {
        pool = new Pool(Math.max(MIN_POOL_SIZE, Math.min(MAX_POOL_SIZE, 2 * Runtime.getRuntime().availableProcessors())));
        captureCap = cap;
        synchronized (LOG_LOCK) {
            closeQuietly(logChannel);
            logChannel = null;
            frameLog = logPath;
        }
        controlEnabled = false;
        broken = false;
        synchronized (ERROR_LOCK) {
            errorNext = 0;
            errorCount = 0;
        }
        started = true;
        update();
    }

    /** Applies the control file: capture on or off, and the payload cap. */
    public static synchronized void control(boolean enabled, int cap) {
        captureCap = cap;
        controlEnabled = enabled;
        update();
    }

    /** Caller holds the class lock, so concurrent updates cannot undo each other. */
    private static void update() {
        active = started && controlEnabled && !broken;
    }

    private static synchronized void switchOff() {
        broken = true;
        update();
    }

    /** One of the Contract.HEARTBEAT_STATE_* values. */
    public static String state() {
        if (broken) {
            return Contract.HEARTBEAT_STATE_OFF;
        }
        return active ? Contract.HEARTBEAT_STATE_ACTIVE : Contract.HEARTBEAT_STATE_DORMANT;
    }

    /** Whether the hooks capture now. */
    public static boolean capturing() {
        return active;
    }

    /** The state once the control file enables capture. */
    public static String stateWhenEnabled() {
        if (broken) {
            return Contract.HEARTBEAT_STATE_OFF;
        }
        return started ? Contract.HEARTBEAT_STATE_ACTIVE : Contract.HEARTBEAT_STATE_DORMANT;
    }

    public static long framesWritten() {
        return FRAMES.sum();
    }

    /** Frames not written: every buffer was busy, or the thread was interrupted. */
    public static long framesDropped() {
        return DROPPED.sum();
    }

    public static long errors() {
        return ERRORS.sum();
    }

    public static int connections() {
        return CONNECTIONS.size();
    }

    /** Advice entry for the shapes that take the whole array of buffers. */
    public static Call enter(ByteBuffer[] bufs) {
        return enter(bufs, 0, bufs == null ? 0 : bufs.length);
    }

    /**
     * Advice entry for {@code wrap} (srcs) and {@code unwrap} (dsts): records
     * where each buffer's position is. Returns null when the exit has nothing
     * to do.
     */
    public static Call enter(ByteBuffer[] bufs, int off, int len) {
        if (!active) {
            return null;
        }
        Call c = call();
        if (c == null || c.depth++ > 0) {
            return c;
        }
        try {
            c.clear();
            if (bufs == null || off < 0 || len <= 0 || len > bufs.length - off || len > MAX_BUFFERS) {
                return c;
            }
            int[] pos = c.pos;
            if (pos.length < len) {
                c.pos = pos = new int[Math.max(len, 2 * pos.length)];
            }
            for (int i = 0; i < len; i++) {
                ByteBuffer b = bufs[off + i];
                pos[i] = b == null ? -1 : b.position();
            }
            c.bufs = bufs;
            c.off = off;
            c.len = len;
            c.recording = true;
        } catch (Throwable t) {
            c.clear();
            error();
        }
        return c;
    }

    /** Advice entry for the shapes that take a single buffer. */
    public static Call enter(ByteBuffer buf) {
        if (!active) {
            return null;
        }
        Call c = call();
        if (c == null || c.depth++ > 0) {
            return c;
        }
        try {
            c.clear();
            if (buf != null) {
                c.single = buf;
                c.singlePos = buf.position();
                c.recording = true;
            }
        } catch (Throwable t) {
            c.clear();
            error();
        }
        return c;
    }

    private static Call call() {
        try {
            return CALL.get();
        } catch (Throwable t) {
            error();
            return null;
        }
    }

    /**
     * Advice exit: at the outermost call, emits the bytes between each
     * buffer's entry position and its current position, which is the
     * plaintext the call consumed (wrap) or produced (unwrap). A connection's
     * first unwrap that consumed TLS bytes sends a RECV frame even without
     * plaintext (a handshake unwrap), which ties the connection to its socket
     * in the kernel; so does every wrap that produced TLS bytes without
     * plaintext, with an empty SEND, which announces the write after it. When
     * the call's result is CLOSED, records that direction as closed, and
     * sends a CLOSE frame once the connection can carry no more responses.
     *
     * @param result the call's SSLEngineResult; null when it threw
     */
    public static void exit(Call c, Object engine, byte op, Object result) {
        if (c == null) {
            return;
        }
        if (--c.depth > 0) {
            return;
        }
        c.depth = 0;
        try {
            if (c.recording) {
                long total = consumed(c);
                if (total > 0 && active) {
                    emitData(c, engine, op, total);
                } else if (active && (op == Frame.OP_SEND ? produced(result) : consumed(result))) {
                    tie(c, engine, op);
                }
            }
            if (result instanceof SSLEngineResult
                    && ((SSLEngineResult) result).getStatus() == SSLEngineResult.Status.CLOSED && active) {
                closed(c, engine, op);
            }
        } catch (Throwable t) {
            error();
        } finally {
            c.clear();
        }
    }

    private static void emitData(Call c, Object engine, byte op, long total) throws Throwable {
        // A FileChannel write from an interrupted thread fails and closes
        // the channel; skip this call instead.
        if (Thread.currentThread().isInterrupted()) {
            DROPPED.increment();
            return;
        }
        Connections.Info conn = CONNECTIONS.get(engine, c.lookup);
        short flags = flags(conn, engine);
        if (op == Frame.OP_SEND) {
            // A wrap's output is written to the socket after it.
            flags |= Frame.FLAG_BEFORE_WRITE;
        }
        // Only a written RECV frame tied the connection; a dropped one
        // leaves the next to try.
        if (emit(c, op, flags, conn.id, (int) Math.min(total, Integer.MAX_VALUE)) && op == Frame.OP_RECV) {
            conn.recvSent = true;
        }
    }

    /**
     * Advice entry for the JDK's blocking {@code SSLSocket} streams: a read or
     * a write of a byte array. The call counts as in flight on its socket
     * until its exit has sent its frame, so a close on another thread sends
     * CLOSE after it (see {@link #socketClosed}). Returns null when the exit
     * has nothing to do.
     */
    public static Call enterStream(Object socket) {
        if (!active) {
            return null;
        }
        Call c = call();
        if (c == null || c.depth++ > 0) {
            return c;
        }
        c.clear();
        c.recording = true;
        try {
            Connections.Info conn = CONNECTIONS.get(socket, c.lookup);
            conn.streamEntered();
            c.stream = conn;
        } catch (Throwable t) {
            error();
        }
        return c;
    }

    /**
     * Advice exit for {@code SSLSocket} streams: emits the plaintext the call
     * read (RECV) or wrote (SEND), b[off, off + n). The socket is the
     * connection, and its first data frame is preceded by an ADDRESS frame
     * with the socket's addresses. A read that reached the end of the stream
     * (n == -1) records the inbound side as closed.
     *
     * @param n bytes read or written; -1 at the end of the stream; 0 when the call threw
     */
    public static void exitStream(Call c, Object socket, byte op, byte[] b, int off, int n) {
        if (c == null) {
            return;
        }
        if (--c.depth > 0) {
            return;
        }
        c.depth = 0;
        try {
            if (!c.recording || !active) {
                return;
            }
            if (n > 0 && b != null && off >= 0 && n <= b.length - off) {
                if (Thread.currentThread().isInterrupted()) {
                    DROPPED.increment();
                    return;
                }
                Connections.Info conn = c.stream != null ? c.stream : CONNECTIONS.get(socket, c.lookup);
                short flags = flags(conn, socket);
                int epoch = addressEpoch;
                if (conn.addressEpoch != epoch) {
                    address(c, conn, socket, flags, epoch);
                }
                c.array = b;
                c.arrayOff = off;
                c.arrayLen = n;
                emit(c, op, flags, conn.id, n);
            } else if (n < 0 && op == Frame.OP_RECV) {
                // The end of the stream: a CLOSE when the inbound side ends
                // the connection (a client's), after any read in flight.
                Connections.Info conn = c.stream != null ? c.stream : CONNECTIONS.get(socket, c.lookup);
                short role = flags(conn, socket);
                if (conn.closed(false, role) && !conn.deferClose(c.stream != null)) {
                    sendClose(c, conn, role);
                }
            }
        } catch (Throwable t) {
            error();
        } finally {
            // Whether or not capture is still on, so the count cannot stick.
            Connections.Info conn = c.stream;
            c.clear();
            if (conn != null && conn.streamExited()) {
                try {
                    if (active) {
                        sendClose(c, conn, flags(conn, socket));
                    } else {
                        conn.closeAttempted(false);
                    }
                } catch (Throwable t) {
                    error();
                }
            }
        }
    }

    /**
     * Sends a socket's ADDRESS frame: its local and remote addresses, which
     * the kernel gives every event of the connection. Recorded for epoch once
     * written; a dropped one (interrupted thread, every buffer busy), or one
     * before the socket is connected, is retried at the next data frame.
     */
    private static void address(Call c, Connections.Info conn, Object socket, short flags, int epoch)
            throws Throwable {
        if (!(socket instanceof SSLSocket)) {
            return;
        }
        SSLSocket s = (SSLSocket) socket;
        InetAddress remote = s.getInetAddress();
        InetAddress local = s.getLocalAddress();
        int remotePort = s.getPort();
        int localPort = s.getLocalPort();
        if (remote == null || local == null || local.isAnyLocalAddress() || remotePort <= 0 || localPort <= 0) {
            return;
        }
        if (emitSmall(c, Frame.OP_ADDRESS, flags, conn.id, local, localPort, remote, remotePort)) {
            conn.addressEpoch = epoch;
        }
    }

    /**
     * Advice exit for {@code SSLSocket.close}: both directions are done, so a
     * connection that carried traffic gets its CLOSE frame, if it has not yet.
     * A read or write on another thread can have done its I/O but not yet
     * sent its frame; then the last of them sends the CLOSE after its frame,
     * so the Insights agent does not complete a response before its last
     * bytes (the same holds for a CLOSE at the end of the stream). A CLOSE
     * dropped there is not retried, as here.
     */
    public static void socketClosed(Object socket) {
        if (!active) {
            return;
        }
        Call c = call();
        if (c == null || c.depth > 0) {
            return;
        }
        try {
            Connections.Info conn = CONNECTIONS.find(socket, c.lookup);
            if (conn == null) {
                return;
            }
            short role = flags(conn, socket);
            if ((conn.closed(true, role) || conn.closed(false, role)) && !conn.deferClose(false)) {
                sendClose(c, conn, role);
            }
        } catch (Throwable t) {
            error();
        }
    }

    /** Sends a CLOSE that {@link Connections.Info#closed} said is due. */
    private static void sendClose(Call c, Connections.Info conn, short role) throws Throwable {
        boolean written = false;
        try {
            written = emitHeader(c, Frame.OP_CLOSE, role, conn.id);
        } finally {
            conn.closeAttempted(written);
        }
    }

    /**
     * Whether an unwrap consumed TLS bytes, which the socket read just
     * before: the evidence a tie frame needs.
     */
    private static boolean consumed(Object result) {
        return result instanceof SSLEngineResult && ((SSLEngineResult) result).bytesConsumed() > 0;
    }

    /**
     * Whether a wrap produced TLS bytes, which the socket write after it
     * carries: the evidence a SEND tie frame needs.
     */
    private static boolean produced(Object result) {
        return result instanceof SSLEngineResult && ((SSLEngineResult) result).bytesProduced() > 0;
    }

    /**
     * Sends an empty frame of op for an unwrap (RECV) that consumed TLS bytes,
     * or a wrap (SEND) that produced some, without plaintext: a handshake
     * call, by whose socket read just before or write just after the kernel
     * ties the connection to its socket. A RECV only at the connection's
     * first such unwrap (retried until written). A SEND at every such wrap:
     * each announces the thread's next write as this connection's, which the
     * kernel needs to see to tell when another connection's wrap waits for
     * the same write.
     */
    private static void tie(Call c, Object engine, byte op) throws Throwable {
        Connections.Info conn = CONNECTIONS.get(engine, c.lookup);
        if (op == Frame.OP_RECV) {
            if (conn.recvSent) {
                return;
            }
            // Set once written: a dropped tie (interrupted thread, every
            // buffer busy) is retried at the next such unwrap.
            if (emitHeader(c, Frame.OP_RECV, flags(conn, engine), conn.id)) {
                conn.recvSent = true;
            }
            return;
        }
        emitHeader(c, op, (short) (flags(conn, engine) | Frame.FLAG_BEFORE_WRITE), conn.id);
    }

    /** Records a CLOSED result, and sends CLOSE when the connection is done. */
    private static void closed(Call c, Object engine, byte op) throws Throwable {
        Connections.Info conn = CONNECTIONS.get(engine, c.lookup);
        short role = flags(conn, engine);
        if (conn.closed(op == Frame.OP_SEND, role)) {
            sendClose(c, conn, role);
        }
    }

    /** Sends a frame with no payload; false when it was dropped. */
    private static boolean emitHeader(Call c, byte op, short flags, long connId) throws Throwable {
        return emitSmall(c, op, flags, connId, null, 0, null, 0);
    }

    /**
     * Sends a frame with no payload, or an ADDRESS frame when local is set;
     * false when it was dropped.
     */
    private static boolean emitSmall(Call c, byte op, short flags, long connId, InetAddress local, int localPort,
                                     InetAddress remote, int remotePort) throws Throwable {
        if (Thread.currentThread().isInterrupted()) {
            DROPPED.increment();
            return false;
        }
        Pool p = pool;
        int idx = p.acquire(c);
        if (idx < 0) {
            DROPPED.increment();
            return false;
        }
        try {
            Slot s = p.slots[idx];
            ByteBuffer f = s.buf;
            int room = Math.max(captureCap, Frame.ADDRESS_SIZE);
            if (f == null || f.capacity() < Frame.HEADER_SIZE + room) {
                s.buf = f = Frame.allocate(room);
            }
            f.clear();
            int len = 0;
            if (local != null) {
                Frame.putAddress(f, Frame.HEADER_SIZE, local, localPort, remote, remotePort);
                len = Frame.ADDRESS_SIZE;
            }
            Frame.putHeader(f, op, flags, len, connId, null, 0, len);
            f.limit(Frame.HEADER_SIZE + len);
            if (write(s, f)) {
                FRAMES.increment();
                return true;
            }
            DROPPED.increment();
            return false;
        } finally {
            p.release(idx);
        }
    }

    private static long consumed(Call c) {
        if (c.single != null) {
            return Math.max(0, c.single.position() - c.singlePos);
        }
        long total = 0;
        for (int i = 0; i < c.len; i++) {
            ByteBuffer b = c.bufs[c.off + i];
            int start = c.pos[i];
            if (b != null && start >= 0 && b.position() > start) {
                total += b.position() - start;
            }
        }
        return total;
    }

    /** A frame's flags for conn: its role, and whether it is a blocking socket's. */
    private static short flags(Connections.Info conn, Object owner) {
        short flags = roleFlags(conn, owner);
        return owner instanceof SSLSocket ? (short) (flags | Frame.FLAG_SOCKET) : flags;
    }

    private static short roleFlags(Connections.Info conn, Object engine) {
        short flags = conn.roleFlags;
        if (flags == 0 && (engine instanceof SSLEngine || engine instanceof SSLSocket)) {
            try {
                boolean client = engine instanceof SSLEngine
                        ? ((SSLEngine) engine).getUseClientMode()
                        : ((SSLSocket) engine).getUseClientMode();
                flags = (short) (Frame.FLAG_ROLE_KNOWN | (client ? Frame.FLAG_CLIENT_MODE : 0));
                conn.roleFlags = flags;
            } catch (Throwable t) {
                // Unknown role; the Insights agent infers it from the traffic.
            }
        }
        return flags;
    }

    /** Writes a frame with the call's bytes; false when it was dropped. */
    private static boolean emit(Call c, byte op, short flags, long connId, int total) throws Throwable {
        Pool p = pool;
        int idx = p.acquire(c);
        if (idx < 0) {
            DROPPED.increment();
            return false;
        }
        try {
            Slot s = p.slots[idx];
            int cap = captureCap;
            ByteBuffer f = s.buf;
            if (f == null || f.capacity() < Frame.HEADER_SIZE + cap) {
                s.buf = f = Frame.allocate(cap);
            }
            f.clear();
            f.position(Frame.HEADER_SIZE);
            if (c.array != null) {
                f.put(c.array, c.arrayOff, Math.min(c.arrayLen, cap));
            } else if (c.single != null) {
                copy(f, c.single, c.singlePos, cap);
            } else {
                for (int i = 0; i < c.len && f.position() - Frame.HEADER_SIZE < cap; i++) {
                    ByteBuffer src = c.bufs[c.off + i];
                    if (src != null && c.pos[i] >= 0) {
                        copy(f, src, c.pos[i], cap);
                    }
                }
            }
            Frame.putHeader(f, op, flags, f.position() - Frame.HEADER_SIZE, connId, null, 0, total);
            f.flip();
            if (write(s, f)) {
                FRAMES.increment();
                return true;
            }
            DROPPED.increment();
            return false;
        } finally {
            p.release(idx);
        }
    }

    /** Appends src's bytes from start to its position, up to the frame's cap, leaving src untouched. */
    private static void copy(ByteBuffer f, ByteBuffer src, int start, int cap) throws Throwable {
        int room = cap - (f.position() - Frame.HEADER_SIZE);
        int n = Math.min(src.position() - start, room);
        if (n <= 0) {
            return;
        }
        if (src.hasArray()) {
            f.put(src.array(), src.arrayOffset() + start, n);
        } else if (ABSOLUTE_PUT != null) {
            int at = f.position();
            ByteBuffer unused = (ByteBuffer) ABSOLUTE_PUT.invokeExact(f, at, src, start, n);
            f.position(at + n);
        } else {
            // JDK 8 to 15, direct or read-only buffers: copy through a view.
            ByteBuffer view = src.duplicate();
            view.limit(start + n);
            view.position(start);
            f.put(view);
        }
    }

    /** Returns false when the frame was not written because the thread was interrupted. */
    private static boolean write(Slot s, ByteBuffer f) throws IOException {
        String log = frameLog;
        if (log != null) {
            synchronized (LOG_LOCK) {
                writeLog(log, f);
            }
            return true;
        }
        FileChannel ch = s.channel;
        if (ch == null || !ch.isOpen()) {
            s.channel = ch = new FileOutputStream("/dev/null").getChannel();
        }
        try {
            ch.write(f, Frame.MAGIC);
            return true;
        } catch (ClosedByInterruptException e) {
            // Interrupted during the write, which closed the channel; it is
            // reopened next time.
            return false;
        }
    }

    /** Caller holds LOG_LOCK. */
    private static void writeLog(String log, ByteBuffer f) throws IOException {
        FileChannel ch = logChannel;
        if (ch == null || !ch.isOpen()) {
            logChannel = ch = new FileOutputStream(log, true).getChannel();
        }
        while (f.hasRemaining()) {
            ch.write(f);
        }
    }

    /**
     * Sends a HEARTBEAT frame. Called only by the agent's own thread; works
     * while dormant too, so the Insights agent can see the agent is alive.
     */
    public static void heartbeat(byte[] payload) {
        if (!started) {
            return;
        }
        try {
            synchronized (HEARTBEAT_LOCK) {
                addressEpoch++;
                ByteBuffer f = heartbeatBuf;
                if (f == null || f.capacity() < Frame.HEADER_SIZE + payload.length) {
                    heartbeatBuf = f = Frame.allocate(payload.length);
                }
                f.clear();
                f.position(Frame.HEADER_SIZE);
                f.put(payload);
                Frame.putHeader(f, Frame.OP_HEARTBEAT, (short) 0, payload.length, 0, null, 0, payload.length);
                f.flip();
                String log = frameLog;
                if (log != null) {
                    synchronized (LOG_LOCK) {
                        writeLog(log, f);
                    }
                    return;
                }
                FileChannel ch = heartbeatChannel;
                if (ch == null || !ch.isOpen()) {
                    heartbeatChannel = ch = new FileOutputStream("/dev/null").getChannel();
                }
                ch.write(f, Frame.MAGIC);
            }
        } catch (Throwable t) {
            error();
        }
    }

    static void error() {
        error(System.nanoTime());
    }

    /**
     * Counts an internal error at {@code now}. Switches the bridge off once
     * ERROR_BUDGET errors fall within ERROR_WINDOW_NANOS of each other: a
     * rolling window over the last ERROR_BUDGET errors, so a burst is caught
     * wherever it starts.
     */
    static void error(long now) {
        ERRORS.increment();
        boolean switchOff;
        synchronized (ERROR_LOCK) {
            ERROR_TIMES[errorNext] = now;
            errorNext = (errorNext + 1) % ERROR_BUDGET;
            if (errorCount < ERROR_BUDGET) {
                errorCount++;
            }
            // Once full, errorNext is the oldest of the last ERROR_BUDGET errors.
            switchOff = errorCount == ERROR_BUDGET && now - ERROR_TIMES[errorNext] <= ERROR_WINDOW_NANOS && !broken;
            if (switchOff) {
                broken = true;
            }
        }
        if (switchOff) {
            switchOff();
            System.err.println("[postman-insights-agent] too many internal errors; HTTPS capture switched off for this JVM");
        }
    }

    /** Testing only: the number of frame buffers. */
    static int poolSize() {
        return pool.slots.length;
    }

    /** Testing only: marks every frame buffer busy (true) or free (false). */
    static void holdAllBuffers(boolean hold) {
        AtomicIntegerArray b = pool.busy;
        for (int i = 0; i < b.length(); i++) {
            b.set(i, hold ? 1 : 0);
        }
    }

    private static void closeQuietly(FileChannel ch) {
        if (ch != null) {
            try {
                ch.close();
            } catch (IOException ignored) {
                // Nothing to do.
            }
        }
    }

    private static MethodHandle absolutePut() {
        try {
            return MethodHandles.publicLookup().findVirtual(ByteBuffer.class, "put",
                    MethodType.methodType(ByteBuffer.class, int.class, ByteBuffer.class, int.class, int.class));
        } catch (Throwable t) {
            return null;
        }
    }
}
