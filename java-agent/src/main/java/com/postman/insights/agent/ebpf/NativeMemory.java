// SPDX-License-Identifier: Apache-2.0

package com.postman.insights.agent.ebpf;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;

import sun.misc.Unsafe;

/**
 * Off-heap memory + JNI glue for the postman-java-agent.
 *
 * <p>Two responsibilities:</p>
 * <ol>
 *   <li>Allocate / free off-heap memory via {@link Unsafe} (works JDK 8–21
 *       with no preview flags or {@code --add-opens}).</li>
 *   <li>Expose {@link #doIoctl(int, long, long)} which dispatches into
 *       libpostman_jni.so → {@code ioctl(2)}.</li>
 * </ol>
 *
 * <p><b>Native-library resolution order:</b></p>
 * <ol>
 *   <li>{@code -Dpostman.agent.native.lib=/abs/path/to/libpostman_jni.so}
 *       → loaded via {@link System#load}. Used by the 5b.1 spike.</li>
 *   <li>Otherwise, unpack from
 *       {@code META-INF/native/linux-<arch>/libpostman_jni.so} bundled in
 *       the agent JAR to a per-process temp file, then {@link System#load}.
 *       Used by the {@code -javaagent:} attach path.</li>
 *   <li>Otherwise, {@link System#loadLibrary "postman_jni"} which honours
 *       {@code -Djava.library.path} and {@code LD_LIBRARY_PATH}.</li>
 * </ol>
 *
 * <p><b>Thread-local off-heap buffer:</b> {@link #threadLocalBuffer()} gives
 * each thread a reusable 64 KiB segment. The agent advice paths use this to
 * avoid per-call {@code allocateMemory}/{@code freeMemory} pressure on the
 * critical {@code SSLEngine} path; the 5b.1 spike's per-call allocator
 * remains for {@link IoctlPacket#sendOnce}.</p>
 */
public final class NativeMemory {

    /** Magic ioctl command — must match {@code JAVA_IOCTL_MAGIC} in java_tls.bpf.c. */
    public static final long IOCTL_MAGIC = 0x0b10b1L;

    /** Sentinel fd checked by the kernel-side kprobe. */
    public static final int  IOCTL_FD = 0;

    /** Thread-local buffer size: 64 KiB. Holds the 41-byte header plus up
     *  to ~65 KiB of payload — the kernel program clamps to MAX_EVENT_PAYLOAD
     *  (currently 1 KiB) anyway, so 64 KiB is generous. */
    public static final int THREAD_BUFFER_SIZE = 64 * 1024;

    private static final Unsafe UNSAFE = getUnsafeOrFail();

    static {
        loadNative();
    }

    private NativeMemory() {}

    // -- JNI -----------------------------------------------------------------

    private static native long doIoctlNative(int fd, long cmd, long arg);

    public static long doIoctl(int fd, long cmd, long arg) {
        return doIoctlNative(fd, cmd, arg);
    }

    public static int  ioctlReturn(long packed) { return (int) packed; }
    public static int  ioctlErrno(long packed)  { return (int) (packed >>> 32); }

    // -- Off-heap memory (per-call) ------------------------------------------

    /** Allocate {@code size} bytes off-heap, zeroed. Caller MUST {@link #freeMemory(long)} it. */
    public static long allocateMemory(long size) {
        long addr = UNSAFE.allocateMemory(size);
        UNSAFE.setMemory(addr, size, (byte) 0);
        return addr;
    }

    public static void freeMemory(long addr) { UNSAFE.freeMemory(addr); }

    // -- Off-heap memory (thread-local, agent fast-path) ---------------------

    /**
     * Lazily-allocated per-thread off-heap segment. Each thread gets its own
     * {@link #THREAD_BUFFER_SIZE}-byte chunk on first call; subsequent calls
     * return the same address. Memory is released when the thread exits via
     * {@link ThreadLocal#remove()} on the {@link FinalizableBuffer} guard.
     *
     * <p>Returns the base address of the segment, zeroed on first allocation
     * only (not on every call — agent advice is responsible for not reading
     * stale bytes).</p>
     */
    public static long threadLocalBuffer() {
        FinalizableBuffer buf = THREAD_BUFFER.get();
        return buf.addr;
    }

    /** Size of the thread-local buffer (convenience for advice paths). */
    public static int threadLocalBufferSize() { return THREAD_BUFFER_SIZE; }

    private static final ThreadLocal<FinalizableBuffer> THREAD_BUFFER =
            ThreadLocal.withInitial(() -> new FinalizableBuffer(THREAD_BUFFER_SIZE));

    /**
     * Holds the off-heap address for a thread-local buffer. When the
     * {@link ThreadLocal} entry is cleared (e.g. thread exit, GC), this
     * object becomes unreachable and its finalizer (deprecated but still
     * functional on JDK 17) returns the memory.
     *
     * <p>This is a deliberate use of {@code finalize()} for off-heap cleanup
     * in a long-lived agent. Replacing with a {@link java.lang.ref.Cleaner}
     * is a 5b.3 follow-up; for the spike, finalisation is sufficient.</p>
     */
    @SuppressWarnings("removal")  // finalize() is deprecated but not removed
    private static final class FinalizableBuffer {
        final long addr;
        FinalizableBuffer(int size) {
            this.addr = allocateMemory(size);
        }
        @Override
        protected void finalize() {
            try { freeMemory(addr); } catch (Throwable ignored) { /* shutdown */ }
        }
    }

    // -- Byte-addressable accessors -----------------------------------------

    public static void putByte(long addr, byte v)   { UNSAFE.putByte(addr, v); }
    public static void putBytes(long addr, byte[] src, int srcOff, int len) {
        UNSAFE.copyMemory(src, Unsafe.ARRAY_BYTE_BASE_OFFSET + srcOff,
                          null, addr, len);
    }
    public static void putU16LE(long addr, int v) {
        UNSAFE.putByte(addr,     (byte) (v       & 0xff));
        UNSAFE.putByte(addr + 1, (byte) ((v >> 8) & 0xff));
    }
    public static void putU32LE(long addr, int v) {
        UNSAFE.putByte(addr,     (byte) (v        & 0xff));
        UNSAFE.putByte(addr + 1, (byte) ((v >> 8)  & 0xff));
        UNSAFE.putByte(addr + 2, (byte) ((v >> 16) & 0xff));
        UNSAFE.putByte(addr + 3, (byte) ((v >> 24) & 0xff));
    }

    // -- Internals -----------------------------------------------------------

    private static Unsafe getUnsafeOrFail() {
        try {
            Field f = Unsafe.class.getDeclaredField("theUnsafe");
            f.setAccessible(true);
            return (Unsafe) f.get(null);
        } catch (ReflectiveOperationException e) {
            throw new ExceptionInInitializerError(
                    "postman-java-agent: cannot access sun.misc.Unsafe — " +
                    "JVM args likely need --add-opens java.base/sun.misc=ALL-UNNAMED " +
                    "(or run on a JDK where Unsafe is still reachable). " + e);
        }
    }

    private static void loadNative() {
        // 1. Explicit absolute path (5b.1 spike compat).
        String explicit = System.getProperty("postman.agent.native.lib");
        if (explicit != null && !explicit.isEmpty()) {
            File p = new File(explicit);
            if (!p.exists()) {
                throw new ExceptionInInitializerError(
                        "postman-java-agent: -Dpostman.agent.native.lib=" + p + " does not exist");
            }
            loadSafely(p.getAbsolutePath());
            return;
        }

        // 2. Unpack from JAR if we find the right resource.
        String osArch = detectOsArch();
        String resource = "META-INF/native/" + osArch + "/libpostman_jni.so";
        if (tryUnpackAndLoad(resource)) {
            return;
        }

        // 3. Last resort — System.loadLibrary via java.library.path / LD_LIBRARY_PATH.
        try {
            System.loadLibrary("postman_jni");
        } catch (UnsatisfiedLinkError e) {
            if (isAlreadyLoadedError(e)) {
                return;  // another classloader already loaded it process-wide
            }
            throw new ExceptionInInitializerError(
                    "postman-java-agent: failed to load libpostman_jni.so. " +
                    "Tried: -Dpostman.agent.native.lib, META-INF/native/" + osArch +
                    "/, and java.library.path. Last error: " + e.getMessage());
        }
    }

    /** {@link System#load} that tolerates the duplicate-load case which
     *  happens when both the app-loader and bootstrap copies of this class
     *  initialise (we put the agent JAR on bootstrap in Agent.premain). */
    private static void loadSafely(String absPath) {
        try {
            System.load(absPath);
        } catch (UnsatisfiedLinkError e) {
            if (!isAlreadyLoadedError(e)) throw e;
        }
    }

    private static boolean isAlreadyLoadedError(UnsatisfiedLinkError e) {
        String m = e.getMessage();
        return m != null && m.contains("already loaded");
    }

    private static boolean tryUnpackAndLoad(String resource) {
        ClassLoader cl = NativeMemory.class.getClassLoader();
        if (cl == null) {
            cl = ClassLoader.getSystemClassLoader();
        }
        try (InputStream in = cl.getResourceAsStream(resource)) {
            if (in == null) {
                return false;
            }
            File tmp = File.createTempFile("postman-jni-", ".so");
            tmp.deleteOnExit();
            try (OutputStream out = new FileOutputStream(tmp)) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) > 0) {
                    out.write(buf, 0, n);
                }
            }
            try {
                System.load(tmp.getAbsolutePath());
            } catch (UnsatisfiedLinkError e) {
                if (!isAlreadyLoadedError(e)) throw e;
            }
            return true;
        } catch (IOException e) {
            return false;
        } catch (UnsatisfiedLinkError e) {
            return false;
        }
    }

    private static String detectOsArch() {
        String os = System.getProperty("os.name", "").toLowerCase().contains("linux") ? "linux" : "linux";
        String archProp = System.getProperty("os.arch", "").toLowerCase();
        String arch;
        switch (archProp) {
            case "amd64":
            case "x86_64":
                arch = "amd64"; break;
            case "aarch64":
            case "arm64":
                arch = "arm64"; break;
            default:
                arch = archProp;
        }
        return os + "-" + arch;
    }
}
