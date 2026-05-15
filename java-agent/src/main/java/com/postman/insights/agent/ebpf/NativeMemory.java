// SPDX-License-Identifier: Apache-2.0

package com.postman.insights.agent.ebpf;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;

import sun.misc.Unsafe;

/**
 * Phase 5b.1 native-memory + JNI glue.
 *
 * <p>Two responsibilities:</p>
 * <ol>
 *   <li>Allocate / free off-heap memory via {@link Unsafe} (works on JDK 8+
 *       without preview flags; 5c may add a {@code MemorySegment}
 *       fast-path for JDK 21+).</li>
 *   <li>Expose {@link #doIoctl(int, long, long)} which dispatches into
 *       libpostman_jni.so → {@code ioctl(2)}.</li>
 * </ol>
 *
 * <p>Library loading order:</p>
 * <ul>
 *   <li>If system property {@code postman.agent.native.lib} is set to an
 *       absolute path, that file is loaded via {@link System#load}.</li>
 *   <li>Otherwise we delegate to {@link System#loadLibrary} with the name
 *       {@code "postman_jni"}, which honors {@code -Djava.library.path}
 *       and {@code LD_LIBRARY_PATH}.</li>
 * </ul>
 *
 * <p>The unpack-from-JAR path (extract {@code META-INF/native/<os>-<arch>/}
 * to a temp dir) is 5b.2 work. For the 5b.1 spike we expect the operator
 * to point at the built {@code .so} directly.</p>
 */
public final class NativeMemory {

    /** Magic ioctl command — must match {@code JAVA_IOCTL_MAGIC} in java_tls.bpf.c. */
    public static final long IOCTL_MAGIC = 0x0b10b1L;

    /** Sentinel fd checked by the kernel-side kprobe. */
    public static final int  IOCTL_FD = 0;

    private static final Unsafe UNSAFE = getUnsafeOrFail();

    static {
        loadNative();
    }

    private NativeMemory() {}

    // -- JNI -----------------------------------------------------------------

    /**
     * Calls {@code ioctl(fd, cmd, (void*) arg)} in native code.
     *
     * @return packed result: high 32 bits = errno (0 if rc≥0); low 32 bits = ioctl rc.
     *         Decode with {@link #ioctlReturn(long)} and {@link #ioctlErrno(long)}.
     */
    private static native long doIoctlNative(int fd, long cmd, long arg);

    public static long doIoctl(int fd, long cmd, long arg) {
        return doIoctlNative(fd, cmd, arg);
    }

    public static int  ioctlReturn(long packed) { return (int) packed; }
    public static int  ioctlErrno(long packed)  { return (int) (packed >>> 32); }

    // -- Off-heap memory -----------------------------------------------------

    /** Allocate {@code size} bytes off-heap. Caller MUST {@link #freeMemory(long)} it. */
    public static long allocateMemory(long size) {
        long addr = UNSAFE.allocateMemory(size);
        UNSAFE.setMemory(addr, size, (byte) 0);
        return addr;
    }

    public static void freeMemory(long addr) { UNSAFE.freeMemory(addr); }

    // Byte-addressable accessors. Java is big-endian by default; we explicitly
    // write little-endian where the BPF program expects host order (which on
    // x86 + arm64 == little-endian — see ebpf/programs/java_tls.bpf.c).
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
        String explicit = System.getProperty("postman.agent.native.lib");
        if (explicit != null && !explicit.isEmpty()) {
            Path p = Path.of(explicit);
            if (!Files.exists(p)) {
                throw new ExceptionInInitializerError(
                        "postman-java-agent: -Dpostman.agent.native.lib=" + p +
                        " does not exist");
            }
            try {
                System.load(p.toAbsolutePath().toString());
            } catch (UnsatisfiedLinkError e) {
                throw new ExceptionInInitializerError(
                        "postman-java-agent: System.load failed for " + p +
                        ": " + e.getMessage());
            }
            return;
        }
        try {
            System.loadLibrary("postman_jni");
        } catch (UnsatisfiedLinkError e) {
            throw new ExceptionInInitializerError(
                    "postman-java-agent: System.loadLibrary(\"postman_jni\") failed. " +
                    "Either set -Dpostman.agent.native.lib=/abs/path/to/libpostman_jni.so " +
                    "or add the directory to -Djava.library.path / LD_LIBRARY_PATH. " +
                    "Cause: " + e.getMessage());
        }
    }
}
