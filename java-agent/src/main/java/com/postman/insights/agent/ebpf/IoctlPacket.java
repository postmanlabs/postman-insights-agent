// SPDX-License-Identifier: Apache-2.0

package com.postman.insights.agent.ebpf;

/**
 * Builds the 41-byte packed {@code java_packet} header (matching
 * {@code ebpf/programs/java_tls.bpf.c}) plus payload in off-heap memory,
 * and dispatches it through {@link NativeMemory#doIoctl(int, long, long)}.
 *
 * <p>Wire format (frozen — must match the C side exactly):</p>
 * <pre>
 *   offset  size  field
 *   ------  ----  -----
 *        0     1  operation       (1 = SEND, 2 = RECV)
 *        1    16  s_addr          (IPv6; IPv4 in first 4 bytes for v4 sockets)
 *       17    16  d_addr
 *       33     2  s_port          (little-endian / host order)
 *       35     2  d_port
 *       37     4  buf_len
 *       41   ...  buffer
 * </pre>
 *
 * <p>Two send paths:</p>
 * <ul>
 *   <li>{@link #sendOnce} — allocates fresh off-heap memory for one ioctl,
 *       frees it after. Used by the 5b.1 spike CLI ({@code Main}).</li>
 *   <li>{@link #sendThreadLocal} — writes into the thread-local 64 KiB
 *       buffer from {@link NativeMemory#threadLocalBuffer()}. Used by
 *       agent advice paths where allocator pressure matters.</li>
 * </ul>
 */
public final class IoctlPacket {

    public static final byte OP_SEND = 1;
    public static final byte OP_RECV = 2;

    public static final int HEADER_SIZE  = 41;
    private static final int OFF_OP      = 0;
    private static final int OFF_SADDR   = 1;
    private static final int OFF_DADDR   = 17;
    private static final int OFF_SPORT   = 33;
    private static final int OFF_DPORT   = 35;
    private static final int OFF_BUFLEN  = 37;

    private IoctlPacket() {}

    /**
     * One-shot send: allocates a fresh off-heap segment, frees it before
     * returning. Convenient for the spike CLI; not for hot paths.
     */
    public static long sendOnce(
            byte op,
            int  srcIpv4, int srcPort,
            int  dstIpv4, int dstPort,
            byte[] payload) {
        int payloadLen = (payload == null) ? 0 : payload.length;
        long total = (long) HEADER_SIZE + payloadLen;
        long addr = NativeMemory.allocateMemory(total);
        try {
            writeHeader(addr, op, srcIpv4, srcPort, dstIpv4, dstPort, payloadLen);
            if (payloadLen > 0) {
                NativeMemory.putBytes(addr + HEADER_SIZE, payload, 0, payloadLen);
            }
            return NativeMemory.doIoctl(NativeMemory.IOCTL_FD,
                                        NativeMemory.IOCTL_MAGIC, addr);
        } finally {
            NativeMemory.freeMemory(addr);
        }
    }

    /**
     * Thread-local fast path: write the header + payload into the calling
     * thread's reusable off-heap buffer, then call {@code ioctl}. The
     * payload is clamped to {@code threadLocalBufferSize() - HEADER_SIZE}.
     *
     * <p>Used by agent advice (one allocation per Thread for the lifetime
     * of the thread, not per request).</p>
     */
    public static long sendThreadLocal(
            byte op,
            int  srcIpv4, int srcPort,
            int  dstIpv4, int dstPort,
            byte[] payload, int payloadOff, int payloadLen) {
        if (payload == null || payloadLen <= 0) {
            return 0;
        }
        int maxPayload = NativeMemory.threadLocalBufferSize() - HEADER_SIZE;
        if (payloadLen > maxPayload) {
            payloadLen = maxPayload;
        }
        long addr = NativeMemory.threadLocalBuffer();
        writeHeader(addr, op, srcIpv4, srcPort, dstIpv4, dstPort, payloadLen);
        NativeMemory.putBytes(addr + HEADER_SIZE, payload, payloadOff, payloadLen);
        return NativeMemory.doIoctl(NativeMemory.IOCTL_FD,
                                    NativeMemory.IOCTL_MAGIC, addr);
    }

    private static void writeHeader(
            long addr, byte op,
            int srcIpv4, int srcPort,
            int dstIpv4, int dstPort,
            int payloadLen) {
        // Zero just the header (the per-call buffer is fresh; the thread-
        // local buffer carries stale bytes past the new header+payload but
        // the kernel only reads buf_len bytes so that's harmless).
        for (int i = 0; i < HEADER_SIZE; i++) {
            NativeMemory.putByte(addr + i, (byte) 0);
        }
        NativeMemory.putByte(addr + OFF_OP, op);
        writeIpv4(addr + OFF_SADDR, srcIpv4);
        writeIpv4(addr + OFF_DADDR, dstIpv4);
        NativeMemory.putU16LE(addr + OFF_SPORT, srcPort & 0xffff);
        NativeMemory.putU16LE(addr + OFF_DPORT, dstPort & 0xffff);
        NativeMemory.putU32LE(addr + OFF_BUFLEN, payloadLen);
    }

    /** Writes a 4-byte IPv4 address at addr, leaving bytes 4..15 zero (v4-mapped). */
    private static void writeIpv4(long addr, int ipv4) {
        NativeMemory.putByte(addr,     (byte) ((ipv4 >> 24) & 0xff));
        NativeMemory.putByte(addr + 1, (byte) ((ipv4 >> 16) & 0xff));
        NativeMemory.putByte(addr + 2, (byte) ((ipv4 >> 8)  & 0xff));
        NativeMemory.putByte(addr + 3, (byte) (ipv4         & 0xff));
    }
}
