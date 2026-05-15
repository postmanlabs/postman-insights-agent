// SPDX-License-Identifier: Apache-2.0

package com.postman.insights.agent.ebpf;

/**
 * Builds the 41-byte packed {@code java_packet} header (matching
 * {@code ebpf/programs/java_tls.bpf.c}) plus payload in off-heap memory,
 * and dispatches it through {@link NativeMemory#doIoctl(int, long, long)}.
 *
 * <p>Wire format — must match the C side exactly:</p>
 * <pre>
 *   offset  size  field
 *   ------  ----  -----
 *        0     1  operation       (1 = SEND, 2 = RECV)
 *        1    16  s_addr          (IPv6; IPv4 in first 4 bytes for v4 sockets)
 *       17    16  d_addr
 *       33     2  s_port          (little-endian / host order on amd64+arm64)
 *       35     2  d_port
 *       37     4  buf_len         (little-endian / host order)
 *       41   ...  buffer
 * </pre>
 *
 * <p>For Phase 5b.1 the only producer is {@link com.postman.insights.agent.Main};
 * Phase 5b.2 adds a thread-local pool and ByteBuffer extraction from
 * {@code SSLEngine} advice.</p>
 */
public final class IoctlPacket {

    /** SEND — local process is writing plaintext (egress, like SSL_write). */
    public static final byte OP_SEND = 1;

    /** RECV — local process has just decrypted plaintext (ingress, like SSL_read). */
    public static final byte OP_RECV = 2;

    public static final int HEADER_SIZE      = 41;
    private static final int OFF_OP          = 0;
    private static final int OFF_SADDR       = 1;
    private static final int OFF_DADDR       = 17;
    private static final int OFF_SPORT       = 33;
    private static final int OFF_DPORT       = 35;
    private static final int OFF_BUFLEN      = 37;

    private IoctlPacket() {}

    /**
     * Build a packet in fresh off-heap memory and send it through the kernel
     * kprobe. Memory is freed before this method returns.
     *
     * @param op             {@link #OP_SEND} or {@link #OP_RECV}
     * @param srcIpv4        4-byte IPv4 in host byte order; e.g. {@code 0x7f000001} for 127.0.0.1
     * @param srcPort        source TCP port (0–65535)
     * @param dstIpv4        4-byte IPv4 dest
     * @param dstPort        dest TCP port
     * @param payload        plaintext bytes (must be ≤ ~32 KiB; longer payloads
     *                       are kernel-truncated to {@code MAX_EVENT_PAYLOAD})
     * @return packed result from {@link NativeMemory#doIoctl(int, long, long)}.
     *         The kprobe runs before the kernel rejects the unknown ioctl, so
     *         a return of -1/ENOTTY ({@code errno=25}) is the expected
     *         successful path.
     */
    public static long send(
            byte op,
            int  srcIpv4, int srcPort,
            int  dstIpv4, int dstPort,
            byte[] payload) {
        int payloadLen = (payload == null) ? 0 : payload.length;
        long total = (long) HEADER_SIZE + payloadLen;
        long addr = NativeMemory.allocateMemory(total);
        try {
            NativeMemory.putByte(addr + OFF_OP, op);
            writeIpv4(addr + OFF_SADDR, srcIpv4);
            writeIpv4(addr + OFF_DADDR, dstIpv4);
            NativeMemory.putU16LE(addr + OFF_SPORT, srcPort & 0xffff);
            NativeMemory.putU16LE(addr + OFF_DPORT, dstPort & 0xffff);
            NativeMemory.putU32LE(addr + OFF_BUFLEN, payloadLen);
            if (payloadLen > 0) {
                NativeMemory.putBytes(addr + HEADER_SIZE, payload, 0, payloadLen);
            }
            return NativeMemory.doIoctl(NativeMemory.IOCTL_FD,
                                        NativeMemory.IOCTL_MAGIC,
                                        addr);
        } finally {
            NativeMemory.freeMemory(addr);
        }
    }

    /** Writes a 4-byte IPv4 address at addr, leaving bytes 4..15 zero (v4-mapped). */
    private static void writeIpv4(long addr, int ipv4) {
        NativeMemory.putByte(addr,     (byte) ((ipv4 >> 24) & 0xff));
        NativeMemory.putByte(addr + 1, (byte) ((ipv4 >> 16) & 0xff));
        NativeMemory.putByte(addr + 2, (byte) ((ipv4 >> 8)  & 0xff));
        NativeMemory.putByte(addr + 3, (byte) (ipv4         & 0xff));
        // bytes 4..15 are zero from allocateMemory's setMemory() init.
    }
}
