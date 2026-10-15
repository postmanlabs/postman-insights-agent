package com.postman.insights.agent.bootstrap;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * The frame format the agent hands to the kernel.
 *
 * <p>One of three copies of the format, which must stay in sync:
 * {@code ebpf/programs/java_frame.h} (kernel), {@code ebpf/javatls/frame.go}
 * (Go) and this class. The example frames in
 * {@code ebpf/javatls/testdata/frames-v1.json} are checked by the Go tests and
 * by {@code FrameTest}.
 *
 * <p>Layout (multi-byte fields little-endian, except the peer port):
 * <pre>
 *  0  u8      version
 *  1  u8      op
 *  2  u16     flags
 *  4  u32     payload_len   payload bytes in this frame
 *  8  u64     conn_id       unique per connection within the JVM
 * 16  u8[16]  peer_addr     IPv6 or IPv4-mapped; zero when unknown
 * 32  u16     peer_port     network byte order; zero when unknown
 * 34  u16     reserved      zero
 * 36  u32     total_len     bytes the engine call produced or consumed
 * 40  ...     payload
 * </pre>
 *
 * <p>An ADDRESS frame's payload, {@link #ADDRESS_SIZE} bytes, is the
 * connection's TCP addresses (see {@link #putAddress}).
 */
public final class Frame {
    /** Write offset that marks a frame ("PMINSIGH" as a little-endian long). */
    public static final long MAGIC = 0x504D494E53494748L;

    public static final byte VERSION_1 = 1;
    public static final int HEADER_SIZE = 40;

    public static final byte OP_SEND = 1;
    public static final byte OP_RECV = 2;
    public static final byte OP_HEARTBEAT = 3;
    public static final byte OP_CLOSE = 4;
    /** The connection's addresses, which the agent knows for a blocking socket. */
    public static final byte OP_ADDRESS = 5;

    public static final int ADDRESS_SIZE = 40;

    public static final short FLAG_ROLE_KNOWN = 0x1;
    public static final short FLAG_CLIENT_MODE = 0x2;
    public static final short FLAG_PEER_KNOWN = 0x4;
    /**
     * A blocking socket's frame: the connection's addresses come in an
     * ADDRESS frame, so the kernel never ties it to the socket its thread
     * read, which a read that returns already decrypted plaintext did not.
     */
    public static final short FLAG_SOCKET = 0x8;

    private static final byte FAMILY_INET = 2;
    private static final byte FAMILY_INET6 = 10;

    private static final int OFF_VERSION = 0;
    private static final int OFF_OP = 1;
    private static final int OFF_FLAGS = 2;
    private static final int OFF_PAYLOAD_LEN = 4;
    private static final int OFF_CONN_ID = 8;
    private static final int OFF_PEER_ADDR = 16;
    private static final int OFF_PEER_PORT = 32;
    private static final int OFF_RESERVED = 34;
    private static final int OFF_TOTAL_LEN = 36;

    private Frame() {}

    /** Allocates a direct buffer for frames with up to {@code maxPayload} payload bytes. */
    public static ByteBuffer allocate(int maxPayload) {
        return ByteBuffer.allocateDirect(HEADER_SIZE + maxPayload).order(ByteOrder.LITTLE_ENDIAN);
    }

    /**
     * Writes the header at the start of {@code buf}, which must be little-endian.
     * Uses absolute puts, so the buffer's position is unchanged.
     *
     * @param peerAddr 16 bytes (IPv6, or IPv4-mapped), or null when unknown
     */
    public static void putHeader(ByteBuffer buf, byte op, short flags, int payloadLen, long connId,
                                 byte[] peerAddr, int peerPort, int totalLen) {
        buf.put(OFF_VERSION, VERSION_1);
        buf.put(OFF_OP, op);
        buf.putShort(OFF_FLAGS, flags);
        buf.putInt(OFF_PAYLOAD_LEN, payloadLen);
        buf.putLong(OFF_CONN_ID, connId);
        for (int i = 0; i < 16; i++) {
            buf.put(OFF_PEER_ADDR + i, peerAddr == null ? 0 : peerAddr[i]);
        }
        buf.put(OFF_PEER_PORT, (byte) (peerPort >>> 8));
        buf.put(OFF_PEER_PORT + 1, (byte) peerPort);
        buf.putShort(OFF_RESERVED, (short) 0);
        buf.putInt(OFF_TOTAL_LEN, totalLen);
    }

    /**
     * Writes an ADDRESS frame's payload at {@code at} in {@code buf}, which
     * must be little-endian, with absolute puts. The layout is the kernel's
     * {@code struct conn_tuple}:
     * <pre>
     *  0  u8      family       2 (IPv4) or 10 (IPv6, including IPv4-mapped)
     *  1  u8[3]   zero
     *  4  u16     local_port   little-endian
     *  6  u16     remote_port  little-endian
     *  8  u8[16]  local_addr   network byte order; IPv4 in the first 4 bytes, the rest zero
     * 24  u8[16]  remote_addr  the same
     * </pre>
     * Family 2 when both addresses are IPv4, else 10, with an IPv4 address
     * mapped.
     */
    public static void putAddress(ByteBuffer buf, int at, InetAddress local, int localPort,
                                  InetAddress remote, int remotePort) {
        boolean inet = local instanceof Inet4Address && remote instanceof Inet4Address;
        buf.put(at, inet ? FAMILY_INET : FAMILY_INET6);
        buf.put(at + 1, (byte) 0);
        buf.put(at + 2, (byte) 0);
        buf.put(at + 3, (byte) 0);
        buf.putShort(at + 4, (short) localPort);
        buf.putShort(at + 6, (short) remotePort);
        putAddr(buf, at + 8, local, inet);
        putAddr(buf, at + 24, remote, inet);
    }

    private static void putAddr(ByteBuffer buf, int at, InetAddress addr, boolean inet) {
        byte[] a = addr.getAddress();
        for (int i = 0; i < 16; i++) {
            buf.put(at + i, (byte) 0);
        }
        if (a.length == 16 || inet) {
            for (int i = 0; i < a.length; i++) {
                buf.put(at + i, a[i]);
            }
            return;
        }
        // IPv4 next to an IPv6 address: IPv4-mapped.
        buf.put(at + 10, (byte) 0xff);
        buf.put(at + 11, (byte) 0xff);
        for (int i = 0; i < 4; i++) {
            buf.put(at + 12 + i, a[i]);
        }
    }
}
