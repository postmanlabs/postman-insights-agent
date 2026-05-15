// SPDX-License-Identifier: Apache-2.0

package com.postman.insights.agent;

import java.util.Locale;

import com.postman.insights.agent.ebpf.IoctlPacket;
import com.postman.insights.agent.ebpf.NativeMemory;

/**
 * Phase 5b.1 spike entry-point. Drives the JNI → eBPF kprobe bridge directly,
 * without any ByteBuddy / instrumentation. The Java-side analogue of
 * {@code test/java-tls-harness/harness.c}.
 *
 * <p>Usage:</p>
 * <pre>
 *   java -Djava.library.path=src/main/c/build \
 *        -jar build/libs/postman-java-agent.jar [mode]
 *
 *   mode:
 *     pair        (default)  one SEND (synthetic GET) + one RECV (synthetic 200)
 *     send        SEND only
 *     recv        RECV only
 *     wrong-cmd   use cmd=0xDEAD instead of magic — kprobe should ignore
 *     bad-op      use op=99 — kprobe should ignore
 *     burst N     N iterations of "pair"
 * </pre>
 *
 * <p>Run an {@code apidump-javatls} listener in another shell first; expect
 * to see one {@code REQ method=GET url=/phase5b1} and one {@code RESP status=200}
 * for the default mode.</p>
 */
public final class Main {

    // 127.0.0.1 in host order.
    private static final int LOOPBACK = (127 << 24) | 1;

    private static final byte[] SYNTHETIC_REQ = (
            "GET /phase5b1 HTTP/1.1\r\n" +
            "Host: spike.local\r\n" +
            "User-Agent: postman-java-agent-5b1/0.1\r\n" +
            "Accept: */*\r\n" +
            "\r\n").getBytes();

    private static final byte[] SYNTHETIC_RESP = (
            "HTTP/1.1 200 OK\r\n" +
            "Content-Type: text/plain\r\n" +
            "Content-Length: 26\r\n" +
            "\r\n" +
            "hello-from-phase-5b1-java\r\n").getBytes();

    public static void main(String[] args) {
        String mode = (args.length > 0 ? args[0] : "pair").toLowerCase(Locale.ROOT);
        int burst = 1;
        if ("burst".equals(mode) && args.length >= 2) {
            try {
                burst = Math.max(1, Integer.parseInt(args[1]));
            } catch (NumberFormatException e) {
                System.err.println("invalid burst count: " + args[1]);
                System.exit(2);
            }
        }

        long cmd = NativeMemory.IOCTL_MAGIC;
        byte op  = IoctlPacket.OP_SEND;

        switch (mode) {
            case "pair":
            case "burst":
                /* handled below */
                break;
            case "send":
                doSend();
                summarise(mode);
                return;
            case "recv":
                doRecv();
                summarise(mode);
                return;
            case "wrong-cmd":
                cmd = 0xDEADL;
                doOne(op, cmd, SYNTHETIC_REQ, /*srcPort=*/54321, /*dstPort=*/8443);
                summarise(mode);
                return;
            case "bad-op":
                op = 99;
                doOne(op, cmd, SYNTHETIC_REQ, 54321, 8443);
                summarise(mode);
                return;
            default:
                System.err.println("unknown mode: " + mode);
                System.err.println("usage: <pair|send|recv|wrong-cmd|bad-op|burst N>");
                System.exit(2);
        }

        for (int i = 0; i < burst; i++) {
            doSend();
            doRecv();
        }
        summarise(burst > 1 ? "burst×" + burst : mode);
    }

    private static void doSend() {
        IoctlPacket.send(IoctlPacket.OP_SEND, LOOPBACK, 54321, LOOPBACK, 8443, SYNTHETIC_REQ);
    }

    private static void doRecv() {
        IoctlPacket.send(IoctlPacket.OP_RECV, LOOPBACK, 8443, LOOPBACK, 54321, SYNTHETIC_RESP);
    }

    /** Single-ioctl helper for the negative modes. */
    private static void doOne(byte op, long cmd, byte[] payload, int srcPort, int dstPort) {
        // Bypass IoctlPacket.send() so we can override `cmd` for the wrong-cmd
        // test. We rebuild the packet manually with the requested op.
        int total = IoctlPacket.HEADER_SIZE + payload.length;
        long addr = NativeMemory.allocateMemory(total);
        try {
            NativeMemory.putByte(addr, op);
            // s_addr (16) — write 127.0.0.1 in first 4 bytes.
            NativeMemory.putByte(addr + 1, (byte) 127);
            NativeMemory.putByte(addr + 4, (byte) 1);
            // d_addr (16) — same.
            NativeMemory.putByte(addr + 17, (byte) 127);
            NativeMemory.putByte(addr + 20, (byte) 1);
            NativeMemory.putU16LE(addr + 33, srcPort);
            NativeMemory.putU16LE(addr + 35, dstPort);
            NativeMemory.putU32LE(addr + 37, payload.length);
            NativeMemory.putBytes(addr + IoctlPacket.HEADER_SIZE, payload, 0, payload.length);
            long packed = NativeMemory.doIoctl(NativeMemory.IOCTL_FD, cmd, addr);
            System.err.printf(
                    "ioctl(0, 0x%x, op=%d) rc=%d errno=%d%n",
                    cmd, op,
                    NativeMemory.ioctlReturn(packed),
                    NativeMemory.ioctlErrno(packed));
        } finally {
            NativeMemory.freeMemory(addr);
        }
    }

    private static void summarise(String mode) {
        System.err.printf("postman-java-agent spike: pid=%d mode=%s done%n",
                ProcessHandle.current().pid(), mode);
    }
}
