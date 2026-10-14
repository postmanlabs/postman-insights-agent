package com.postman.insights.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * The frames the agent appended to its frame log (see build.gradle.kts). The
 * agent's classes are not on the test classpath, so the format is decoded
 * here independently.
 */
final class Frames {
    static final byte OP_SEND = 1;
    static final byte OP_RECV = 2;
    static final byte OP_HEARTBEAT = 3;
    static final byte OP_CLOSE = 4;
    static final short ROLE_KNOWN = 0x1;
    static final short CLIENT_MODE = 0x2;

    static final class Frame {
        byte op;
        short flags;
        long connId;
        int totalLen;
        byte[] payload;

        String text() {
            return new String(payload, StandardCharsets.ISO_8859_1);
        }

        @Override
        public String toString() {
            return "op " + op + " conn " + connId + " [" + text().trim() + "]";
        }
    }

    private static final File LOG = new File(System.getProperty("frames.log"));
    private long start;

    /** Starts reading from the current end of the log. */
    Frames mark() {
        start = LOG.exists() ? LOG.length() : 0;
        return this;
    }

    /** Every frame in the log, from the start. */
    static List<Frame> all() throws Exception {
        return new Frames().read();
    }

    /** Frames written since the mark. */
    List<Frame> read() throws Exception {
        byte[] all = Files.readAllBytes(LOG.toPath());
        ByteBuffer b = ByteBuffer.wrap(all).order(ByteOrder.LITTLE_ENDIAN);
        b.position((int) start);
        List<Frame> out = new ArrayList<Frame>();
        while (b.remaining() >= 40) {
            int at = b.position();
            assertEquals(1, b.get(at), "frame version");
            Frame f = new Frame();
            f.op = b.get(at + 1);
            f.flags = b.getShort(at + 2);
            int len = b.getInt(at + 4);
            f.connId = b.getLong(at + 8);
            f.totalLen = b.getInt(at + 36);
            f.payload = Arrays.copyOfRange(all, at + 40, at + 40 + len);
            b.position(at + 40 + len);
            out.add(f);
        }
        assertEquals(0, b.remaining(), "trailing bytes in the frame log");
        return out;
    }

    /** Traffic frames (SEND and RECV) since the mark. */
    List<Frame> traffic() throws Exception {
        List<Frame> out = new ArrayList<Frame>();
        for (Frame f : read()) {
            if (f.op == OP_SEND || f.op == OP_RECV) {
                out.add(f);
            }
        }
        return out;
    }

    static Frame find(List<Frame> frames, byte op, String text) {
        for (Frame f : frames) {
            if (f.op == op && f.text().equals(text)) {
                return f;
            }
        }
        throw new AssertionError("no op " + op + " frame with " + text.trim() + " in " + frames);
    }

    static Frame findPrefix(List<Frame> frames, byte op, String prefix) {
        for (Frame f : frames) {
            if (f.op == op && f.text().startsWith(prefix)) {
                return f;
            }
        }
        throw new AssertionError("no op " + op + " frame starting with " + prefix + " in " + frames);
    }

    static int count(List<Frame> frames, byte op, String contains) {
        int n = 0;
        for (Frame f : frames) {
            if (f.op == op && f.text().contains(contains)) {
                n++;
            }
        }
        return n;
    }
}
