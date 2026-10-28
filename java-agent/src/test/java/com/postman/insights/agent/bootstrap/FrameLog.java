package com.postman.insights.agent.bootstrap;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Reads the frames the bridge appends to its test log. Tests share the
 * bridge's static state, so each reads only the frames written after {@link #mark}.
 */
public final class FrameLog {
    public static final class LoggedFrame {
        public byte op;
        public short flags;
        public long connId;
        public int totalLen;
        public byte[] payload;

        public String text() {
            return new String(payload, StandardCharsets.ISO_8859_1);
        }
    }

    private final File file;
    private long start;

    public FrameLog(String prefix) throws IOException {
        file = File.createTempFile(prefix, ".frames");
        file.deleteOnExit();
    }

    public String path() {
        return file.getAbsolutePath();
    }

    public void mark() {
        start = file.length();
    }

    /** Frames written since the last mark. */
    public List<LoggedFrame> frames() throws IOException {
        byte[] all = Files.readAllBytes(file.toPath());
        ByteBuffer b = ByteBuffer.wrap(all, (int) start, all.length - (int) start).order(ByteOrder.LITTLE_ENDIAN);
        List<LoggedFrame> out = new ArrayList<LoggedFrame>();
        while (b.remaining() >= Frame.HEADER_SIZE) {
            int at = b.position();
            assertEquals(Frame.VERSION_1, b.get(at));
            LoggedFrame f = new LoggedFrame();
            f.op = b.get(at + 1);
            f.flags = b.getShort(at + 2);
            int len = b.getInt(at + 4);
            f.connId = b.getLong(at + 8);
            f.totalLen = b.getInt(at + 36);
            f.payload = Arrays.copyOfRange(all, at + Frame.HEADER_SIZE, at + Frame.HEADER_SIZE + len);
            b.position(at + Frame.HEADER_SIZE + len);
            out.add(f);
        }
        assertEquals(0, b.remaining(), "trailing bytes in the frame log");
        return out;
    }
}
