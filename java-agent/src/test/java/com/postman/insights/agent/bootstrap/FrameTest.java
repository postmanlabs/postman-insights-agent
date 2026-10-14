package com.postman.insights.agent.bootstrap;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.io.Reader;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

/** Checks the encoder against the example frames shared with the Go side. */
class FrameTest {
    private static JsonObject vectors() throws Exception {
        try (Reader r = Files.newBufferedReader(Paths.get(System.getProperty("frames.vectors")), StandardCharsets.UTF_8)) {
            return JsonParser.parseReader(r).getAsJsonObject();
        }
    }

    @Test
    void constantsMatchVectors() throws Exception {
        JsonObject v = vectors();
        assertEquals(Long.parseUnsignedLong(v.get("magic").getAsString().substring(2), 16), Frame.MAGIC);
        assertEquals(v.get("header_size").getAsInt(), Frame.HEADER_SIZE);
    }

    @Test
    void encodesExampleFrames() throws Exception {
        JsonArray frames = vectors().getAsJsonArray("frames");
        assertFalse(frames.isEmpty());
        for (JsonElement e : frames) {
            JsonObject f = e.getAsJsonObject();
            String name = f.get("name").getAsString();
            assertEquals(Frame.VERSION_1, f.get("version").getAsInt(), name);

            byte[] payload = hex(f.get("payload_hex").getAsString());
            String peer = f.get("peer_addr").getAsString();
            byte[] peerAddr = peer.isEmpty() ? null : mapped(InetAddress.getByName(peer).getAddress());

            ByteBuffer buf = Frame.allocate(payload.length);
            Frame.putHeader(buf,
                    (byte) f.get("op").getAsInt(),
                    (short) f.get("flags").getAsInt(),
                    payload.length,
                    Long.parseUnsignedLong(f.get("conn_id").getAsString().substring(2), 16),
                    peerAddr,
                    f.get("peer_port").getAsInt(),
                    f.get("total_len").getAsInt());
            buf.position(Frame.HEADER_SIZE);
            buf.put(payload);
            buf.flip();
            byte[] got = new byte[buf.remaining()];
            buf.get(got);

            assertArrayEquals(hex(f.get("frame_hex").getAsString()), got, name);
        }
    }

    private static byte[] mapped(byte[] addr) {
        if (addr.length == 16) {
            return addr;
        }
        byte[] out = new byte[16];
        out[10] = (byte) 0xff;
        out[11] = (byte) 0xff;
        System.arraycopy(addr, 0, out, 12, 4);
        return out;
    }

    private static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }
}
