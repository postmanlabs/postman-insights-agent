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

            // A pooled buffer holds an earlier frame's bytes: the header must
            // overwrite them all, the reserved bytes included.
            ByteBuffer buf = Frame.allocate(payload.length);
            for (int i = 0; i < buf.capacity(); i++) {
                buf.put(i, (byte) 0xa5);
            }
            Frame.putHeader(buf,
                    (byte) f.get("op").getAsInt(),
                    (short) f.get("flags").getAsInt(),
                    payload.length,
                    Long.parseUnsignedLong(f.get("conn_id").getAsString().substring(2), 16),
                    f.get("total_len").getAsInt());
            buf.position(Frame.HEADER_SIZE);
            buf.put(payload);
            buf.flip();
            byte[] got = new byte[buf.remaining()];
            buf.get(got);

            assertArrayEquals(hex(f.get("frame_hex").getAsString()), got, name);
        }
    }

    @Test
    void encodesExampleAddresses() throws Exception {
        JsonArray addresses = vectors().getAsJsonArray("addresses");
        assertFalse(addresses.isEmpty());
        for (JsonElement e : addresses) {
            JsonObject a = e.getAsJsonObject();
            String name = a.get("name").getAsString();
            ByteBuffer buf = Frame.allocate(Frame.ADDRESS_SIZE);
            Frame.putAddress(buf, Frame.HEADER_SIZE,
                    InetAddress.getByName(a.get("local").getAsString()), a.get("local_port").getAsInt(),
                    InetAddress.getByName(a.get("remote").getAsString()), a.get("remote_port").getAsInt());
            byte[] got = new byte[Frame.ADDRESS_SIZE];
            buf.position(Frame.HEADER_SIZE);
            buf.get(got);
            assertArrayEquals(hex(a.get("payload_hex").getAsString()), got, name);
        }
    }

    private static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }
}
