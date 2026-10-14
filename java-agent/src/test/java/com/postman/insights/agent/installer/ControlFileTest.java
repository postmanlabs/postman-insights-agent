package com.postman.insights.agent.installer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ControlFileTest {
    @TempDir
    File dir;

    static JsonObject vectors() throws Exception {
        try (Reader r = Files.newBufferedReader(Paths.get(System.getProperty("payloads.vectors")), StandardCharsets.UTF_8)) {
            return JsonParser.parseReader(r).getAsJsonObject();
        }
    }

    /** The examples shared with the Go writer (ebpf/javatls/testdata/payloads-v1.json). */
    @Test
    void parsesExamples() throws Exception {
        int n = 0;
        for (JsonElement e : vectors().getAsJsonArray("control")) {
            JsonObject c = e.getAsJsonObject();
            String name = c.get("name").getAsString();
            ControlFile.Settings s = ControlFile.parse(c.get("content").getAsString());
            assertEquals(c.get("enabled").getAsBoolean(), s.enabled, name);
            assertEquals(c.get("cap_bytes").getAsInt(), s.captureCap, name);
            if (s.enabled) {
                assertNull(s.dormantReason, name);
            } else {
                assertNotNull(s.dormantReason, name);
            }
            n++;
        }
        assertTrue(n > 0);
    }

    private ControlFile write(String content, long ageMillis, long now) throws Exception {
        File f = new File(dir, "control");
        Files.write(f.toPath(), content.getBytes(StandardCharsets.UTF_8));
        assertTrue(f.setLastModified(now - ageMillis));
        return new ControlFile(f);
    }

    @Test
    void freshFileIsApplied() throws Exception {
        long now = System.currentTimeMillis();
        ControlFile.Settings s = write("version=1\nenabled=1\ncap_bytes=2048\n", 1_000, now).check(now);
        assertTrue(s.enabled);
        assertEquals(2048, s.captureCap);
    }

    @Test
    void missingFileIsDormant() {
        ControlFile.Settings s = new ControlFile(new File(dir, "nothing-here")).check(System.currentTimeMillis());
        assertFalse(s.enabled);
        assertTrue(s.dormantReason.startsWith("no control file"), s.dormantReason);
    }

    @Test
    void staleFileIsDormant() throws Exception {
        long now = System.currentTimeMillis();
        ControlFile.Settings s = write("version=1\nenabled=1\n", 61_000, now).check(now);
        assertFalse(s.enabled);
        assertTrue(s.dormantReason.contains("older than 60 s"), s.dormantReason);

        // Just under the limit still counts.
        assertTrue(write("version=1\nenabled=1\n", 59_000, now).check(now).enabled);
    }

    @Test
    void oversizedFileIsDormant() throws Exception {
        char[] filler = new char[ControlFile.MAX_SIZE];
        Arrays.fill(filler, '#');
        long now = System.currentTimeMillis();
        ControlFile.Settings s = write("version=1\nenabled=1\n" + new String(filler), 0, now).check(now);
        assertFalse(s.enabled);
        assertTrue(s.dormantReason.contains("larger than"), s.dormantReason);
    }

    @Test
    void directoryIsDormant() {
        ControlFile.Settings s = new ControlFile(dir).check(System.currentTimeMillis());
        assertFalse(s.enabled);
    }
}
