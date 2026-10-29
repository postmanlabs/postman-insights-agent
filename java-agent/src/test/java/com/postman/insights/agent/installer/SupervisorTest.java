package com.postman.insights.agent.installer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.postman.insights.agent.bootstrap.Bridge;
import com.postman.insights.agent.bootstrap.Contract;
import com.postman.insights.agent.bootstrap.Frame;
import com.postman.insights.agent.bootstrap.FrameLog;

class SupervisorTest {
    private static final int ARG_CAP = 1024;

    @TempDir
    File dir;
    private File controlFile;
    private FrameLog log;
    private Supervisor supervisor;

    @BeforeEach
    void setUp() throws Exception {
        log = new FrameLog("supervisor-test");
        Bridge.start(ARG_CAP, log.path());
        controlFile = new File(dir, "control");
        supervisor = new Supervisor(new ControlFile(controlFile), ARG_CAP, "1.2.3", Contract.HEARTBEAT_SOURCE_ATTACH);
    }

    private void control(String content) throws Exception {
        Files.write(controlFile.toPath(), content.getBytes(StandardCharsets.UTF_8));
    }

    private List<String> heartbeats() throws Exception {
        List<String> out = new ArrayList<String>();
        for (FrameLog.LoggedFrame f : log.frames()) {
            if (f.op == Frame.OP_HEARTBEAT) {
                out.add(new String(f.payload, StandardCharsets.UTF_8));
            }
        }
        return out;
    }

    @Test
    void appliesTheControlFile() throws Exception {
        long now = System.currentTimeMillis();
        supervisor.check(now);
        assertEquals(Contract.HEARTBEAT_STATE_DORMANT, Bridge.state());

        control("version=1\nenabled=1\n");
        supervisor.check(now);
        assertEquals(Contract.HEARTBEAT_STATE_ACTIVE, Bridge.state());

        control("version=1\nenabled=0\n");
        supervisor.check(now);
        assertEquals(Contract.HEARTBEAT_STATE_DORMANT, Bridge.state());

        // Stale: the Insights agent stopped refreshing it.
        control("version=1\nenabled=1\n");
        supervisor.check(now + Contract.CONTROL_STALE_AFTER_MILLIS + 1_000);
        assertEquals(Contract.HEARTBEAT_STATE_DORMANT, Bridge.state());
    }

    @Test
    void heartbeatAtStartThenEveryInterval() throws Exception {
        long now = System.currentTimeMillis();
        control("version=1\nenabled=1\n");
        log.mark();
        for (int i = 0; i < 2 * Supervisor.CHECKS_PER_HEARTBEAT + 1; i++) {
            supervisor.check(now);
        }
        List<String> heartbeats = heartbeats();
        assertEquals(3, heartbeats.size());
        String first = heartbeats.get(0);
        assertTrue(first.startsWith("agent_version=1.2.3\njava_version=" + System.getProperty("java.version") + "\n"), first);
        assertTrue(first.contains("\nsource=attach\nstate=active\n"), first);
    }

    /**
     * Switching capture on sends a heartbeat at once, between periodic ones,
     * so the kernel records the process's socket reads before its first
     * captured connection.
     */
    @Test
    void heartbeatWhenSwitchingOn() throws Exception {
        long now = System.currentTimeMillis();
        control("version=1\nenabled=0\n");
        supervisor.check(now);
        log.mark();
        control("version=1\nenabled=1\n");
        supervisor.check(now);
        supervisor.check(now);
        List<String> heartbeats = heartbeats();
        assertEquals(1, heartbeats.size());
        assertTrue(heartbeats.get(0).contains("\nstate=active\n"), heartbeats.get(0));
    }

    @Test
    void heartbeatWhileDormant() throws Exception {
        log.mark();
        supervisor.check(System.currentTimeMillis());
        List<String> heartbeats = heartbeats();
        assertEquals(1, heartbeats.size());
        assertTrue(heartbeats.get(0).contains("\nstate=dormant\n"), heartbeats.get(0));
    }

    /** The canonical example shared with the Go decoder (ebpf/javatls/testdata/payloads-v1.json). */
    @Test
    void heartbeatPayloadMatchesExample() throws Exception {
        int n = 0;
        for (JsonElement e : ControlFileTest.vectors().getAsJsonArray("heartbeat")) {
            JsonObject h = e.getAsJsonObject();
            if (!h.get("canonical").getAsBoolean()) {
                continue;
            }
            JsonObject f = h.getAsJsonObject("fields");
            byte[] got = Supervisor.heartbeat(f.get("agent_version").getAsString(), f.get("java_version").getAsString(),
                    f.get("java_vendor").getAsString(), f.get("source").getAsString(), f.get("state").getAsString(),
                    f.get("frames").getAsLong(), f.get("dropped").getAsLong(), f.get("errors").getAsLong(),
                    f.get("connections").getAsLong());
            assertEquals(h.get("payload").getAsString(), new String(got, StandardCharsets.UTF_8));
            n++;
        }
        assertTrue(n > 0);
    }

    @Test
    void heartbeatValuesStayOnOneLine() {
        String got = new String(Supervisor.heartbeat("1\n2", null, "a\rb", "static", "active", 0, 0, 0, 0),
                StandardCharsets.UTF_8);
        assertTrue(got.startsWith("agent_version=1 2\njava_version=\njava_vendor=a b\n"), got);
    }
}
