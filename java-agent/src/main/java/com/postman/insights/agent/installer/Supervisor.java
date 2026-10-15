package com.postman.insights.agent.installer;

import java.nio.charset.StandardCharsets;

import com.postman.insights.agent.bootstrap.Bridge;
import com.postman.insights.agent.bootstrap.Contract;

/**
 * The agent's own background thread: applies the control file every
 * CHECK_INTERVAL_MILLIS and sends a HEARTBEAT frame every
 * {@link Contract#HEARTBEAT_INTERVAL_MILLIS}, whether capturing or dormant.
 */
final class Supervisor implements Runnable {
    static final long CHECK_INTERVAL_MILLIS = 5_000;
    /** Checks between HEARTBEAT frames. */
    static final int CHECKS_PER_HEARTBEAT = (int) (Contract.HEARTBEAT_INTERVAL_MILLIS / CHECK_INTERVAL_MILLIS);

    private final ControlFile control;
    private final int argCap;
    private final String version;
    private final String source;

    private int checks;
    /** What was last logged: the dormant reason, or "" for capturing; null before the first check. */
    private String logged;

    Supervisor(ControlFile control, int argCap, String version, String source) {
        this.control = control;
        this.argCap = argCap;
        this.version = version;
        this.source = source;
    }

    /** Starts the background thread, after the first {@link #check}. */
    void start() {
        Thread t = new Thread(this, "postman-insights-agent");
        t.setDaemon(true);
        // Keep no reference to an application class loader.
        t.setContextClassLoader(null);
        t.start();
    }

    @Override
    public void run() {
        for (;;) {
            try {
                Thread.sleep(CHECK_INTERVAL_MILLIS);
            } catch (InterruptedException e) {
                // Keep going: if the control file stopped being checked,
                // capture could not be switched off any more.
            }
            try {
                check(System.currentTimeMillis());
            } catch (Throwable t) {
                Installer.log("control check failed: " + t);
            }
        }
    }

    /** Applies the control file, and sends HEARTBEAT when due. */
    void check(long nowMillis) {
        ControlFile.Settings s = control.check(nowMillis);
        int cap = s.captureCap > 0 ? s.captureCap : argCap;
        boolean due = checks++ % CHECKS_PER_HEARTBEAT == 0;
        // Switching capture on: a heartbeat first. The Insights agent's
        // kernel programs record a process's socket reads and writes only once
        // it has sent them a frame, and the heartbeat at start may have come
        // before they ran; recorded from now, the first connections are tied
        // to their sockets.
        if (s.enabled && !Bridge.capturing()) {
            heartbeat(Bridge.stateWhenEnabled());
            due = false;
        }
        Bridge.control(s.enabled, cap);
        String now = s.enabled ? "" : s.dormantReason;
        if (!now.equals(logged)) {
            Installer.log(s.enabled ? "capturing HTTPS traffic (payload cap " + cap + " bytes)"
                    : "dormant, not capturing: " + s.dormantReason);
            logged = now;
        }
        if (due) {
            heartbeat(Bridge.state());
        }
    }

    private void heartbeat(String state) {
        Bridge.heartbeat(heartbeat(version, System.getProperty("java.version"), System.getProperty("java.vendor"),
                source, state, Bridge.framesWritten(), Bridge.framesDropped(), Bridge.errors(),
                Bridge.connections()));
    }

    /** The HEARTBEAT payload: key=value lines, in a fixed order. */
    static byte[] heartbeat(String agentVersion, String javaVersion, String javaVendor, String source, String state,
                        long frames, long dropped, long errors, long connections) {
        StringBuilder b = new StringBuilder(256);
        line(b, Contract.HEARTBEAT_KEY_AGENT_VERSION, agentVersion);
        line(b, Contract.HEARTBEAT_KEY_JAVA_VERSION, javaVersion);
        line(b, Contract.HEARTBEAT_KEY_JAVA_VENDOR, javaVendor);
        line(b, Contract.HEARTBEAT_KEY_SOURCE, source);
        line(b, Contract.HEARTBEAT_KEY_STATE, state);
        line(b, Contract.HEARTBEAT_KEY_FRAMES, Long.toString(frames));
        line(b, Contract.HEARTBEAT_KEY_DROPPED, Long.toString(dropped));
        line(b, Contract.HEARTBEAT_KEY_ERRORS, Long.toString(errors));
        line(b, Contract.HEARTBEAT_KEY_CONNECTIONS, Long.toString(connections));
        return b.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static void line(StringBuilder b, String key, String value) {
        String v = value == null ? "" : value.replace('\n', ' ').replace('\r', ' ');
        b.append(key).append('=').append(v).append('\n');
    }
}
