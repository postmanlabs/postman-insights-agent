package com.postman.insights.agent.bootstrap;

/**
 * Names the agent and the Insights agent agree on, besides the frame format.
 * Mirrors {@code ebpf/javatls/contract.go}.
 */
public final class Contract {
    /**
     * System property set once the agent is loaded; its value is the agent
     * version. The Insights agent reads it to avoid loading a second copy.
     */
    public static final String MARKER_PROPERTY = "postman.insights.agent.version";

    /**
     * System property set when the agent failed to start; its value is the
     * version and the reason. The agent does not retry in the same JVM.
     */
    public static final String FAILED_PROPERTY = "postman.insights.agent.failed";

    /** Agent argument: maximum payload bytes per frame. */
    public static final String ARG_CAPTURE_CAP = "cap";

    /** Per-frame payload cap without a {@code cap} argument; MAX_EVENT_PAYLOAD in the kernel. */
    public static final int DEFAULT_CAPTURE_CAP = 16384;

    /**
     * Control file written by the Insights agent inside the container:
     * key=value lines. The agent is dormant unless the file is fresh, has a
     * known version and says enabled=1.
     */
    public static final String CONTROL_FILE_PATH = "/tmp/.postman-insights/control";
    public static final String CONTROL_KEY_VERSION = "version";
    public static final String CONTROL_KEY_ENABLED = "enabled";
    public static final String CONTROL_KEY_CAPTURE_CAP = "cap_bytes";
    public static final String CONTROL_VERSION_1 = "1";
    public static final long CONTROL_REFRESH_INTERVAL_MILLIS = 10_000;
    public static final long CONTROL_STALE_AFTER_MILLIS = 60_000;

    /** HEARTBEAT frame payload: key=value lines, sent at start and every HEARTBEAT_INTERVAL_MILLIS. */
    public static final String HEARTBEAT_KEY_AGENT_VERSION = "agent_version";
    public static final String HEARTBEAT_KEY_JAVA_VERSION = "java_version";
    public static final String HEARTBEAT_KEY_JAVA_VENDOR = "java_vendor";
    public static final String HEARTBEAT_KEY_SOURCE = "source";
    public static final String HEARTBEAT_KEY_STATE = "state";
    public static final String HEARTBEAT_KEY_FRAMES = "frames";
    public static final String HEARTBEAT_KEY_DROPPED = "dropped";
    public static final String HEARTBEAT_KEY_ERRORS = "errors";
    public static final String HEARTBEAT_KEY_CONNECTIONS = "connections";
    public static final String HEARTBEAT_SOURCE_STATIC = "static";
    public static final String HEARTBEAT_SOURCE_ATTACH = "attach";
    public static final String HEARTBEAT_STATE_ACTIVE = "active";
    public static final String HEARTBEAT_STATE_DORMANT = "dormant";
    public static final String HEARTBEAT_STATE_OFF = "off";
    public static final long HEARTBEAT_INTERVAL_MILLIS = 30_000;

    /**
     * Testing only: when set to a file path, frames are appended to that file
     * instead of being written to the kernel, so tests can check them without
     * eBPF. Not part of the contract with the Insights agent.
     */
    public static final String FRAME_LOG_PROPERTY = "postman.insights.agent.frameLog";

    /**
     * Testing only: read the control file from this path instead of
     * {@link #CONTROL_FILE_PATH}. Not part of the contract with the Insights
     * agent.
     */
    public static final String CONTROL_FILE_PROPERTY = "postman.insights.agent.controlFile";

    private Contract() {}
}
