package com.postman.insights.agent.installer;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import com.postman.insights.agent.bootstrap.Contract;

/**
 * The control file the Insights agent writes into the container
 * ({@link Contract#CONTROL_FILE_PATH}) and refreshes every
 * {@link Contract#CONTROL_REFRESH_INTERVAL_MILLIS}. The agent captures only
 * while the file is fresh, has a version it knows and says {@code enabled=1};
 * in every other case it is dormant. So capture stops on its own when the
 * Insights agent is removed or stops monitoring the pod.
 */
final class ControlFile {
    /** Larger files are not control files the Insights agent wrote. */
    static final int MAX_SIZE = 4096;

    /** What the file says, or why the agent is dormant. */
    static final class Settings {
        final boolean enabled;
        /** Payload cap from the file, or 0 to keep the agent's own. */
        final int captureCap;
        /** Why capture is off; null when enabled. */
        final String dormantReason;

        private Settings(boolean enabled, int captureCap, String dormantReason) {
            this.enabled = enabled;
            this.captureCap = captureCap;
            this.dormantReason = dormantReason;
        }

        static Settings dormant(String reason) {
            return new Settings(false, 0, reason);
        }

        static Settings enabled(int captureCap) {
            return new Settings(true, captureCap, null);
        }
    }

    private final File file;

    ControlFile(File file) {
        this.file = file;
    }

    File file() {
        return file;
    }

    /** Reads the file. The file is tiny, so it is simply read on every check. */
    Settings check(long nowMillis) {
        long modified = file.lastModified();
        if (modified == 0) {
            return Settings.dormant("no control file at " + file);
        }
        if (nowMillis - modified > Contract.CONTROL_STALE_AFTER_MILLIS) {
            return Settings.dormant("the control file at " + file + " is older than "
                    + Contract.CONTROL_STALE_AFTER_MILLIS / 1000 + " s");
        }
        try {
            return parse(read(file));
        } catch (IOException e) {
            return Settings.dormant("cannot read the control file at " + file + ": " + e.getMessage());
        }
    }

    private static String read(File f) throws IOException {
        byte[] buf = new byte[MAX_SIZE + 1];
        int n = 0;
        try (InputStream in = new FileInputStream(f)) {
            for (int r; n < buf.length && (r = in.read(buf, n, buf.length - n)) > 0; ) {
                n += r;
            }
        }
        if (n > MAX_SIZE) {
            throw new IOException("larger than " + MAX_SIZE + " bytes");
        }
        return new String(buf, 0, n, StandardCharsets.UTF_8);
    }

    /**
     * Parses key=value lines. Blank lines, lines without '=' and unknown keys
     * are skipped, so newer Insights agents can add keys; a format they cannot
     * keep compatible gets a new version, which this agent refuses.
     */
    static Settings parse(String content) {
        String version = null;
        String enabled = null;
        int cap = 0;
        for (String line : content.split("\n")) {
            int eq = line.indexOf('=');
            if (eq < 0) {
                continue;
            }
            String key = line.substring(0, eq).trim();
            String value = line.substring(eq + 1).trim();
            if (key.equals(Contract.CONTROL_KEY_VERSION)) {
                version = value;
            } else if (key.equals(Contract.CONTROL_KEY_ENABLED)) {
                enabled = value;
            } else if (key.equals(Contract.CONTROL_KEY_CAPTURE_CAP)) {
                try {
                    cap = AgentArgs.clampCap(Integer.parseInt(value));
                } catch (NumberFormatException e) {
                    cap = 0;
                }
            }
        }
        if (version == null) {
            return Settings.dormant("the control file has no version");
        }
        if (!version.equals(Contract.CONTROL_VERSION_1)) {
            return Settings.dormant("the control file has version " + version + ", which this agent does not support");
        }
        if ("0".equals(enabled)) {
            return Settings.dormant("disabled by the Insights agent");
        }
        if (!"1".equals(enabled)) {
            return Settings.dormant("the control file does not say enabled=1");
        }
        return Settings.enabled(cap);
    }
}
