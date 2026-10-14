package com.postman.insights.agent.installer;

import com.postman.insights.agent.bootstrap.Contract;

/**
 * The agent's arguments: comma-separated key=value pairs, for example
 * {@code cap=16384}. Unknown keys and malformed values are ignored, so older
 * agents accept arguments from newer Insights agents.
 */
final class AgentArgs {
    /** Largest cap accepted; the kernel keeps at most this many bytes per event anyway. */
    static final int MAX_CAPTURE_CAP = Contract.DEFAULT_CAPTURE_CAP;
    static final int MIN_CAPTURE_CAP = 64;

    final int captureCap;

    private AgentArgs(int captureCap) {
        this.captureCap = captureCap;
    }

    static AgentArgs parse(String raw) {
        int cap = Contract.DEFAULT_CAPTURE_CAP;
        if (raw != null) {
            for (String pair : raw.split(",")) {
                int eq = pair.indexOf('=');
                if (eq <= 0) {
                    continue;
                }
                String key = pair.substring(0, eq).trim();
                String value = pair.substring(eq + 1).trim();
                if (key.equals(Contract.ARG_CAPTURE_CAP)) {
                    try {
                        cap = Math.max(MIN_CAPTURE_CAP, Math.min(MAX_CAPTURE_CAP, Integer.parseInt(value)));
                    } catch (NumberFormatException ignored) {
                        // Keep the default.
                    }
                }
            }
        }
        return new AgentArgs(cap);
    }
}
