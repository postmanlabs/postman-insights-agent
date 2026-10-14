package com.postman.insights.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * The start-up bookkeeping the attacher relies on. In unit tests AgentMain is
 * loaded from a class directory, not a jar, so starting fails, which is the
 * case under test. (The success path is covered by the -javaagent tests.)
 */
class AgentMainTest {
    private static final String MARKER = "postman.insights.agent.version";
    private static final String FAILED = "postman.insights.agent.failed";

    @AfterEach
    void clearProperties() {
        System.clearProperty(MARKER);
        System.clearProperty(FAILED);
    }

    @Test
    void failedStartIsRecordedAndNotRetried() {
        AgentMain.premain("", null);

        assertNull(System.getProperty(MARKER), "marker set although the hooks are not installed");
        String failed = System.getProperty(FAILED);
        assertNotNull(failed);
        assertTrue(failed.startsWith("unknown: "), failed);

        // A later attach must not try again or overwrite the first reason.
        System.setProperty(FAILED, "first");
        AgentMain.agentmain("", null);
        assertNull(System.getProperty(MARKER));
        assertEquals("first", System.getProperty(FAILED));
    }
}
