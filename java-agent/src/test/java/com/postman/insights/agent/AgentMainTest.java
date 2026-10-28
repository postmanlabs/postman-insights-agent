package com.postman.insights.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
    void jdkToolsAreSkipped() {
        for (String tool : new String[] {
                "sun.tools.jcmd.JCmd 1234 VM.version",                 // JDK 8
                "jdk.jcmd/sun.tools.jcmd.JCmd 1234 Thread.print",      // JDK 9+
                "jdk.jcmd/sun.tools.jps.Jps",
                "java.base/sun.security.tools.keytool.Main -list",
                "jdk.compiler/com.sun.tools.javac.Main Foo.java",
                "jdk.jshell/jdk.internal.jshell.tool.JShellToolProvider",
                "jdk.jartool/sun.tools.jar.Main tf app.jar"}) {
            assertTrue(AgentMain.isJdkTool(tool), tool);
        }
        for (String app : new String[] {
                "/app/app.jar --server.port=8443",
                "app.jar",
                "org.springframework.boot.loader.launch.JarLauncher",
                "com.example.Main jdk.foo",
                "com.sun.enterprise.glassfish.bootstrap.ASMain",       // GlassFish is an application
                // The source launcher runs the application's own code.
                "jdk.compiler/com.sun.tools.javac.launcher.Main Server.java",          // JDK 11 to 21
                "jdk.compiler/com.sun.tools.javac.launcher.SourceLauncher Server.java", // JDK 22+
                "",
                null}) {
            assertFalse(AgentMain.isJdkTool(app), String.valueOf(app));
        }
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
