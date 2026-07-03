// SPDX-License-Identifier: Apache-2.0

package com.postman.insights.agent;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link Agent#shouldSkipForCliToolJVM()} — the early-exit
 * guard added to fix runbook LIMIT-2 (NoClassDefFoundError noise in keytool
 * subprocesses).
 *
 * <p>Tests manipulate {@code sun.java.command} via {@link System#setProperty}
 * before each case and restore the original value in {@code @AfterEach}.
 * Reading the property at test time is safe because the detection method
 * re-reads it on every invocation.
 */
class AgentCliSkipTest {

    private static final String CMD_PROP = "sun.java.command";
    private static final String FORCE_PROP = "postman.agent.force";

    private String savedCmd;
    private String savedForce;

    @BeforeEach
    void saveProps() {
        savedCmd = System.getProperty(CMD_PROP);
        savedForce = System.getProperty(FORCE_PROP);
        System.clearProperty(FORCE_PROP);
    }

    @AfterEach
    void restoreProps() {
        if (savedCmd == null) {
            System.clearProperty(CMD_PROP);
        } else {
            System.setProperty(CMD_PROP, savedCmd);
        }
        if (savedForce == null) {
            System.clearProperty(FORCE_PROP);
        } else {
            System.setProperty(FORCE_PROP, savedForce);
        }
    }

    // -- Positive: known CLI tools by wrapper-script basename -------------

    @Test
    void keytoolWrapperIsDetected() {
        System.setProperty(CMD_PROP, "keytool -genkey -alias foo");
        assertTrue(Agent.shouldSkipForCliToolJVM(),
                "keytool wrapper invocation must be skipped");
    }

    @Test
    void keytoolWithAbsolutePathIsDetected() {
        // Some setups set sun.java.command to the absolute path. We strip
        // any leading directory before matching.
        System.setProperty(CMD_PROP, "/usr/lib/jvm/temurin-21/bin/keytool -list");
        assertTrue(Agent.shouldSkipForCliToolJVM());
    }

    @Test
    void jarsignerIsDetected() {
        System.setProperty(CMD_PROP, "jarsigner -verify foo.jar");
        assertTrue(Agent.shouldSkipForCliToolJVM());
    }

    @Test
    void jcmdIsDetected() {
        System.setProperty(CMD_PROP, "jcmd 12345 Thread.print");
        assertTrue(Agent.shouldSkipForCliToolJVM());
    }

    @Test
    void javacIsDetected() {
        System.setProperty(CMD_PROP, "javac -d build foo.java");
        assertTrue(Agent.shouldSkipForCliToolJVM());
    }

    @Test
    void jshellIsDetected() {
        // jshell is borderline (it's interactive, not always short-lived)
        // but it still produces the LIMIT-2 noise on JDK 25 and we have an
        // escape hatch for power users (postman.agent.force=true).
        System.setProperty(CMD_PROP, "jshell");
        assertTrue(Agent.shouldSkipForCliToolJVM());
    }

    // -- Positive: known CLI tools by FQN main class ----------------------

    @Test
    void keytoolMainClassIsDetected() {
        // `java -cp /jdk/lib/tools.jar sun.security.tools.keytool.Main ...`
        System.setProperty(CMD_PROP, "sun.security.tools.keytool.Main -genkey");
        assertTrue(Agent.shouldSkipForCliToolJVM());
    }

    @Test
    void jarMainClassIsDetected_JDK8() {
        // JDK 8 jar tool main class.
        System.setProperty(CMD_PROP, "sun.tools.jar.Main cf foo.jar Foo.class");
        assertTrue(Agent.shouldSkipForCliToolJVM());
    }

    @Test
    void jarLauncherIsDetected_JDK9plus() {
        // JDK 9+ moved the jar tool under jdk.jartool.
        System.setProperty(CMD_PROP, "jdk.jartool.JarMain");
        assertTrue(Agent.shouldSkipForCliToolJVM());
    }

    @Test
    void javacMainClassIsDetected() {
        System.setProperty(CMD_PROP, "com.sun.tools.javac.Main foo.java");
        assertTrue(Agent.shouldSkipForCliToolJVM());
    }

    // -- Negative: real workloads must NOT be skipped ---------------------

    @Test
    void springBootAppIsNotSkipped() {
        System.setProperty(CMD_PROP, "org.springframework.boot.loader.JarLauncher");
        assertFalse(Agent.shouldSkipForCliToolJVM());
    }

    @Test
    void tomcatBootstrapIsNotSkipped() {
        System.setProperty(CMD_PROP, "org.apache.catalina.startup.Bootstrap start");
        assertFalse(Agent.shouldSkipForCliToolJVM());
    }

    @Test
    void kafkaIsNotSkipped() {
        System.setProperty(CMD_PROP, "kafka.Kafka /opt/kafka/config/server.properties");
        assertFalse(Agent.shouldSkipForCliToolJVM());
    }

    @Test
    void plainAppJarIsNotSkipped() {
        // A user app shipped as foo.jar would set sun.java.command to "foo.jar args..."
        System.setProperty(CMD_PROP, "myapp.jar --port=8443");
        assertFalse(Agent.shouldSkipForCliToolJVM());
    }

    @Test
    void appWithKeytoolInNameIsNotSkipped() {
        // Substring match would be wrong — only exact basename match counts.
        // "my-keytool-frontend" is a hypothetical app whose name contains
        // "keytool" but is NOT the keytool tool.
        System.setProperty(CMD_PROP, "my-keytool-frontend.jar");
        assertFalse(Agent.shouldSkipForCliToolJVM());
    }

    // -- Edge cases -------------------------------------------------------

    @Test
    void missingPropertyIsNotSkipped() {
        // sun.java.command is normally set by the launcher, but in
        // embedded JVMs or unusual JNI hosts it can be absent. Default to
        // NOT skipping — better to spam stderr than silently drop
        // instrumentation on a real workload.
        System.clearProperty(CMD_PROP);
        assertFalse(Agent.shouldSkipForCliToolJVM());
    }

    @Test
    void emptyPropertyIsNotSkipped() {
        System.setProperty(CMD_PROP, "");
        assertFalse(Agent.shouldSkipForCliToolJVM());
    }

    @Test
    void forceFlagOverridesEvenForKeytool() {
        System.setProperty(CMD_PROP, "keytool -genkey");
        System.setProperty(FORCE_PROP, "true");
        assertFalse(Agent.shouldSkipForCliToolJVM(),
                "postman.agent.force=true must override the skip guard");
    }

    @Test
    void backslashPathIsNormalised_Windows() {
        // Windows-style separator. The detection helper strips both kinds.
        System.setProperty(CMD_PROP, "C:\\Program Files\\Java\\bin\\keytool.exe -list");
        // ".exe" is NOT one of our suffixes — only ".jar" is stripped. So
        // "keytool.exe" isn't in CLI_TOOL_BASENAMES. That's intentional:
        // launcher scripts on Windows that actually invoke "keytool.exe"
        // typically still set sun.java.command to the wrapper *script* form
        // (just "keytool"), not the .exe form. If a real Windows user
        // discovers this isn't detected, we can extend the BASENAMES set.
        assertFalse(Agent.shouldSkipForCliToolJVM(),
                "Windows .exe form should NOT be auto-detected without a confirmed sample");
    }

    @Test
    void jarLauncherWithJarSuffixIsDetected() {
        // 'java -jar /opt/jdk/lib/jrt-fs.jar' — sun.java.command = "<path>.jar args".
        // Our code strips the ".jar" suffix before matching, so this becomes "jrt-fs"
        // which is NOT in the set. Good — we shouldn't auto-skip random user JARs.
        System.setProperty(CMD_PROP, "/some/path/keytool.jar -genkey");
        assertTrue(Agent.shouldSkipForCliToolJVM(),
                "but a JAR literally named 'keytool.jar' should still be skipped (rare but safe)");
    }
}
