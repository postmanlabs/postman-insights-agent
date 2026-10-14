package com.postman.insights.agent;

import java.io.File;
import java.lang.instrument.Instrumentation;
import java.util.jar.JarFile;

import com.postman.insights.agent.bootstrap.Contract;

/**
 * Entry point for both ways the agent is loaded: {@code -javaagent} at JVM
 * start (premain) and dynamic attach by the Insights agent (agentmain).
 *
 * <p>Class loading is arranged so the agent never collides with application
 * classes (see the jar layout in build.gradle.kts):
 * <ul>
 *   <li>The JVM loads this class from the system class loader.
 *   <li>The whole jar is appended to the bootstrap class path, which makes the
 *       {@code bootstrap} package visible to every class, including JDK
 *       classes such as {@code SSLEngineImpl} that the advice is inlined into.
 *       The jar's other classes are stored as {@code inst/*.classdata}, so the
 *       bootstrap and application class loaders cannot find them.
 *   <li>{@link AgentClassLoader} loads those, including the agent's own copy
 *       of Byte Buddy, so an application's Byte Buddy is never affected.
 * </ul>
 *
 * <p>This class must not touch the {@code bootstrap} package before the jar is
 * on the bootstrap class path, or the system class loader would load a second
 * copy of those classes. (Compile-time constants are inlined and safe.)
 */
public final class AgentMain {
    private static final String MARKER_PROPERTY = "postman.insights.agent.version";
    private static final String FAILED_PROPERTY = "postman.insights.agent.failed";
    private static final String INSTALLER = "com.postman.insights.agent.installer.Installer";

    /**
     * Whether a start was attempted in this JVM. Every load (static, and each
     * attach) reaches this same class through the system class loader, so one
     * flag covers them all.
     */
    private static boolean attempted;

    private AgentMain() {}

    public static void premain(String args, Instrumentation inst) {
        // Loaded through JAVA_TOOL_OPTIONS, the agent starts in every JVM in
        // the container, including the JDK's own tools; they have no HTTPS
        // traffic worth capturing, and starting the agent would slow them down.
        if (isJdkTool(System.getProperty("sun.java.command"))) {
            return;
        }
        start(args, inst, Contract.HEARTBEAT_SOURCE_STATIC);
    }

    public static void agentmain(String args, Instrumentation inst) {
        start(args, inst, Contract.HEARTBEAT_SOURCE_ATTACH);
    }

    /**
     * Installs the hooks at most once per JVM. The marker property is set only
     * once they are installed, so it never claims capture that is not running.
     * A failed start is not retried, because it can leave partial state behind
     * (the jar on the bootstrap class path, some classes transformed) that a
     * second install would duplicate; the failed property records why.
     */
    private static synchronized void start(String args, Instrumentation inst, String source) {
        String loaded = System.getProperty(MARKER_PROPERTY);
        if (loaded != null) {
            log("version " + loaded + " is already loaded in this JVM; not loading again");
            return;
        }
        if (attempted) {
            log("an earlier start failed in this JVM (" + System.getProperty(FAILED_PROPERTY) + "); not retrying");
            return;
        }
        attempted = true;

        String version = "unknown";
        try {
            File jarPath = new File(AgentMain.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            JarFile jar = new JarFile(jarPath, false);
            String v = jar.getManifest().getMainAttributes().getValue("Implementation-Version");
            if (v != null) {
                version = v;
            }
            inst.appendToBootstrapClassLoaderSearch(jar);
            ClassLoader loader = new AgentClassLoader(jarPath);
            Class<?> installer = Class.forName(INSTALLER, true, loader);
            installer.getMethod("install", Instrumentation.class, String.class, String.class, String.class)
                    .invoke(null, inst, args, source, version);
            System.setProperty(MARKER_PROPERTY, version);
        } catch (Throwable t) {
            Throwable cause = rootCause(t);
            System.setProperty(FAILED_PROPERTY, version + ": " + cause);
            log("failed to start, HTTPS capture is off for this JVM: " + cause);
        }
    }

    /**
     * Whether the JVM runs one of the JDK's own tools (jcmd, jps, jstack,
     * keytool, javac, jshell and so on), from its sun.java.command: the main
     * class, prefixed with its module on JDK 9+ ("jdk.jcmd/sun.tools.jcmd.JCmd"),
     * or a jar path for {@code java -jar}, then the arguments. Their main
     * classes are in packages the JDK reserves for itself.
     */
    static boolean isJdkTool(String command) {
        if (command == null) {
            return false;
        }
        String main = command.trim();
        int space = main.indexOf(' ');
        if (space >= 0) {
            main = main.substring(0, space);
        }
        if (main.endsWith(".jar")) {
            return false;
        }
        int slash = main.indexOf('/');
        if (slash >= 0) {
            main = main.substring(slash + 1);
        }
        return main.startsWith("sun.") || main.startsWith("jdk.") || main.startsWith("java.")
                || main.startsWith("com.sun.tools.");
    }

    private static Throwable rootCause(Throwable t) {
        while (t.getCause() != null && t.getCause() != t) {
            t = t.getCause();
        }
        return t;
    }

    private static void log(String msg) {
        System.err.println("[postman-insights-agent] " + msg);
    }
}
