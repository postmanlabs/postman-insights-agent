package com.postman.insights.agent;

import java.io.File;
import java.lang.instrument.Instrumentation;
import java.util.jar.JarFile;

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
    private static final String INSTALLER = "com.postman.insights.agent.installer.Installer";

    private AgentMain() {}

    public static void premain(String args, Instrumentation inst) {
        start(args, inst, "static");
    }

    public static void agentmain(String args, Instrumentation inst) {
        start(args, inst, "attach");
    }

    private static synchronized void start(String args, Instrumentation inst, String source) {
        try {
            String loaded = System.getProperty(MARKER_PROPERTY);
            if (loaded != null) {
                log("version " + loaded + " is already loaded in this JVM; not loading again");
                return;
            }
            File jarPath = new File(AgentMain.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            JarFile jar = new JarFile(jarPath, false);
            String version = jar.getManifest().getMainAttributes().getValue("Implementation-Version");
            if (version == null) {
                version = "unknown";
            }
            // Set first, so a second load attempt (static and attach, or two
            // attaches) can never install the hooks twice.
            System.setProperty(MARKER_PROPERTY, version);

            inst.appendToBootstrapClassLoaderSearch(jar);
            ClassLoader loader = new AgentClassLoader(jarPath);
            Class<?> installer = Class.forName(INSTALLER, true, loader);
            installer.getMethod("install", Instrumentation.class, String.class, String.class, String.class)
                    .invoke(null, inst, args, source, version);
        } catch (Throwable t) {
            log("failed to start, HTTPS capture is off for this JVM: " + rootCause(t));
        }
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
