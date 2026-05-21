// SPDX-License-Identifier: Apache-2.0

package com.postman.insights.agent;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.instrument.Instrumentation;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.jar.JarFile;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.matcher.ElementMatchers;

import com.postman.insights.agent.instrumentations.JettySslEndPointInst;
import com.postman.insights.agent.instrumentations.SSLEngineInst;

/**
 * Postman Insights Java agent — JVM entry point.
 *
 * <p>Loaded with {@code -javaagent:postman-java-agent.jar}. ByteBuddy
 * installs class-file transformers that splice {@code @Advice} bytecode
 * around the SSLEngine.wrap / unwrap exit points. At advice exit, plaintext
 * is read out of the relevant {@link java.nio.ByteBuffer} and shipped to
 * the kernel via {@code ioctl(0, 0x0b10b1, …)} → java_tls kprobe →
 * ringbuf → adapter → akinet parser.</p>
 *
 * <p>Scope (Phase 5b.2): {@link SSLEngineInst} only. Spring Boot / Tomcat
 * / Netty / gRPC-Java workloads come in 5c.</p>
 */
public final class Agent {

    private Agent() {}

    /** Called by the JVM before any application classes load. */
    public static void premain(String agentArgs, Instrumentation inst) {
        attach("premain", agentArgs, inst);
    }

    /** Called by the JVM for runtime attach. We share the same wiring. */
    public static void agentmain(String agentArgs, Instrumentation inst) {
        attach("agentmain", agentArgs, inst);
    }

    // -- CLI-tool detection -----------------------------------------------

    /**
     * Bare-name basenames of JDK CLI tools whose wrapper scripts pass their
     * own name as the first token of {@code sun.java.command}. Match
     * verbatim against the basename.
     */
    private static final Set<String> CLI_TOOL_BASENAMES =
            Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
                    "keytool", "jarsigner", "jar", "javac", "javadoc", "jshell",
                    "jcmd", "jstack", "jmap", "jps", "jstat", "jinfo", "jhsdb",
                    "jlink", "jmod", "jdeps", "jdeprscan", "jpackage", "jconsole",
                    "jdb", "jrunscript", "jwebserver")));

    /**
     * Fully-qualified main-class prefixes for the same tools when launched
     * via {@code java -cp ... <main-class>}. Match as a String startsWith
     * against the first token of {@code sun.java.command}.
     */
    private static final String[] CLI_TOOL_FQN_PREFIXES = {
            "sun.security.tools.keytool.",
            "sun.security.tools.jarsigner.",
            "sun.tools.jar.",                // JDK 8 jar tool
            "com.sun.tools.javac.",          // JDK 8 javac
            "jdk.jartool.",                  // JDK 9+ jar tool
            "jdk.compiler.",                 // JDK 9+ javac
            "com.sun.tools.javadoc.",
            "jdk.javadoc.",
            "jdk.jshell.",
            "sun.tools.attach.",
            "sun.tools.jcmd.",
            "sun.tools.jstack.",
            "sun.tools.jmap.",
            "sun.tools.jps.",
            "sun.tools.jstat.",
            "sun.tools.jinfo.",
    };

    /**
     * Returns true if this JVM looks like a short-lived JDK CLI tool that
     * we should NOT instrument. Detection is conservative — false negatives
     * (failing to detect a tool) are harmless (cosmetic noise), false
     * positives (skipping a real workload) would silently drop
     * instrumentation. The only way a real workload matches is if its main
     * class name happens to start with {@code sun.security.tools.keytool.}
     * (etc.), which the JLS effectively prohibits for non-JDK code.
     *
     * <p>The detection respects an escape hatch: setting
     * {@code -Dpostman.agent.force=true} bypasses this check, in case a
     * caller really does want the agent in (say) {@code jshell}.
     */
    static boolean shouldSkipForCliToolJVM() {
        if (Boolean.getBoolean("postman.agent.force")) {
            return false;
        }
        String cmd = System.getProperty("sun.java.command", "");
        if (cmd.isEmpty()) {
            return false;
        }
        // First whitespace-delimited token: main class FQN OR wrapper name.
        int sp = cmd.indexOf(' ');
        String first = (sp >= 0) ? cmd.substring(0, sp) : cmd;

        // Path form: "/usr/lib/jvm/.../bin/keytool" or just "keytool".
        // Strip any directory prefix to get the basename.
        int slash = first.lastIndexOf('/');
        if (slash >= 0) {
            first = first.substring(slash + 1);
        }
        int bslash = first.lastIndexOf('\\');
        if (bslash >= 0) {
            first = first.substring(bslash + 1);
        }

        // Strip a trailing .jar suffix — 'java -jar /path/keytool.jar' would
        // set sun.java.command to '/path/keytool.jar args...'.
        if (first.endsWith(".jar")) {
            first = first.substring(0, first.length() - 4);
        }

        if (CLI_TOOL_BASENAMES.contains(first)) {
            return true;
        }
        for (String prefix : CLI_TOOL_FQN_PREFIXES) {
            if (first.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private static void attach(String entry, String agentArgs, Instrumentation inst) {
        // (0) Early-exit guard for short-lived CLI tools (keytool, jar, jcmd,
        // javac, etc.). These JVMs typically inherit JAVA_TOOL_OPTIONS from
        // their parent process, get our -javaagent appended, and try to
        // initialise the agent. On JDK 25 with the `jdk.unsupported` module
        // visibility tightening, that initialisation often fails with
        // 'NoClassDefFoundError: sun/misc/Unsafe' — a real error stack
        // printed to stderr that confuses operators (see
        // docs/webhook-runbook.md LIMIT-2).
        //
        // These tools are short-lived and serve no instrumentation value;
        // skipping attach is purely a cosmetic + correctness improvement.
        // The PRIMARY JVM (the one the user actually ran) keeps the agent.
        if (shouldSkipForCliToolJVM()) {
            System.err.println("[postman-insights] skipping agent attach "
                    + "(JVM appears to be a short-lived CLI tool: "
                    + System.getProperty("sun.java.command", "<unknown>") + ")");
            return;
        }

        long t0 = System.nanoTime();

        // (1) Extract the bundled bootstrap JAR and put it on the JVM's
        // bootstrap class loader. This makes IoctlPacket / NativeMemory /
        // SSLEngineInst$Hooks reachable from inside JDK classes like
        // sun.security.ssl.SSLEngineImpl (which lives in module java.base,
        // loaded by bootstrap, and can't see app-loaded classes).
        //
        // We deliberately do NOT append the whole main agent JAR — doing
        // so puts ByteBuddy on bootstrap AND app, which causes
        // loader-constraint LinkageError when Agent (app-loaded) calls
        // ByteBuddy methods whose signatures reference bootstrap-resolved
        // types.
        try {
            File bootJar = extractBundledBootstrapJar();
            inst.appendToBootstrapClassLoaderSearch(new JarFile(bootJar));
            System.err.println("[postman-insights] appended to bootstrap CL: " + bootJar);
        } catch (Throwable t) {
            System.err.println("[postman-insights] agent attach FAILED at bootstrap step: " + t);
            t.printStackTrace(System.err);
            return;
        }

        // (2) Open java.base read access to our module. Required on JDK 9+
        // when our classes are in the unnamed module (default for
        // -javaagent jars without an explicit module-info). On JDK 8 there
        // is no module system, so this step is skipped via reflection-based
        // invocation. Belt-and-braces alongside the bootstrap append.
        try {
            // Use reflection so this code compiles & loads on JDK 8 (which
            // doesn't have java.lang.Module or Instrumentation.redefineModule).
            Class<?> moduleClass = tryLoad("java.lang.Module");
            if (moduleClass != null) {
                Object ourModule = Agent.class.getClass()
                        .getMethod("getModule").invoke(Agent.class);
                // Look up the SSLEngine class without an import (would force
                // a load on classes we want to ignore on JDK 8 too).
                Class<?> sslEngineClass = Class.forName("javax.net.ssl.SSLEngine");
                Object javaBase = sslEngineClass.getClass()
                        .getMethod("getModule").invoke(sslEngineClass);
                if (javaBase != null && ourModule != null && javaBase != ourModule) {
                    java.lang.reflect.Method redefineModule = Instrumentation.class.getMethod(
                            "redefineModule", moduleClass,
                            java.util.Set.class, java.util.Map.class,
                            java.util.Map.class, java.util.Set.class,
                            java.util.Map.class);
                    redefineModule.invoke(inst,
                            javaBase,
                            java.util.Collections.singleton(ourModule),
                            java.util.Collections.emptyMap(),
                            java.util.Collections.emptyMap(),
                            java.util.Collections.emptySet(),
                            java.util.Collections.emptyMap());
                }
            }
        } catch (Throwable t) {
            // JDK 8 path (no module system) or transient failure — not
            // critical because the bootstrap-classpath append on its own
            // is sufficient for advice to find the helper classes.
            if (System.getProperty("postman.agent.debug") != null) {
                System.err.println("[postman-insights] redefineModule skipped/failed: " + t);
            }
        }

        // (3) Force the BOOTSTRAP copy of NativeMemory to <clinit> first,
        // which makes IT the one that calls System.load on libpostman_jni.so.
        //
        // Why this matters on JDK 8: JNI's name-based symbol lookup is
        // per-classloader on JDK 8. If we instead initialised the app-CL
        // copy of NativeMemory here (via a direct call like
        // NativeMemory.allocateMemory(8)), the JNI lib would be registered
        // with the app classloader. Then the ByteBuddy advice (inlined into
        // bootstrap-loaded SSLEngineImpl) calls NativeMemory.doIoctlNative
        // resolving through the BOOTSTRAP copy of NativeMemory, whose
        // <clinit> would see 'already loaded' and skip the System.load —
        // and JDK 8 cannot resolve the native symbol from the bootstrap-CL's
        // view of the lib. Result: UnsatisfiedLinkError swallowed by
        // advice's suppress=Throwable, ZERO captured events on JDK 8.
        //
        // JDK 9+ relaxed this and looks up JNI symbols process-wide, which
        // is why the same code worked on JDK 11/17/21 but silently failed
        // on JDK 8. Diagnosed in phase-5c2-results.md.
        //
        // Class.forName(..., true, null) loads via the BOOTSTRAP CL and
        // triggers <clinit>. Reflection on the loaded class invokes static
        // methods through the bootstrap-CL copy.
        try {
            Class<?> bootNativeMemory = Class.forName(
                    "com.postman.insights.agent.ebpf.NativeMemory", true, null);
            // allocateMemory(8) + freeMemory ensure the JNI lib is loaded
            // AND that the native doIoctlNative symbol has been resolved
            // for this classloader's view of the class.
            long probe = (long) bootNativeMemory.getMethod("allocateMemory", long.class)
                    .invoke(null, 8L);
            bootNativeMemory.getMethod("freeMemory", long.class).invoke(null, probe);
        } catch (Throwable t) {
            System.err.println("[postman-insights] agent attach FAILED at native step: " + t);
            t.printStackTrace(System.err);
            return;
        }

        boolean debug = System.getProperty("postman.agent.debug") != null;

        AgentBuilder builder = new AgentBuilder.Default()
                // Default ignore list is conservative — it excludes bootstrap
                // classes, which means SSLEngineImpl (in java.base) would be
                // ignored. We override with a narrower list that only excludes
                // our own packages.
                .ignore(
                        ElementMatchers.<net.bytebuddy.description.type.TypeDescription>nameStartsWith(
                                "com.postman.insights.agent.")
                        .or(ElementMatchers.nameStartsWith("com.postman.insights.agent.shaded.")))
                .disableClassFormatChanges()
                .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
                .with(AgentBuilder.InitializationStrategy.NoOp.INSTANCE)
                .with(AgentBuilder.TypeStrategy.Default.REDEFINE);

        if (debug) {
            builder = builder.with(AgentBuilder.Listener.StreamWriting.toSystemError());
        } else {
            // Always log errors, even outside debug mode — silent advice
            // failures cost us hours of head-scratching.
            builder = builder.with(
                    new AgentBuilder.Listener.WithErrorsOnly(
                            AgentBuilder.Listener.StreamWriting.toSystemError()));
        }

        builder = SSLEngineInst.install(builder);
        builder = JettySslEndPointInst.install(builder);

        builder.installOn(inst);

        long dtMs = (System.nanoTime() - t0) / 1_000_000;
        System.err.println("[postman-insights] agent attached via " + entry +
                           " in " + dtMs + " ms (args=" + (agentArgs == null ? "" : agentArgs) + ")");

        // Optional shutdown-time counter dump for diagnostic runs.
        if (System.getProperty("postman.agent.trace.first") != null) {
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                try {
                    Class<?> hooks = Class.forName(
                            "com.postman.insights.agent.instrumentations.SSLEngineInst$Hooks");
                    long wc = (long) hooks.getMethod("wrapCalls").invoke(null);
                    long we = (long) hooks.getMethod("wrapEmits").invoke(null);
                    long uc = (long) hooks.getMethod("unwrapCalls").invoke(null);
                    long ue = (long) hooks.getMethod("unwrapEmits").invoke(null);
                    System.err.println("[postman-insights] FINAL counters: wrap calls=" + wc +
                            " emits=" + we + " | unwrap calls=" + uc + " emits=" + ue);
                } catch (Throwable t) {
                    System.err.println("[postman-insights] counter dump failed: " + t);
                }
            }, "postman-insights-counter-dump"));
        }
    }

    /** Extract {@code META-INF/postman-agent-bootstrap.jarblob} from our own
     *  JAR to a process-private temp file. The JVM's
     *  {@code appendToBootstrapClassLoaderSearch} needs a real on-disk
     *  JarFile, so we materialise it. JDK-8-compatible — uses
     *  {@link File#createTempFile} and {@link FileOutputStream} rather than
     *  {@code java.nio.file.Files} APIs. */
    private static File extractBundledBootstrapJar() throws IOException {
        ClassLoader cl = Agent.class.getClassLoader();
        if (cl == null) cl = ClassLoader.getSystemClassLoader();
        try (InputStream in = cl.getResourceAsStream("META-INF/postman-agent-bootstrap.jarblob")) {
            if (in == null) {
                throw new IOException("postman-agent-bootstrap.jarblob not found inside agent JAR " +
                        "(was the agent built with the bootstrap-jar Gradle task?)");
            }
            File tmp = File.createTempFile("postman-agent-bootstrap-", ".jar");
            tmp.deleteOnExit();
            try (OutputStream out = new FileOutputStream(tmp)) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) > 0) {
                    out.write(buf, 0, n);
                }
            }
            return tmp;
        }
    }

    /** Class.forName that returns null on ClassNotFoundException (used for
     *  JDK-version-conditional reflection). */
    private static Class<?> tryLoad(String name) {
        try { return Class.forName(name); } catch (Throwable t) { return null; }
    }
}
