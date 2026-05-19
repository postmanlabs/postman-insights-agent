// SPDX-License-Identifier: Apache-2.0

package com.postman.insights.agent;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.instrument.Instrumentation;
import java.util.jar.JarFile;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.matcher.ElementMatchers;

import com.postman.insights.agent.ebpf.NativeMemory;
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

    private static void attach(String entry, String agentArgs, Instrumentation inst) {
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

        // (3) Force NativeMemory's static init early so any failure surfaces
        // at agent-attach time, not on the first HTTPS request.
        try {
            long probe = NativeMemory.allocateMemory(8);
            NativeMemory.freeMemory(probe);
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
