// SPDX-License-Identifier: Apache-2.0

package com.postman.insights.agent;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.instrument.Instrumentation;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.jar.JarFile;
import javax.net.ssl.SSLEngine;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.matcher.ElementMatchers;

import com.postman.insights.agent.ebpf.NativeMemory;
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
            Path bootJar = extractBundledBootstrapJar();
            inst.appendToBootstrapClassLoaderSearch(new JarFile(bootJar.toFile()));
            System.err.println("[postman-insights] appended to bootstrap CL: " + bootJar);
        } catch (Throwable t) {
            System.err.println("[postman-insights] agent attach FAILED at bootstrap step: " + t);
            t.printStackTrace(System.err);
            return;
        }

        // (2) Open java.base read access to our module. Required when our
        // classes are in the unnamed module (default for -javaagent jars
        // without an explicit module-info). Belt-and-braces alongside the
        // bootstrap append.
        try {
            Module ourModule    = Agent.class.getModule();
            Module javaBase     = SSLEngine.class.getModule();
            if (javaBase != null && ourModule != null && javaBase != ourModule) {
                inst.redefineModule(
                        javaBase,
                        /*extraReads=*/ java.util.Set.of(ourModule),
                        /*extraExports=*/ java.util.Map.of(),
                        /*extraOpens=*/ java.util.Map.of(),
                        /*extraUses=*/ java.util.Set.of(),
                        /*extraProvides=*/ java.util.Map.of());
            }
        } catch (Throwable t) {
            System.err.println("[postman-insights] WARNING: redefineModule failed: " + t);
            // continue — bootstrap-classpath append alone is usually enough
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

    /** Extract {@code META-INF/postman-agent-bootstrap.jar} from our own
     *  JAR to a process-private temp file. The JVM's
     *  {@code appendToBootstrapClassLoaderSearch} needs a real on-disk
     *  JarFile, so we materialise it. */
    private static Path extractBundledBootstrapJar() throws IOException {
        ClassLoader cl = Agent.class.getClassLoader();
        if (cl == null) cl = ClassLoader.getSystemClassLoader();
        // We embed the bootstrap JAR with a .jarblob extension so the
        // shadow Gradle plugin doesn't try to merge its contents into the
        // main JAR. Identical bytes; just a different filename.
        try (InputStream in = cl.getResourceAsStream("META-INF/postman-agent-bootstrap.jarblob")) {
            if (in == null) {
                throw new IOException("postman-agent-bootstrap.jarblob not found inside agent JAR " +
                        "(was the agent built with the bootstrap-jar Gradle task?)");
            }
            Path tmp = Files.createTempFile("postman-agent-bootstrap-", ".jar");
            tmp.toFile().deleteOnExit();
            Files.copy(in, tmp, StandardCopyOption.REPLACE_EXISTING);
            return tmp;
        }
    }
}
