package com.postman.insights.agent.installer;

import static net.bytebuddy.matcher.ElementMatchers.failSafe;
import static net.bytebuddy.matcher.ElementMatchers.hasSuperType;
import static net.bytebuddy.matcher.ElementMatchers.isAbstract;
import static net.bytebuddy.matcher.ElementMatchers.isInterface;
import static net.bytebuddy.matcher.ElementMatchers.isSynthetic;
import static net.bytebuddy.matcher.ElementMatchers.nameStartsWith;
import static net.bytebuddy.matcher.ElementMatchers.nameContains;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.not;
import static net.bytebuddy.matcher.ElementMatchers.takesArgument;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

import java.lang.instrument.Instrumentation;
import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicInteger;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.pool.TypePool;
import net.bytebuddy.utility.JavaModule;

import com.postman.insights.agent.bootstrap.Bridge;
import com.postman.insights.agent.bootstrap.Contract;

/**
 * Installs the hooks. Loaded by AgentClassLoader, called once per JVM by
 * AgentMain.
 */
public final class Installer {
    private Installer() {}

    /**
     * @param source "static" (-javaagent) or "attach" (dynamic attach)
     */
    public static void install(Instrumentation inst, String rawArgs, String source, String version) {
        long start = System.nanoTime();
        AgentArgs args = AgentArgs.parse(rawArgs);
        Bridge.start(args.captureCap, System.getProperty(Contract.FRAME_LOG_PROPERTY));

        ClassLoader own = Installer.class.getClassLoader();
        newAgentBuilder()
                // Retransform engines that are already loaded (dynamic attach
                // into a JVM that is serving traffic) without changing their
                // shape, which retransformation does not allow.
                .disableClassFormatChanges()
                .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
                // Describe types from class files only. Resolving them through
                // reflection loads classes during matching, which broke
                // gRPC-Java startup in the old proof of concept.
                .with(AgentBuilder.DescriptionStrategy.Default.POOL_ONLY)
                // Advice is inlined, so no helper classes are ever injected.
                .with(AgentBuilder.InjectionStrategy.Disabled.INSTANCE)
                .with(new ErrorListener())
                .ignore(nameStartsWith("com.postman.insights.agent.")
                        .or(nameStartsWith("net.bytebuddy."))
                        .or(nameStartsWith("sun.reflect."))
                        .or(isSynthetic())
                        // Classes generated at runtime (proxies, lambda forms)
                        // have no class file to describe and are never engines.
                        .or(nameStartsWith("java.lang.invoke."))
                        .or(nameStartsWith("jdk.internal.reflect."))
                        .or(nameStartsWith("jdk.proxy"))
                        .or(nameStartsWith("com.sun.proxy."))
                        .or(nameContains("$$Lambda")))
                .or((type, loader, module, classBeingRedefined, pd) -> loader == own)
                // Advice inlined into java.base calls Bridge, which lives in
                // the bootstrap class loader's unnamed module.
                .assureReadEdgeTo(inst, Bridge.class)
                // Every SSLEngine implementation: the JDK's, Netty's, Conscrypt's,
                // and wrappers. failSafe: a type whose hierarchy cannot be
                // resolved is skipped, never an error.
                .type(failSafe(hasSuperType(named("javax.net.ssl.SSLEngine")).and(not(isInterface()))))
                .transform((builder, type, loader, module, pd) -> builder
                        .visit(Advice.to(WrapAdvice.class).on(named("wrap")
                                .and(not(isAbstract()))
                                .and(takesArguments(4))
                                .and(takesArgument(0, ByteBuffer[].class))
                                .and(takesArgument(3, ByteBuffer.class))))
                        .visit(Advice.to(UnwrapAdvice.class).on(named("unwrap")
                                .and(not(isAbstract()))
                                .and(takesArguments(4))
                                .and(takesArgument(0, ByteBuffer.class))
                                .and(takesArgument(1, ByteBuffer[].class)))))
                .installOn(inst);

        log("version " + version + " loaded (" + source + ") into Java " + System.getProperty("java.version")
                + " in " + (System.nanoTime() - start) / 1_000_000 + " ms");
    }

    private static final String NEXUS_DISABLED = "net.bytebuddy.nexus.disabled";

    /**
     * AgentBuilder.Default's constructor prepares Byte Buddy's Nexus, which
     * injects a class into the application's system class loader (through
     * sun.misc.Unsafe, which JDK 24+ reports on stderr). Inlined advice needs
     * no Nexus, so it is disabled while the builder is created. Byte Buddy reads
     * the property once, when this agent's own copy of NexusAccessor
     * initializes, and the previous value is restored right away.
     */
    private static AgentBuilder newAgentBuilder() {
        String previous = System.getProperty(NEXUS_DISABLED);
        System.setProperty(NEXUS_DISABLED, "true");
        try {
            return new AgentBuilder.Default().with(AgentBuilder.InitializationStrategy.NoOp.INSTANCE);
        } finally {
            if (previous == null) {
                System.clearProperty(NEXUS_DISABLED);
            } else {
                System.setProperty(NEXUS_DISABLED, previous);
            }
        }
    }

    static void log(String msg) {
        System.err.println("[postman-insights-agent] " + msg);
    }

    /**
     * Logs the first few instrumentation failures; they never affect the
     * application. Types without a class file (generated at runtime) cannot be
     * described and are skipped silently: they are never engines.
     */
    private static final class ErrorListener extends AgentBuilder.Listener.Adapter {
        private static final int MAX_LOGGED = 10;
        private final AtomicInteger logged = new AtomicInteger();

        @Override
        public void onError(String typeName, ClassLoader loader, JavaModule module, boolean loaded, Throwable t) {
            if (t instanceof TypePool.Resolution.NoSuchTypeException) {
                return;
            }
            if (logged.incrementAndGet() <= MAX_LOGGED) {
                log("could not instrument " + typeName + ": " + t);
            }
        }
    }
}
