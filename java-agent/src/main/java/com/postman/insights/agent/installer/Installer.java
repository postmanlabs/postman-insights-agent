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
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

import java.io.File;
import java.lang.instrument.Instrumentation;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.asm.AsmVisitorWrapper;
import net.bytebuddy.dynamic.DynamicType;
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

    private static final Class<?> BUF = ByteBuffer.class;
    private static final Class<?> BUFS = ByteBuffer[].class;
    private static final Class<?> INT = int.class;

    /**
     * Every wrap and unwrap shape engines declare. Engines implement the
     * abstract 4-arg forms, but may override the others without delegating to
     * them (Netty's OpenSSL engine does), so each is hooked; the bridge emits
     * only at the outermost hooked call.
     */
    private static final List<AsmVisitorWrapper> HOOKS = hooks();

    private static List<AsmVisitorWrapper> hooks() {
        List<AsmVisitorWrapper> h = new ArrayList<AsmVisitorWrapper>();
        h.add(hook(WrapAdvice.Array.class, "wrap", BUFS, INT, INT, BUF));
        h.add(hook(WrapAdvice.Arrays.class, "wrap", BUFS, INT, INT, BUFS, INT, INT));
        h.add(hook(WrapAdvice.ArrayAll.class, "wrap", BUFS, BUF));
        h.add(hook(WrapAdvice.Single.class, "wrap", BUF, BUF));
        h.add(hook(UnwrapAdvice.Array.class, "unwrap", BUF, BUFS, INT, INT));
        h.add(hook(UnwrapAdvice.Arrays.class, "unwrap", BUFS, INT, INT, BUFS, INT, INT));
        h.add(hook(UnwrapAdvice.ArrayAll.class, "unwrap", BUF, BUFS));
        h.add(hook(UnwrapAdvice.ArraysAll.class, "unwrap", BUFS, BUFS));
        h.add(hook(UnwrapAdvice.Single.class, "unwrap", BUF, BUF));
        return h;
    }

    private static final Class<?> BYTES = byte[].class;

    /** The JDK's SSLSocket: its application streams and its close (SocketAdvice). */
    private static final AsmVisitorWrapper SOCKET_READ = hook(SocketAdvice.Read.class, "read", BYTES, INT, INT);
    private static final AsmVisitorWrapper SOCKET_WRITE = hook(SocketAdvice.Write.class, "write", BYTES, INT, INT);
    private static final AsmVisitorWrapper SOCKET_CLOSE = hook(SocketAdvice.Close.class, "close");

    private static AsmVisitorWrapper hook(Class<?> advice, String method, Class<?>... params) {
        return Advice.to(advice).on(named(method).and(not(isAbstract())).and(takesArguments(params)));
    }

    private static DynamicType.Builder<?> instrument(DynamicType.Builder<?> builder) {
        for (AsmVisitorWrapper h : HOOKS) {
            builder = builder.visit(h);
        }
        return builder;
    }

    /**
     * @param source Contract.HEARTBEAT_SOURCE_STATIC (-javaagent) or
     *               Contract.HEARTBEAT_SOURCE_ATTACH (dynamic attach)
     */
    public static void install(Instrumentation inst, String rawArgs, String source, String version) {
        long start = System.nanoTime();
        AgentArgs args = AgentArgs.parse(rawArgs);
        Bridge.start(args.captureCap, System.getProperty(Contract.FRAME_LOG_PROPERTY));
        ControlFile control = new ControlFile(
                new File(System.getProperty(Contract.CONTROL_FILE_PROPERTY, Contract.CONTROL_FILE_PATH)));
        Supervisor supervisor = new Supervisor(control, args.captureCap, version, source);

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
                .transform((builder, type, loader, module, pd) -> instrument(builder))
                .type(named(SocketAdvice.INPUT))
                .transform((builder, type, loader, module, pd) -> builder.visit(SOCKET_READ))
                .type(named(SocketAdvice.OUTPUT))
                .transform((builder, type, loader, module, pd) -> builder.visit(SOCKET_WRITE))
                .type(named(SocketAdvice.SOCKET))
                .transform((builder, type, loader, module, pd) -> builder.visit(SOCKET_CLOSE))
                .installOn(inst);

        log("version " + version + " loaded (" + source + ") into Java " + System.getProperty("java.version")
                + " in " + (System.nanoTime() - start) / 1_000_000 + " ms");
        // Apply the control file before returning, so a JVM the Insights
        // agent is monitoring captures from its first request.
        supervisor.check(System.currentTimeMillis());
        supervisor.start();
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
        System.err.println("[postman-insights-java-agent] " + msg);
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
