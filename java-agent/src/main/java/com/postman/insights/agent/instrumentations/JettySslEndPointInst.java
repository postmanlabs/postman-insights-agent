// SPDX-License-Identifier: Apache-2.0

package com.postman.insights.agent.instrumentations;

import java.nio.ByteBuffer;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.matcher.ElementMatchers;

import com.postman.insights.agent.ebpf.IoctlPacket;

/**
 * Phase 5c.2 Jetty-specific instrumentation.
 *
 * <h2>Why this exists separately from SSLEngineInst</h2>
 *
 * <p>Jetty 12's {@code org.eclipse.jetty.io.ssl.SslConnection.SslEndPoint}
 * is the outbound endpoint that the {@code WriteFlusher} writes through.
 * Its {@code flush(ByteBuffer...)} method is the choke point — every
 * outbound HTTP response byte goes through it. Internally it calls
 * {@code SSLEngine.wrap()} via a layered state machine that buffers
 * pending ciphertext in a {@code RetainableByteBuffer _encryptedOutput}
 * field, queues partial writes, and re-flushes them later. The net effect
 * is that the {@code SSLEngine.wrap} calls we see at runtime carry empty
 * placeholder buffers as {@code srcs[0]} (Jetty passes
 * {@code BufferUtil.EMPTY_BUFFER} for state-machine wraps), and the
 * actual response plaintext sits in Jetty's buffer pool by the time
 * {@code wrap} would have seen it.</p>
 *
 * <p>Diagnosed in phase-5c2-results.md via TRACE_ALL: every Jetty wrap
 * call has {@code consumed=0, srcs[0].cap=0}, while curl receives correct
 * HTTPS responses. {@link SSLEngineInst}'s advice never gets to see real
 * plaintext for Jetty.</p>
 *
 * <h2>The fix</h2>
 *
 * <p>Hook {@code SslEndPoint.flush(ByteBuffer[])} directly. At entry we
 * see the plaintext response bytes BEFORE Jetty's encryption machinery
 * starts. Same shape as
 * {@link SSLEngineInst}'s {@code OP_SEND} path but with Jetty-specific
 * type matching.</p>
 *
 * <p>This is the OBI / Datadog pattern: when a JDK-level abstraction is
 * bypassed by a framework optimisation, hook the framework directly. We
 * only ship Jetty advice; we do NOT add a runtime dependency on Jetty.
 * ByteBuddy's {@code nameStartsWith} matcher only fires for processes
 * that actually load Jetty.</p>
 */
public final class JettySslEndPointInst {

    private JettySslEndPointInst() {}

    /** Wire this instrumentation onto an existing builder. */
    public static AgentBuilder install(AgentBuilder builder) {
        return builder
                // Jetty's SslEndPoint is a nested class of SslConnection.
                // Match by exact class name; Jetty doesn't move this class
                // between versions (it's been stable since Jetty 9).
                .type(ElementMatchers.named("org.eclipse.jetty.io.ssl.SslConnection$SslEndPoint"))
                .transform((b, type, classLoader, module, protectionDomain) -> b
                        .visit(Advice.to(FlushAdvice.class).on(
                                ElementMatchers.named("flush")
                                        .and(ElementMatchers.takesArguments(1))
                                        .and(ElementMatchers.takesArgument(0, ByteBuffer[].class)))));
    }

    // ----------------------------------------------------------------------
    // flush(ByteBuffer[]) — outbound plaintext entry point.
    //
    // Captured BEFORE Jetty's encryption machinery runs. We read the bytes
    // that the caller wants to send out, which are unambiguously plaintext.
    // ----------------------------------------------------------------------

    public static class FlushAdvice {
        @Advice.OnMethodEnter(suppress = Throwable.class)
        public static void onEnter(
                @Advice.This        Object endPoint,
                @Advice.Argument(0) ByteBuffer[] buffers) {
            try {
                JettyHooks.beforeFlush(endPoint, buffers);
            } catch (Throwable t) {
                // Swallow — never propagate into Jetty.
            }
        }
    }

    /**
     * Real work lives here so advice bytecode stays small. Loaded from the
     * bootstrap JAR (see {@code java-agent/build.gradle.kts} bootstrapJar
     * task includes this class).
     */
    public static final class JettyHooks {
        private JettyHooks() {}

        private static final boolean CRASH_INJECTION =
                System.getProperty("postman.agent.crash.injection") != null;

        public static void beforeFlush(Object endPoint, ByteBuffer[] buffers) {
            if (CRASH_INJECTION) {
                throw new RuntimeException("postman-agent: synthetic crash from Jetty beforeFlush");
            }
            if (buffers == null || buffers.length == 0) return;

            // Stable connection id across SEND/RECV: use identityHashCode of
            // the endpoint (one per connection). Matches the kernel-side
            // hash semantics in java_tls.bpf.c.
            int id = System.identityHashCode(endPoint);

            for (ByteBuffer buf : buffers) {
                if (buf == null) continue;
                int n = buf.remaining();
                if (n <= 0) continue;

                // Copy bytes WITHOUT mutating the caller's buffer state.
                ByteBuffer view = buf.duplicate();
                byte[] copy = new byte[n];
                view.get(copy);

                IoctlPacket.sendThreadLocal(
                        IoctlPacket.OP_SEND,
                        id, 0,
                        0,  0,
                        copy, 0, copy.length);
            }
        }
    }
}
