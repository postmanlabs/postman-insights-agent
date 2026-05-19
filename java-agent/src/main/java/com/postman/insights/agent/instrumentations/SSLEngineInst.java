// SPDX-License-Identifier: Apache-2.0

package com.postman.insights.agent.instrumentations;

import java.nio.ByteBuffer;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.matcher.ElementMatchers;

import com.postman.insights.agent.ebpf.IoctlPacket;

/**
 * ByteBuddy instrumentation of {@link SSLEngine} implementations.
 *
 * <h2>Why the 4-arg signatures</h2>
 *
 * <p>{@link SSLEngine#wrap(ByteBuffer, ByteBuffer)} and
 * {@link SSLEngine#unwrap(ByteBuffer, ByteBuffer)} are <b>concrete methods
 * declared on the abstract {@code SSLEngine} class</b>. Implementations like
 * {@code sun.security.ssl.SSLEngineImpl} do NOT override them — they
 * delegate to the abstract 4-arg variants:</p>
 *
 * <pre>
 *   SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst)
 *   SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length)
 * </pre>
 *
 * <p>These ARE declared on {@code SSLEngineImpl} (and every other JSSE
 * provider's impl), so that's where we hook. Matching the 2-arg form on
 * {@code SSLEngineImpl} would silently match nothing — which is exactly
 * what bit us during 5b.2 development.</p>
 *
 * <h2>Single-buffer case</h2>
 *
 * <p>In practice, JDK's {@code HttpsServer}, modern HTTP clients, Tomcat,
 * Netty etc. all pass {@code length == 1} (one ByteBuffer scatter/gather
 * slot). For 5b.2 we only handle that single-buffer case explicitly;
 * length>1 calls fall through silently. Phase 5c will widen this.</p>
 *
 * <p>Advice contract: <b>must not throw into user code.</b> Every advice
 * method catches {@link Throwable} and swallows it.</p>
 */
public final class SSLEngineInst {

    private SSLEngineInst() {}

    /** Wire this instrumentation onto an existing builder. */
    public static AgentBuilder install(AgentBuilder builder) {
        return builder
                .type(ElementMatchers.isSubTypeOf(SSLEngine.class)
                        .and(ElementMatchers.not(ElementMatchers.isAbstract())))
                .transform((b, type, classLoader, module, protectionDomain) -> b
                        // wrap(ByteBuffer[], int, int, ByteBuffer)
                        .visit(Advice.to(WrapAdvice.class).on(
                                ElementMatchers.named("wrap")
                                        .and(ElementMatchers.takesArguments(4))
                                        .and(ElementMatchers.takesArgument(0, ByteBuffer[].class))
                                        .and(ElementMatchers.takesArgument(1, int.class))
                                        .and(ElementMatchers.takesArgument(2, int.class))
                                        .and(ElementMatchers.takesArgument(3, ByteBuffer.class))))
                        // unwrap(ByteBuffer, ByteBuffer[], int, int)
                        .visit(Advice.to(UnwrapAdvice.class).on(
                                ElementMatchers.named("unwrap")
                                        .and(ElementMatchers.takesArguments(4))
                                        .and(ElementMatchers.takesArgument(0, ByteBuffer.class))
                                        .and(ElementMatchers.takesArgument(1, ByteBuffer[].class))
                                        .and(ElementMatchers.takesArgument(2, int.class))
                                        .and(ElementMatchers.takesArgument(3, int.class)))));
    }

    // ----------------------------------------------------------------------
    // wrap(srcs[], offset, length, dst) — outbound plaintext lives in
    // srcs[offset..offset+length-1] before the call. result.bytesConsumed()
    // is the total across all matched src buffers; for length==1 it equals
    // (srcs[offset].position_after - entryPos).
    // ----------------------------------------------------------------------

    public static class WrapAdvice {
        @Advice.OnMethodEnter
        public static int onEnter(
                @Advice.Argument(0) ByteBuffer[] srcs,
                @Advice.Argument(1) int offset,
                @Advice.Argument(2) int length) {
            try {
                if (srcs == null || length != 1 || offset < 0 || offset >= srcs.length) return -1;
                ByteBuffer src = srcs[offset];
                return src != null ? src.position() : -1;
            } catch (Throwable t) {
                return -1;
            }
        }

        @Advice.OnMethodExit(suppress = Throwable.class)
        public static void onExit(
                @Advice.This            SSLEngine engine,
                @Advice.Argument(0)     ByteBuffer[] srcs,
                @Advice.Argument(1)     int offset,
                @Advice.Argument(2)     int length,
                @Advice.Return          SSLEngineResult result,
                @Advice.Enter           int entryPos) {
            try {
                if (result == null || entryPos < 0 || srcs == null) return;
                Hooks.afterWrap(engine, srcs, offset, length, result, entryPos);
            } catch (Throwable t) {
                // Swallow — never propagate into user code.
            }
        }
    }

    // ----------------------------------------------------------------------
    // unwrap(src, dsts[], offset, length) — inbound plaintext lands in
    // dsts[offset..offset+length-1] after the call.
    // ----------------------------------------------------------------------

    public static class UnwrapAdvice {
        @Advice.OnMethodExit(suppress = Throwable.class)
        public static void onExit(
                @Advice.This        SSLEngine engine,
                @Advice.Argument(1) ByteBuffer[] dsts,
                @Advice.Argument(2) int offset,
                @Advice.Argument(3) int length,
                @Advice.Return      SSLEngineResult result) {
            try {
                if (result == null || dsts == null) return;
                Hooks.afterUnwrap(engine, dsts, offset, length, result);
            } catch (Throwable t) {
                // Swallow.
            }
        }
    }

    // ----------------------------------------------------------------------
    // Real work — split out so advice bytecode stays small. These classes
    // are loaded from the agent JAR on the bootstrap class loader (see
    // Agent.premain's appendToBootstrapClassLoaderSearch).
    // ----------------------------------------------------------------------

    public static final class Hooks {
        private Hooks() {}

        /**
         * 5b.3 crash-resilience knob. When the system property
         * {@code postman.agent.crash.injection} is set (any non-empty
         * value), every Hooks call throws a {@link RuntimeException}.
         * Used to verify that the {@code suppress = Throwable.class}
         * discipline on the advice catches every failure path and the
         * host HTTPS request still completes successfully.
         *
         * <p>Read once and cached — we don't want to hit
         * {@code System.getProperty} on every wrap/unwrap.</p>
         */
        private static final boolean CRASH_INJECTION =
                System.getProperty("postman.agent.crash.injection") != null;

        /** One-shot diagnostic: when -Dpostman.agent.trace.first=1 is set,
         *  the FIRST entry into each Hooks method prints a stderr line with
         *  the engine class, buffer state, and result. Used to discover
         *  whether advice is reaching specific frameworks like Jetty. */
        private static final boolean TRACE_FIRST =
                System.getProperty("postman.agent.trace.first") != null;
        private static final java.util.concurrent.atomic.AtomicBoolean WRAP_TRACED   = new java.util.concurrent.atomic.AtomicBoolean();
        private static final java.util.concurrent.atomic.AtomicBoolean UNWRAP_TRACED = new java.util.concurrent.atomic.AtomicBoolean();
        private static final java.util.concurrent.atomic.AtomicLong WRAP_CALLS   = new java.util.concurrent.atomic.AtomicLong();
        private static final java.util.concurrent.atomic.AtomicLong WRAP_EMITS   = new java.util.concurrent.atomic.AtomicLong();
        private static final java.util.concurrent.atomic.AtomicLong UNWRAP_CALLS = new java.util.concurrent.atomic.AtomicLong();
        private static final java.util.concurrent.atomic.AtomicLong UNWRAP_EMITS = new java.util.concurrent.atomic.AtomicLong();

        public static long wrapCalls()    { return WRAP_CALLS.get(); }
        public static long wrapEmits()    { return WRAP_EMITS.get(); }
        public static long unwrapCalls()  { return UNWRAP_CALLS.get(); }
        public static long unwrapEmits()  { return UNWRAP_EMITS.get(); }

        // wrap() scatter-gather: plaintext lives in srcs[offset..offset+length-1].
        // result.bytesConsumed() is the TOTAL across all matched buffers.
        // 5c.2 generalisation — the 5b.2 version skipped length != 1,
        // which silently lost Jetty (which uses multi-buffer writes).
        public static void afterWrap(SSLEngine engine, ByteBuffer[] srcs,
                                     int offset, int length,
                                     SSLEngineResult result, int entryFirstPos) {
            if (CRASH_INJECTION) {
                throw new RuntimeException("postman-agent: synthetic crash from afterWrap");
            }
            WRAP_CALLS.incrementAndGet();
            if (TRACE_FIRST && WRAP_TRACED.compareAndSet(false, true)) {
                System.err.println("[postman-insights] afterWrap FIRED  engine=" + engine.getClass().getName()
                        + " srcs.length=" + (srcs == null ? "null" : srcs.length)
                        + " offset=" + offset + " length=" + length
                        + " consumed=" + (result == null ? "null" : result.bytesConsumed())
                        + " produced=" + (result == null ? "null" : result.bytesProduced())
                        + " entryFirstPos=" + entryFirstPos);
            }
            if (result == null || srcs == null || length <= 0) return;
            int consumed = result.bytesConsumed();
            if (consumed <= 0) return;

            int id = System.identityHashCode(engine);

            // Fast path: single buffer (the common Spring Boot / Tomcat / HelloHttps case).
            if (length == 1) {
                if (entryFirstPos < 0) return;
                ByteBuffer src = srcs[offset];
                if (src == null) return;
                int n = Math.min(consumed, src.position() - entryFirstPos);
                if (n <= 0) return;
                byte[] copy = readBytes(src, entryFirstPos, n);
                if (copy == null || copy.length == 0) return;
                IoctlPacket.sendThreadLocal(IoctlPacket.OP_SEND,
                        id, 0, 0, 0, copy, 0, copy.length);
                WRAP_EMITS.incrementAndGet();
                return;
            }

            // Slow path: scatter-gather. We don't have per-buffer entry
            // positions for length>1; walk buffers in order and read the
            // trailing `remaining` bytes ending at each buffer's current
            // position, splitting `consumed` across them. Emit one ioctl
            // per source buffer — the kernel adapter is stream-oriented.
            int remaining = consumed;
            for (int i = offset; i < offset + length && remaining > 0; i++) {
                ByteBuffer src = srcs[i];
                if (src == null) continue;
                int endPos = src.position();
                int take = Math.min(remaining, endPos);
                int startPos = endPos - take;
                if (startPos < 0 || take <= 0) continue;
                byte[] copy = readBytes(src, startPos, take);
                if (copy == null || copy.length == 0) continue;
                IoctlPacket.sendThreadLocal(IoctlPacket.OP_SEND,
                        id, 0, 0, 0, copy, 0, copy.length);
                remaining -= take;
            }
        }

        // unwrap() scatter-gather: result.bytesProduced() lands in
        // dsts[offset..offset+length-1].
        public static void afterUnwrap(SSLEngine engine, ByteBuffer[] dsts,
                                       int offset, int length,
                                       SSLEngineResult result) {
            if (CRASH_INJECTION) {
                throw new RuntimeException("postman-agent: synthetic crash from afterUnwrap");
            }
            UNWRAP_CALLS.incrementAndGet();
            if (TRACE_FIRST && UNWRAP_TRACED.compareAndSet(false, true)) {
                System.err.println("[postman-insights] afterUnwrap FIRED engine=" + engine.getClass().getName()
                        + " dsts.length=" + (dsts == null ? "null" : dsts.length)
                        + " offset=" + offset + " length=" + length
                        + " produced=" + (result == null ? "null" : result.bytesProduced()));
            }
            if (result == null || dsts == null || length <= 0) return;
            int produced = result.bytesProduced();
            if (produced <= 0) return;

            int id = System.identityHashCode(engine);

            // Fast path: single dst.
            if (length == 1) {
                ByteBuffer dst = dsts[offset];
                if (dst == null) return;
                int endPos = dst.position();
                int startPos = endPos - produced;
                if (startPos < 0) return;
                byte[] copy = readBytes(dst, startPos, produced);
                if (copy == null || copy.length == 0) return;
                IoctlPacket.sendThreadLocal(IoctlPacket.OP_RECV,
                        id, 0, 0, 0, copy, 0, copy.length);
                UNWRAP_EMITS.incrementAndGet();
                return;
            }

            // Slow path: walk dsts in order, reading trailing bytes from each.
            int remaining = produced;
            for (int i = offset; i < offset + length && remaining > 0; i++) {
                ByteBuffer dst = dsts[i];
                if (dst == null) continue;
                int endPos = dst.position();
                int take = Math.min(remaining, endPos);
                int startPos = endPos - take;
                if (startPos < 0 || take <= 0) continue;
                byte[] copy = readBytes(dst, startPos, take);
                if (copy == null || copy.length == 0) continue;
                IoctlPacket.sendThreadLocal(IoctlPacket.OP_RECV,
                        id, 0, 0, 0, copy, 0, copy.length);
                remaining -= take;
            }
        }

        private static byte[] readBytes(ByteBuffer buf, int start, int len) {
            try {
                if (len <= 0) return null;
                ByteBuffer view = buf.duplicate();
                int cap = view.capacity();
                if (start < 0 || start + len > cap) return null;
                view.position(start);
                view.limit(start + len);
                byte[] out = new byte[len];
                view.get(out);
                return out;
            } catch (Throwable t) {
                return null;
            }
        }
    }
}
