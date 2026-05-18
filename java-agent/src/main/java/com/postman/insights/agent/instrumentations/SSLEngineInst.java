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
                if (length != 1 || entryPos < 0 || result == null) return;
                Hooks.afterWrap(engine, srcs[offset], result, entryPos);
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
                if (length != 1 || result == null) return;
                Hooks.afterUnwrap(engine, dsts[offset], result);
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

        public static void afterWrap(SSLEngine engine, ByteBuffer src,
                                     SSLEngineResult result, int entryPos) {
            if (CRASH_INJECTION) {
                throw new RuntimeException("postman-agent: synthetic crash from afterWrap");
            }
            if (result == null || src == null) return;
            int consumed = result.bytesConsumed();
            if (consumed <= 0 || entryPos < 0) return;

            byte[] copy = readBytes(src, entryPos, consumed);
            if (copy == null || copy.length == 0) return;

            int id = System.identityHashCode(engine);
            IoctlPacket.sendThreadLocal(
                    IoctlPacket.OP_SEND,
                    id, 0,
                    0,  0,
                    copy, 0, copy.length);
        }

        public static void afterUnwrap(SSLEngine engine, ByteBuffer dst,
                                       SSLEngineResult result) {
            if (CRASH_INJECTION) {
                throw new RuntimeException("postman-agent: synthetic crash from afterUnwrap");
            }
            if (result == null || dst == null) return;
            int produced = result.bytesProduced();
            if (produced <= 0) return;

            int endPos = dst.position();
            int startPos = endPos - produced;
            if (startPos < 0) return;

            byte[] copy = readBytes(dst, startPos, produced);
            if (copy == null || copy.length == 0) return;

            int id = System.identityHashCode(engine);
            IoctlPacket.sendThreadLocal(
                    IoctlPacket.OP_RECV,
                    id, 0,
                    0,  0,
                    copy, 0, copy.length);
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
