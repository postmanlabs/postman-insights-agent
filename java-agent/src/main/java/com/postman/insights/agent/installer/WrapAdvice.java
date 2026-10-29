package com.postman.insights.agent.installer;

import java.nio.ByteBuffer;

import net.bytebuddy.asm.Advice;

import com.postman.insights.agent.bootstrap.Bridge;
import com.postman.insights.agent.bootstrap.Frame;

/**
 * Advice for the {@code SSLEngine.wrap} shapes: the plaintext the application
 * sends is what the call consumes from its sources. One class per shape,
 * because advice binds arguments by position.
 *
 * <p>Inlined code can only reference classes the instrumented class can see,
 * which for JDK classes means the bootstrap package.
 */
final class WrapAdvice {
    private WrapAdvice() {}

    /** {@code wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst)}: the abstract form every engine implements. */
    static final class Array {
        private Array() {}

        @Advice.OnMethodEnter(suppress = Throwable.class)
        static Bridge.Call enter(@Advice.Argument(0) ByteBuffer[] srcs,
                                 @Advice.Argument(1) int off,
                                 @Advice.Argument(2) int len) {
            return Bridge.enter(srcs, off, len);
        }

        @Advice.OnMethodExit(suppress = Throwable.class, onThrowable = Throwable.class)
        static void exit(@Advice.This Object engine, @Advice.Enter Bridge.Call call,
                         @Advice.Return Object result) {
            Bridge.exit(call, engine, Frame.OP_SEND, result);
        }
    }

    /**
     * {@code wrap(ByteBuffer[] srcs, int srcsOffset, int srcsLength, ByteBuffer[] dsts, int dstsOffset, int dstsLength)}:
     * not part of the SSLEngine API, but where the JDK's own engine does the work.
     */
    static final class Arrays {
        private Arrays() {}

        @Advice.OnMethodEnter(suppress = Throwable.class)
        static Bridge.Call enter(@Advice.Argument(0) ByteBuffer[] srcs,
                                 @Advice.Argument(1) int off,
                                 @Advice.Argument(2) int len) {
            return Bridge.enter(srcs, off, len);
        }

        @Advice.OnMethodExit(suppress = Throwable.class, onThrowable = Throwable.class)
        static void exit(@Advice.This Object engine, @Advice.Enter Bridge.Call call,
                         @Advice.Return Object result) {
            Bridge.exit(call, engine, Frame.OP_SEND, result);
        }
    }

    /** {@code wrap(ByteBuffer[] srcs, ByteBuffer dst)}. */
    static final class ArrayAll {
        private ArrayAll() {}

        @Advice.OnMethodEnter(suppress = Throwable.class)
        static Bridge.Call enter(@Advice.Argument(0) ByteBuffer[] srcs) {
            return Bridge.enter(srcs);
        }

        @Advice.OnMethodExit(suppress = Throwable.class, onThrowable = Throwable.class)
        static void exit(@Advice.This Object engine, @Advice.Enter Bridge.Call call,
                         @Advice.Return Object result) {
            Bridge.exit(call, engine, Frame.OP_SEND, result);
        }
    }

    /** {@code wrap(ByteBuffer src, ByteBuffer dst)}. */
    static final class Single {
        private Single() {}

        @Advice.OnMethodEnter(suppress = Throwable.class)
        static Bridge.Call enter(@Advice.Argument(0) ByteBuffer src) {
            return Bridge.enter(src);
        }

        @Advice.OnMethodExit(suppress = Throwable.class, onThrowable = Throwable.class)
        static void exit(@Advice.This Object engine, @Advice.Enter Bridge.Call call,
                         @Advice.Return Object result) {
            Bridge.exit(call, engine, Frame.OP_SEND, result);
        }
    }
}
