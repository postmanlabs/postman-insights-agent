package com.postman.insights.agent.installer;

import java.nio.ByteBuffer;

import net.bytebuddy.asm.Advice;

import com.postman.insights.agent.bootstrap.Bridge;
import com.postman.insights.agent.bootstrap.Frame;

/**
 * Advice for the {@code SSLEngine.unwrap} shapes: the plaintext the
 * application receives is what the call produces into its destinations. One
 * class per shape, because advice binds arguments by position.
 */
final class UnwrapAdvice {
    private UnwrapAdvice() {}

    /** {@code unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length)}: the abstract form every engine implements. */
    static final class Array {
        private Array() {}

        @Advice.OnMethodEnter(suppress = Throwable.class)
        static Bridge.Call enter(@Advice.Argument(1) ByteBuffer[] dsts,
                                 @Advice.Argument(2) int off,
                                 @Advice.Argument(3) int len) {
            return Bridge.enter(dsts, off, len);
        }

        @Advice.OnMethodExit(suppress = Throwable.class, onThrowable = Throwable.class)
        static void exit(@Advice.This Object engine, @Advice.Enter Bridge.Call call,
                         @Advice.Return Object result) {
            Bridge.exit(call, engine, Frame.OP_RECV, result);
        }
    }

    /** {@code unwrap(ByteBuffer src, ByteBuffer[] dsts)}. */
    static final class ArrayAll {
        private ArrayAll() {}

        @Advice.OnMethodEnter(suppress = Throwable.class)
        static Bridge.Call enter(@Advice.Argument(1) ByteBuffer[] dsts) {
            return Bridge.enter(dsts);
        }

        @Advice.OnMethodExit(suppress = Throwable.class, onThrowable = Throwable.class)
        static void exit(@Advice.This Object engine, @Advice.Enter Bridge.Call call,
                         @Advice.Return Object result) {
            Bridge.exit(call, engine, Frame.OP_RECV, result);
        }
    }

    /** {@code unwrap(ByteBuffer src, ByteBuffer dst)}. */
    static final class Single {
        private Single() {}

        @Advice.OnMethodEnter(suppress = Throwable.class)
        static Bridge.Call enter(@Advice.Argument(1) ByteBuffer dst) {
            return Bridge.enter(dst);
        }

        @Advice.OnMethodExit(suppress = Throwable.class, onThrowable = Throwable.class)
        static void exit(@Advice.This Object engine, @Advice.Enter Bridge.Call call,
                         @Advice.Return Object result) {
            Bridge.exit(call, engine, Frame.OP_RECV, result);
        }
    }

    /**
     * {@code unwrap(ByteBuffer[] srcs, int srcsOffset, int srcsLength, ByteBuffer[] dsts, int dstsOffset, int dstsLength)}:
     * not part of the SSLEngine API, but where Netty's OpenSSL engine and the
     * JDK's own engine do the work. Netty's SslHandler calls the two-array
     * form, which reaches only this one, never the abstract 4-arg form.
     */
    static final class Arrays {
        private Arrays() {}

        @Advice.OnMethodEnter(suppress = Throwable.class)
        static Bridge.Call enter(@Advice.Argument(3) ByteBuffer[] dsts,
                                 @Advice.Argument(4) int off,
                                 @Advice.Argument(5) int len) {
            return Bridge.enter(dsts, off, len);
        }

        @Advice.OnMethodExit(suppress = Throwable.class, onThrowable = Throwable.class)
        static void exit(@Advice.This Object engine, @Advice.Enter Bridge.Call call,
                         @Advice.Return Object result) {
            Bridge.exit(call, engine, Frame.OP_RECV, result);
        }
    }

    /** {@code unwrap(ByteBuffer[] srcs, ByteBuffer[] dsts)}: Netty's OpenSSL engine. */
    static final class ArraysAll {
        private ArraysAll() {}

        @Advice.OnMethodEnter(suppress = Throwable.class)
        static Bridge.Call enter(@Advice.Argument(1) ByteBuffer[] dsts) {
            return Bridge.enter(dsts);
        }

        @Advice.OnMethodExit(suppress = Throwable.class, onThrowable = Throwable.class)
        static void exit(@Advice.This Object engine, @Advice.Enter Bridge.Call call,
                         @Advice.Return Object result) {
            Bridge.exit(call, engine, Frame.OP_RECV, result);
        }
    }
}
