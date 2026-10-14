package com.postman.insights.agent.installer;

import java.nio.ByteBuffer;

import net.bytebuddy.asm.Advice;

import com.postman.insights.agent.bootstrap.Bridge;
import com.postman.insights.agent.bootstrap.Frame;

/**
 * Inlined into {@code SSLEngine.unwrap(ByteBuffer src, ByteBuffer[] dsts, int off, int len)}:
 * the plaintext the application receives is what the call produces into dsts.
 */
final class UnwrapAdvice {
    private UnwrapAdvice() {}

    @Advice.OnMethodEnter(suppress = Throwable.class)
    static int[] enter(@Advice.Argument(1) ByteBuffer[] dsts,
                       @Advice.Argument(2) int off,
                       @Advice.Argument(3) int len) {
        return Bridge.enter(dsts, off, len);
    }

    @Advice.OnMethodExit(suppress = Throwable.class, onThrowable = Throwable.class)
    static void exit(@Advice.This Object engine,
                     @Advice.Argument(1) ByteBuffer[] dsts,
                     @Advice.Argument(2) int off,
                     @Advice.Argument(3) int len,
                     @Advice.Enter int[] pos) {
        Bridge.exit(engine, Frame.OP_RECV, dsts, off, len, pos);
    }
}
