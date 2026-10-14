package com.postman.insights.agent.installer;

import java.nio.ByteBuffer;

import net.bytebuddy.asm.Advice;

import com.postman.insights.agent.bootstrap.Bridge;
import com.postman.insights.agent.bootstrap.Frame;

/**
 * Inlined into {@code SSLEngine.wrap(ByteBuffer[] srcs, int off, int len, ByteBuffer dst)}:
 * the plaintext the application sends is what the call consumes from srcs.
 *
 * <p>Inlined code can only reference classes the instrumented class can see,
 * which for JDK classes means the bootstrap package.
 */
final class WrapAdvice {
    private WrapAdvice() {}

    @Advice.OnMethodEnter(suppress = Throwable.class)
    static int[] enter(@Advice.Argument(0) ByteBuffer[] srcs,
                       @Advice.Argument(1) int off,
                       @Advice.Argument(2) int len) {
        return Bridge.enter(srcs, off, len);
    }

    @Advice.OnMethodExit(suppress = Throwable.class, onThrowable = Throwable.class)
    static void exit(@Advice.This Object engine,
                     @Advice.Argument(0) ByteBuffer[] srcs,
                     @Advice.Argument(1) int off,
                     @Advice.Argument(2) int len,
                     @Advice.Enter int[] pos) {
        Bridge.exit(engine, Frame.OP_SEND, srcs, off, len, pos);
    }
}
