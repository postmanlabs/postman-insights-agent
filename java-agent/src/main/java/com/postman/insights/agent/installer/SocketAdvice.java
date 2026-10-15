package com.postman.insights.agent.installer;

import net.bytebuddy.asm.Advice;

import com.postman.insights.agent.bootstrap.Bridge;
import com.postman.insights.agent.bootstrap.Frame;

/**
 * Advice for the JDK's blocking {@code SSLSocket} ({@code sun.security.ssl.SSLSocketImpl},
 * JDK 8u261 and newer), which does not use an {@code SSLEngine}: its
 * application streams' reads and writes carry the plaintext, and the socket
 * is the connection, whose addresses the agent takes from it; {@code close}
 * is hooked for the CLOSE frame. Blocking clients use it:
 * {@code HttpsURLConnection}, Apache HttpClient's classic API, OkHttp.
 *
 * <p>The streams are inner classes; {@code this$0} is their socket. Their
 * one-byte {@code read()} and {@code write(int)} delegate to the array forms
 * hooked here.
 */
final class SocketAdvice {
    private SocketAdvice() {}

    static final String SOCKET = "sun.security.ssl.SSLSocketImpl";
    static final String INPUT = SOCKET + "$AppInputStream";
    static final String OUTPUT = SOCKET + "$AppOutputStream";

    /** {@code AppInputStream.read(byte[] b, int off, int len)}: returns the bytes read, or -1 at the end. */
    static final class Read {
        private Read() {}

        @Advice.OnMethodEnter(suppress = Throwable.class)
        static Bridge.Call enter() {
            return Bridge.enterStream();
        }

        @Advice.OnMethodExit(suppress = Throwable.class, onThrowable = Throwable.class)
        static void exit(@Advice.FieldValue("this$0") Object socket, @Advice.Enter Bridge.Call call,
                         @Advice.Argument(0) byte[] b, @Advice.Argument(1) int off,
                         @Advice.Return int n, @Advice.Thrown Throwable thrown) {
            Bridge.exitStream(call, socket, Frame.OP_RECV, b, off, thrown == null ? n : 0);
        }
    }

    /** {@code AppOutputStream.write(byte[] b, int off, int len)}: returns once all len bytes are sent. */
    static final class Write {
        private Write() {}

        @Advice.OnMethodEnter(suppress = Throwable.class)
        static Bridge.Call enter() {
            return Bridge.enterStream();
        }

        @Advice.OnMethodExit(suppress = Throwable.class, onThrowable = Throwable.class)
        static void exit(@Advice.FieldValue("this$0") Object socket, @Advice.Enter Bridge.Call call,
                         @Advice.Argument(0) byte[] b, @Advice.Argument(1) int off,
                         @Advice.Argument(2) int len, @Advice.Thrown Throwable thrown) {
            Bridge.exitStream(call, socket, Frame.OP_SEND, b, off, thrown == null ? len : 0);
        }
    }

    /** {@code SSLSocketImpl.close()}. */
    static final class Close {
        private Close() {}

        @Advice.OnMethodExit(suppress = Throwable.class, onThrowable = Throwable.class)
        static void exit(@Advice.This Object socket) {
            Bridge.socketClosed(socket);
        }
    }
}
