package com.postman.insights.agent;

import static com.postman.insights.agent.Frames.OP_RECV;
import static com.postman.insights.agent.Frames.OP_SEND;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import javax.net.ssl.SSLEngine;

import com.example.engines.DelegatingEngine;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.postman.insights.agent.Frames.Frame;

/** Every wrap and unwrap shape of the JDK's engine, and an engine that wraps another. */
class HookShapesTest {
    @BeforeEach
    void setUp() throws Exception {
        Control.enable();
    }

    private static SSLEngine jdkEngine(boolean client) throws Exception {
        SSLEngine e = client ? Tls.get().context.createSSLEngine("localhost", 443) : Tls.get().context.createSSLEngine();
        e.setUseClientMode(client);
        return e;
    }

    @Test
    void jdkEngineHeapBuffers() throws Exception {
        new ShapeChecks(new EnginePair(jdkEngine(true), jdkEngine(false)).handshake(), false).apiShapes();
    }

    @Test
    void jdkEngineDirectBuffers() throws Exception {
        new ShapeChecks(new EnginePair(jdkEngine(true), jdkEngine(false)).handshake(), true).apiShapes();
    }

    /**
     * Wrapper engines (Netty's JdkSslEngine, gRPC's SslEngineWrapper) delegate
     * to another hooked engine. Each record must still be emitted once, with
     * the wrapper's connection id.
     */
    @Test
    void wrapperEngineEmitsOnce() throws Exception {
        EnginePair p = new EnginePair(new DelegatingEngine(jdkEngine(true)), new DelegatingEngine(jdkEngine(false)))
                .handshake();
        new ShapeChecks(p, false).apiShapes();

        Frames frames = new Frames().mark();
        String request = "GET /wrapped HTTP/1.1\r\n\r\n";
        assertEquals(request, p.send(p.client, request));
        List<Frame> got = frames.traffic();
        assertEquals(1, Frames.count(got, OP_SEND, request), got.toString());
        assertEquals(1, Frames.count(got, OP_RECV, request), got.toString());
    }
}
