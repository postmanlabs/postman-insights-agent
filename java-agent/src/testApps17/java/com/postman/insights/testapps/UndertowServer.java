package com.postman.insights.testapps;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

import io.undertow.Undertow;
import io.undertow.util.Headers;

/** Undertow, on XNIO's SSL conduit over JSSE: WildFly's and Quarkus's classic HTTP layer. */
public final class UndertowServer {
    private UndertowServer() {}

    public static void start(String keystore, String unused) throws Exception {
        Undertow server = Undertow.builder()
                .addHttpsListener(0, "127.0.0.1", Main.serverContext(keystore))
                .setHandler(exchange -> {
                    exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "application/json");
                    exchange.getResponseHeaders().put(Headers.CONTENT_LENGTH, Main.BODY.length);
                    exchange.getResponseSender().send(ByteBuffer.wrap(Main.BODY));
                })
                .build();
        server.start();
        InetSocketAddress addr = (InetSocketAddress) server.getListenerInfo().get(0).getAddress();
        Main.listening(addr.getPort());
        Thread.currentThread().join();
    }
}
