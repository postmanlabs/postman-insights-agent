package com.postman.insights.agent;

import static com.postman.insights.agent.Frames.OP_RECV;
import static com.postman.insights.agent.Frames.OP_SEND;
import static com.postman.insights.agent.Frames.ROLE_KNOWN;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLEngine;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.ssl.OpenSsl;
import io.netty.handler.ssl.ReferenceCountedOpenSslEngine;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslHandler;
import io.netty.handler.ssl.SslProvider;
import io.netty.util.ReferenceCountUtil;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.postman.insights.agent.Frames.Frame;

/**
 * Netty's OpenSSL (BoringSSL) engine. Its 2-arg unwrap, which SslHandler
 * calls, and its two-array unwrap, which SslHandler calls when its input
 * spans buffers, both reach the 6-arg form, never the abstract 4-arg one;
 * with only the abstract forms hooked, requests to a Netty server were never
 * captured.
 */
class NettyOpenSslTest {
    private static final int UPLOAD_SIZE = 256 * 1024;
    private static SslContext serverContext;
    private static SslContext clientContext;

    @BeforeAll
    static void contexts() throws Exception {
        assertTrue(OpenSsl.isAvailable(), "netty-tcnative did not load: " + OpenSsl.unavailabilityCause());
        serverContext = SslContextBuilder.forServer(Tls.get().keys).sslProvider(SslProvider.OPENSSL).build();
        clientContext = SslContextBuilder.forClient().sslProvider(SslProvider.OPENSSL)
                .trustManager(Tls.get().trust).build();
    }

    @BeforeEach
    void setUp() throws Exception {
        Control.enable();
    }

    private static EnginePair openSslPair() throws Exception {
        SSLEngine client = clientContext.newEngine(ByteBufAllocator.DEFAULT, "localhost", 443);
        SSLEngine server = serverContext.newEngine(ByteBufAllocator.DEFAULT);
        assertTrue(client instanceof ReferenceCountedOpenSslEngine, client.getClass().getName());
        assertTrue(server instanceof ReferenceCountedOpenSslEngine, server.getClass().getName());
        return new EnginePair(client, server).handshake();
    }

    private static void release(EnginePair p) {
        ReferenceCountUtil.release(p.client);
        ReferenceCountUtil.release(p.server);
    }

    @Test
    void everyShapeHeapBuffers() throws Exception {
        shapes(false);
    }

    @Test
    void everyShapeDirectBuffers() throws Exception {
        shapes(true);
    }

    private static void shapes(boolean direct) throws Exception {
        EnginePair p = openSslPair();
        try {
            ShapeChecks checks = new ShapeChecks(p, direct);
            checks.apiShapes();
            // The forms Netty's SslHandler uses.
            checks.unwrap("unwrap(srcs, dsts)", (e, s, d) ->
                    ((ReferenceCountedOpenSslEngine) e).unwrap(new ByteBuffer[] {s}, d), "netty arrays");
            checks.unwrap("unwrap(srcs, soff, slen, dsts, doff, dlen)", (e, s, d) -> {
                ByteBuffer[] padded = {ByteBuffer.allocate(8), d[0]};
                ((ReferenceCountedOpenSslEngine) e).unwrap(new ByteBuffer[] {s}, 0, 1, padded, 1, 1);
            }, "netty ranges");
        } finally {
            release(p);
        }
    }

    /** Sends a request with HttpsURLConnection (an SSLSocket, which is not hooked) and returns the body. */
    private static String request(int port, String path, byte[] body) throws Exception {
        HttpsURLConnection conn = (HttpsURLConnection) new URL("https://localhost:" + port + path).openConnection();
        conn.setSSLSocketFactory(Tls.get().context.getSocketFactory());
        conn.setHostnameVerifier((host, session) -> true);
        if (body != null) {
            conn.setDoOutput(true);
            conn.setFixedLengthStreamingMode(body.length);
            try (OutputStream out = conn.getOutputStream()) {
                for (int off = 0; off < body.length; off += 1000) {
                    out.write(body, off, Math.min(1000, body.length - off));
                    out.flush();
                }
            }
        }
        assertEquals(200, conn.getResponseCode());
        try (InputStream in = conn.getInputStream()) {
            return new String(Tls.readAll(in), StandardCharsets.UTF_8);
        }
    }

    /** A real Netty HTTPS server: SslHandler, on its event loop, with the OpenSSL engine. */
    @Test
    void nettyServerRequestAndResponse() throws Exception {
        AtomicReference<String> engineClass = new AtomicReference<String>();
        EventLoopGroup group = new NioEventLoopGroup(1);
        try {
            Channel server = new ServerBootstrap().group(group).channel(NioServerSocketChannel.class)
                    .childHandler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        protected void initChannel(SocketChannel ch) {
                            SslHandler ssl = serverContext.newHandler(ch.alloc());
                            engineClass.set(ssl.engine().getClass().getName());
                            ch.pipeline().addLast(ssl, new HttpServerCodec(), new HttpObjectAggregator(1 << 20),
                                    new SimpleChannelInboundHandler<FullHttpRequest>() {
                                        @Override
                                        protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest req) {
                                            byte[] body = ("{\"netty\":\"" + req.uri() + "\",\"read\":"
                                                    + req.content().readableBytes() + "}")
                                                    .getBytes(StandardCharsets.UTF_8);
                                            FullHttpResponse resp = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1,
                                                    HttpResponseStatus.OK, Unpooled.wrappedBuffer(body));
                                            resp.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json");
                                            resp.headers().setInt(HttpHeaderNames.CONTENT_LENGTH, body.length);
                                            ctx.writeAndFlush(resp).addListener(ChannelFutureListener.CLOSE);
                                        }
                                    });
                        }
                    })
                    .bind("127.0.0.1", 0).sync().channel();
            int port = ((InetSocketAddress) server.localAddress()).getPort();

            Frames frames = new Frames().mark();
            assertEquals("{\"netty\":\"/netty?x=1\",\"read\":0}", request(port, "/netty?x=1", null));
            List<Frame> got = frames.traffic();

            // A large upload: many records, many reads.
            Frames uploadFrames = new Frames().mark();
            byte[] upload = new byte[UPLOAD_SIZE];
            Arrays.fill(upload, (byte) 'u');
            assertEquals("{\"netty\":\"/upload\",\"read\":" + UPLOAD_SIZE + "}", request(port, "/upload", upload));
            List<Frame> uploaded = uploadFrames.traffic();
            server.close().sync();

            assertTrue(engineClass.get().contains("OpenSsl"), engineClass.get());
            // The client is an SSLSocket, which is not hooked yet: only the
            // server's frames are expected.
            Frame req = Frames.findPrefix(got, OP_RECV, "GET /netty?x=1 HTTP/1.1");
            Frame resp = Frames.findPrefix(got, OP_SEND, "HTTP/1.1 200 OK");
            assertEquals(req.connId, resp.connId);
            assertEquals(ROLE_KNOWN, req.flags);
            assertEquals(1, Frames.count(got, OP_RECV, "GET /netty?x=1"), got.toString());
            assertEquals(1, Frames.count(got, OP_SEND, "{\"netty\":\"/netty?x=1\""), got.toString());

            // Every byte of the upload was seen exactly once (frames are
            // capped, but each records how much its call produced).
            long id = Frames.findPrefix(uploaded, OP_RECV, "POST /upload HTTP/1.1").connId;
            long received = 0;
            for (Frame f : uploaded) {
                if (f.op == OP_RECV && f.connId == id) {
                    received += f.totalLen;
                }
            }
            assertTrue(received > UPLOAD_SIZE && received < UPLOAD_SIZE + 1024,
                    "received " + received + " bytes for a " + UPLOAD_SIZE + "-byte upload");
        } finally {
            group.shutdownGracefully().sync();
        }
    }
}
