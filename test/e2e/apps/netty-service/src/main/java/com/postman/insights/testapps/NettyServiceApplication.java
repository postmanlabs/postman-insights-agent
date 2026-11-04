package com.postman.insights.testapps;

import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.KeyManagerFactory;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaderValues;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.HttpUtil;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.codec.http.QueryStringDecoder;
import io.netty.handler.ssl.OpenSsl;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslHandler;
import io.netty.handler.ssl.SslProvider;

/**
 * The same small HTTPS API as the Spring Boot service, served by plain Netty
 * through its OpenSSL (BoringSSL) engine, whose wrap and unwrap shapes differ
 * from the JDK's.
 */
public final class NettyServiceApplication {
    private static final int PORT = 8443;
    private static final Pattern ORDER = Pattern.compile("/orders/(\\d+)");
    private static final AtomicLong NEXT_ORDER = new AtomicLong(1000);

    public static void main(String[] args) throws Exception {
        if (!OpenSsl.isAvailable()) {
            throw new IllegalStateException("netty-tcnative did not load", OpenSsl.unavailabilityCause());
        }
        char[] password = "changeit".toCharArray();
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = new FileInputStream("/app/keystore.p12")) {
            store.load(in, password);
        }
        KeyManagerFactory keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(store, password);
        SslContext tls = SslContextBuilder.forServer(keys).sslProvider(SslProvider.OPENSSL).build();

        EventLoopGroup group = new MultiThreadIoEventLoopGroup(NioIoHandler.newFactory());
        try {
            new ServerBootstrap().group(group).channel(NioServerSocketChannel.class)
                    .childHandler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        protected void initChannel(SocketChannel ch) {
                            ch.pipeline().addLast(tls.newHandler(ch.alloc()), new HttpServerCodec(),
                                    new HttpObjectAggregator(1 << 20), new Api());
                        }
                    })
                    .bind(PORT).sync()
                    .channel().closeFuture().sync();
        } finally {
            group.shutdownGracefully();
        }
    }

    private static final class Api extends SimpleChannelInboundHandler<FullHttpRequest> {
        private boolean logged;

        @Override
        protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest req) {
            if (!logged) {
                System.out.println("serving HTTPS with " + ctx.pipeline().get(SslHandler.class).engine().getClass().getName());
                logged = true;
            }
            QueryStringDecoder uri = new QueryStringDecoder(req.uri());
            Matcher order = ORDER.matcher(uri.path());
            if (req.method().equals(HttpMethod.GET) && uri.path().equals("/hello")) {
                String name = uri.parameters().containsKey("name") ? uri.parameters().get("name").get(0) : "world";
                respond(ctx, req, HttpResponseStatus.OK, "{\"message\":\"hello " + name + "\"}");
            } else if (req.method().equals(HttpMethod.GET) && order.matches()) {
                respond(ctx, req, HttpResponseStatus.OK,
                        "{\"id\":" + order.group(1) + ",\"status\":\"shipped\",\"items\":3}");
            } else if (req.method().equals(HttpMethod.POST) && uri.path().equals("/orders")) {
                String body = req.content().toString(StandardCharsets.UTF_8).trim();
                String fields = body.startsWith("{") && body.length() > 2 ? body.substring(1, body.length() - 1) + "," : "";
                respond(ctx, req, HttpResponseStatus.CREATED,
                        "{" + fields + "\"id\":" + NEXT_ORDER.getAndIncrement() + ",\"status\":\"created\"}");
            } else {
                respond(ctx, req, HttpResponseStatus.NOT_FOUND, "{\"error\":\"not found\"}");
            }
        }

        private static void respond(ChannelHandlerContext ctx, FullHttpRequest req, HttpResponseStatus status,
                                    String json) {
            byte[] body = json.getBytes(StandardCharsets.UTF_8);
            FullHttpResponse resp = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, status,
                    Unpooled.wrappedBuffer(body));
            resp.headers().set(HttpHeaderNames.CONTENT_TYPE, HttpHeaderValues.APPLICATION_JSON);
            resp.headers().setInt(HttpHeaderNames.CONTENT_LENGTH, body.length);
            boolean keepAlive = HttpUtil.isKeepAlive(req);
            HttpUtil.setKeepAlive(resp, keepAlive);
            if (keepAlive) {
                ctx.writeAndFlush(resp);
            } else {
                ctx.writeAndFlush(resp).addListener(ChannelFutureListener.CLOSE);
            }
        }
    }
}
