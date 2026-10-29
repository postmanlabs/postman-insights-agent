package com.postman.insights.testapps;

import java.net.InetSocketAddress;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.epoll.EpollEventLoopGroup;
import io.netty.channel.epoll.EpollServerSocketChannel;
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
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;

import javax.net.ssl.KeyManagerFactory;

/**
 * Netty's HTTPS server, on the JDK's SSLEngine or on Netty's OpenSSL
 * (BoringSSL) engine, with the NIO transport or the native epoll one (which
 * Reactor Netty uses on Linux when it is available): the stack under Reactor
 * Netty (Spring WebFlux), Micronaut, Vert.x and Quarkus.
 */
final class NettyServer {
    private NettyServer() {}

    static void start(String keystore, boolean openssl, boolean epoll) throws Exception {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(Main.keyStore(keystore), Main.PASSWORD);
        SslContext ssl = SslContextBuilder.forServer(kmf)
                .sslProvider(openssl ? SslProvider.OPENSSL : SslProvider.JDK)
                .build();
        ServerBootstrap b = new ServerBootstrap();
        if (epoll) {
            b.group(new EpollEventLoopGroup(1), new EpollEventLoopGroup(2)).channel(EpollServerSocketChannel.class);
        } else {
            b.group(new NioEventLoopGroup(1), new NioEventLoopGroup(2)).channel(NioServerSocketChannel.class);
        }
        b.childHandler(new ChannelInitializer<SocketChannel>() {
            @Override
            protected void initChannel(SocketChannel ch) {
                ch.pipeline().addLast(ssl.newHandler(ch.alloc()), new HttpServerCodec(),
                        new HttpObjectAggregator(1 << 16), new Hello());
            }
        });
        Channel ch = b.bind("127.0.0.1", 0).sync().channel();
        Main.listening(((InetSocketAddress) ch.localAddress()).getPort());
        ch.closeFuture().sync();
    }

    private static final class Hello extends SimpleChannelInboundHandler<FullHttpRequest> {
        @Override
        protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest req) {
            FullHttpResponse resp = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK,
                    Unpooled.wrappedBuffer(Main.BODY));
            resp.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json");
            resp.headers().setInt(HttpHeaderNames.CONTENT_LENGTH, Main.BODY.length);
            ctx.writeAndFlush(resp);
        }
    }
}
