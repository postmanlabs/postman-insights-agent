// SPDX-License-Identifier: Apache-2.0

package com.postman.insights.testdata;

import java.io.File;
import java.util.concurrent.TimeUnit;

import io.grpc.ManagedChannel;
import io.grpc.netty.shaded.io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.netty.handler.ssl.SslContext;
import io.grpc.netty.shaded.io.netty.handler.ssl.util.InsecureTrustManagerFactory;

import com.postman.insights.testdata.proto.GreeterGrpc;
import com.postman.insights.testdata.proto.HelloRequest;
import com.postman.insights.testdata.proto.HelloReply;

/**
 * Minimal gRPC client that issues N {@code SayHello} unary RPCs against the
 * Phase 5c.2 GrpcServer on localhost:8446. Usage:
 *
 * <pre>java -cp grpc-java.jar com.postman.insights.testdata.GrpcClient [N]</pre>
 */
public final class GrpcClient {

    public static void main(String[] args) throws Exception {
        int count = args.length > 0 ? Integer.parseInt(args[0]) : 5;

        SslContext sslCtx = GrpcSslContexts.forClient()
                .trustManager(InsecureTrustManagerFactory.INSTANCE)
                .build();

        // Explicit dns:/// scheme — grpc-netty 1.62 sometimes picks 'unix' as
        // the default NameResolver, which fails on hostname:port targets.
        ManagedChannel ch = NettyChannelBuilder.forTarget("dns:///localhost:8446")
                .sslContext(sslCtx)
                .overrideAuthority("localhost")
                .build();

        GreeterGrpc.GreeterBlockingStub stub = GreeterGrpc.newBlockingStub(ch);

        for (int i = 0; i < count; i++) {
            HelloReply reply = stub.sayHello(HelloRequest.newBuilder().setName("phase5c2-" + i).build());
            System.err.println("client recv: " + reply.getMessage());
        }

        ch.shutdown().awaitTermination(5, TimeUnit.SECONDS);
    }
}
