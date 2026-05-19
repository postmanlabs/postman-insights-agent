// SPDX-License-Identifier: Apache-2.0

package com.postman.insights.testdata;

import java.io.File;

import io.grpc.Server;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import io.grpc.stub.StreamObserver;

import com.postman.insights.testdata.proto.GreeterGrpc;
import com.postman.insights.testdata.proto.HelloReply;
import com.postman.insights.testdata.proto.HelloRequest;

/**
 * Phase 5c.2 — gRPC-Java HTTPS workload. Netty server transport, TLS via
 * the JDK's pure-Java SSLEngine (no netty-tcnative). Exercises both
 * unary (no streaming for now) and ALPN-negotiated h2.
 *
 * <p>Cert + key files in PEM format expected at {@code /tmp/grpc-cert.pem}
 * and {@code /tmp/grpc-key.pem}; the {@code gen-cert.sh} script in this
 * directory generates them via openssl.</p>
 */
public final class GrpcServer {

    public static void main(String[] args) throws Exception {
        File cert = new File("/tmp/grpc-cert.pem");
        File key  = new File("/tmp/grpc-key.pem");
        if (!cert.exists() || !key.exists()) {
            throw new IllegalStateException(
                    "missing /tmp/grpc-cert.pem or /tmp/grpc-key.pem — run gen-cert.sh first");
        }

        Server server = NettyServerBuilder
                .forPort(8446)
                .useTransportSecurity(cert, key)
                .addService(new GreeterImpl())
                .build()
                .start();

        System.err.println("gRPC server listening on https://localhost:8446 (h2)");
        server.awaitTermination();
    }

    static final class GreeterImpl extends GreeterGrpc.GreeterImplBase {
        @Override
        public void sayHello(HelloRequest req, StreamObserver<HelloReply> out) {
            out.onNext(HelloReply.newBuilder().setMessage("hi " + req.getName()).build());
            out.onCompleted();
        }
    }
}
