// SPDX-License-Identifier: Apache-2.0

package com.postman.insights.testdata;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.util.concurrent.Executors;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

import io.grpc.Server;
import io.grpc.protobuf.services.ProtoReflectionService;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import io.grpc.stub.StreamObserver;

import com.postman.insights.testdata.proto.GreeterGrpc;
import com.postman.insights.testdata.proto.HelloReply;
import com.postman.insights.testdata.proto.HelloRequest;

/**
 * Combined test workload: REST HTTPS ({@code HttpsServer}) and gRPC-TLS
 * ({@code NettyServerBuilder}) in one JVM — mirrors a real microservice with
 * multiple endpoints behind one process and one {@code -javaagent}.
 *
 * <p>TLS material under {@code /tls/} (see kind init container):</p>
 * <ul>
 *   <li>{@code hello-https-keystore.p12} — JDK HTTPS on {@code https.port}</li>
 *   <li>{@code grpc-cert.pem}, {@code grpc-key.pem} — gRPC on {@code grpc.port}</li>
 * </ul>
 */
public final class CombinedServer {

    private static final String KEYSTORE_PASS = "changeit";

    public static void main(String[] args) throws Exception {
        int httpsPort = Integer.parseInt(System.getProperty("https.port", "8443"));
        int grpcPort  = Integer.parseInt(System.getProperty("grpc.port", "8446"));
        String tlsDir = System.getProperty("tls.dir", "/tls");
        String bind   = System.getProperty("bind.host", "127.0.0.1");

        File keystore = new File(tlsDir, "hello-https-keystore.p12");
        File grpcCert = new File(tlsDir, "grpc-cert.pem");
        File grpcKey  = new File(tlsDir, "grpc-key.pem");

        if (!keystore.exists() || !grpcCert.exists() || !grpcKey.exists()) {
            throw new IllegalStateException(
                    "missing TLS files under " + tlsDir
                    + " — need hello-https-keystore.p12, grpc-cert.pem, grpc-key.pem");
        }

        HttpsServer https = startHttps(bind, httpsPort, keystore);
        Server grpc = startGrpc(bind, grpcPort, grpcCert, grpcKey);

        System.err.printf(
                "CombinedServer: HTTPS https://%s:%d/phase5b2  +  gRPC https://%s:%d (h2)%n",
                bind, httpsPort, bind, grpcPort);

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            https.stop(0);
            grpc.shutdown();
        }, "combined-shutdown"));

        grpc.awaitTermination();
    }

    private static HttpsServer startHttps(String bind, int port, File keystore) throws Exception {
        SSLContext sslCtx = buildSslContext(keystore);
        HttpsServer server = HttpsServer.create(new InetSocketAddress(bind, port), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(sslCtx));
        server.createContext("/phase5b2", new HelloHandler());
        server.createContext("/", new HelloHandler());
        server.setExecutor(Executors.newFixedThreadPool(4));
        server.start();
        return server;
    }

    private static Server startGrpc(String bind, int port, File cert, File key) throws IOException {
        Server server = NettyServerBuilder
                .forAddress(new InetSocketAddress(bind, port))
                .useTransportSecurity(cert, key)
                .addService(new GreeterImpl())
                .addService(ProtoReflectionService.newInstance())
                .build()
                .start();
        return server;
    }

    private static SSLContext buildSslContext(File keystorePath) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream in = new FileInputStream(keystorePath)) {
            ks.load(in, KEYSTORE_PASS.toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, KEYSTORE_PASS.toCharArray());
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        SSLContext sslCtx = SSLContext.getInstance("TLS");
        sslCtx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return sslCtx;
    }

    private static final class HelloHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange ex) throws IOException {
            try (InputStream in = ex.getRequestBody()) {
                byte[] buf = new byte[1024];
                while (in.read(buf) > 0) { /* drop */ }
            }
            byte[] body = ("hello-from-combined-server phase=5b2\n").getBytes();
            ex.getResponseHeaders().set("Content-Type", "text/plain");
            ex.sendResponseHeaders(200, body.length);
            try (OutputStream out = ex.getResponseBody()) {
                out.write(body);
            }
        }
    }

    static final class GreeterImpl extends GreeterGrpc.GreeterImplBase {
        @Override
        public void sayHello(HelloRequest req, StreamObserver<HelloReply> out) {
            out.onNext(HelloReply.newBuilder()
                    .setMessage("hi " + req.getName() + " from-combined-server")
                    .build());
            out.onCompleted();
        }
    }
}
