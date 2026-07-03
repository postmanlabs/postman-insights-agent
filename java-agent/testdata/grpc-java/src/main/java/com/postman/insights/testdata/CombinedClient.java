// SPDX-License-Identifier: Apache-2.0

package com.postman.insights.testdata;

import java.io.File;
import java.io.FileInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import io.grpc.ManagedChannel;
import io.grpc.netty.shaded.io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.netty.handler.ssl.SslContext;

import com.postman.insights.testdata.proto.GreeterGrpc;
import com.postman.insights.testdata.proto.HelloReply;
import com.postman.insights.testdata.proto.HelloRequest;

/**
 * Combined test client: one HTTPS GET and N gRPC {@code SayHello} RPCs against
 * {@link CombinedServer}. Uses the trust PEM from the kind init container
 * (certificate verification, no {@code -k} / insecure trust).
 *
 * <pre>java -cp grpc-java.jar:postman-java-agent.jar \
 *      com.postman.insights.testdata.CombinedClient [grpcCount]</pre>
 */
public final class CombinedClient {

    public static void main(String[] args) throws Exception {
        int grpcCount = args.length > 0 ? Integer.parseInt(args[0]) : 3;
        String tlsDir = System.getProperty("tls.dir", "/tls");
        String host   = System.getProperty("bind.host", "127.0.0.1");
        int httpsPort = Integer.parseInt(System.getProperty("https.port", "8443"));
        int grpcPort  = Integer.parseInt(System.getProperty("grpc.port", "8446"));

        File trustPem = new File(tlsDir, "hello-https-trust.pem");
        if (!trustPem.exists()) {
            throw new IllegalStateException("missing trust PEM: " + trustPem);
        }

        SSLContext sslCtx = trustContextFromPem(trustPem);

        runHttpsGet(sslCtx, host, httpsPort);
        runGrpcCalls(trustPem, grpcPort, grpcCount);
    }

    private static void runHttpsGet(SSLContext sslCtx, String host, int port) throws Exception {
        HttpClient client = HttpClient.newBuilder()
                .sslContext(sslCtx)
                .build();
        URI uri = URI.create("https://" + host + ":" + port + "/phase5b2");
        HttpRequest req = HttpRequest.newBuilder(uri).GET().build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        System.err.printf("https GET %s → status=%d body=%s%n",
                uri, resp.statusCode(), resp.body().strip());
    }

    private static void runGrpcCalls(File trustPem, int grpcPort, int count) throws Exception {
        SslContext nettySsl = GrpcSslContexts.forClient()
                .trustManager(trustPem)
                .build();

        ManagedChannel ch = NettyChannelBuilder
                .forTarget("dns:///127.0.0.1:" + grpcPort)
                .sslContext(nettySsl)
                .overrideAuthority("localhost")
                .build();

        GreeterGrpc.GreeterBlockingStub stub = GreeterGrpc.newBlockingStub(ch);
        try {
            for (int i = 0; i < count; i++) {
                HelloReply reply = stub.sayHello(
                        HelloRequest.newBuilder().setName("combined-" + i).build());
                System.err.println("grpc SayHello → " + reply.getMessage());
            }
        } finally {
            ch.shutdown().awaitTermination(5, TimeUnit.SECONDS);
        }
    }

    /** Build an {@link SSLContext} that trusts exactly the self-signed PEM. */
    private static SSLContext trustContextFromPem(File pem) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate cert;
        try (FileInputStream in = new FileInputStream(pem)) {
            cert = cf.generateCertificate(in);
        }
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        ks.setCertificateEntry("hello", cert);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tmf.getTrustManagers(), null);
        return ctx;
    }
}
