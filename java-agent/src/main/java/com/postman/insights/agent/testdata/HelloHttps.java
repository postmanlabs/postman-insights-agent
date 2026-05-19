// SPDX-License-Identifier: Apache-2.0

package com.postman.insights.agent.testdata;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.io.File;
import java.security.KeyStore;
import java.util.concurrent.Executors;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

/**
 * Minimal HTTPS server used to validate Phase 5b.2 end-to-end.
 *
 * <p>Listens on {@code 127.0.0.1:8443} and replies with a fixed plaintext
 * body to {@code GET /phase5b2}. Uses JDK's built-in {@code HttpsServer}
 * (which sits on {@code SSLEngine} under the hood — exactly the path our
 * agent instruments).</p>
 *
 * <p>Keystore lookup order:</p>
 * <ol>
 *   <li>{@code -Dhello.keystore=/path/to/keystore.p12} system property.</li>
 *   <li>Else: {@code /tmp/hello-https-keystore.p12} (auto-generated on
 *       first run via {@code keytool}, which ships with the JDK).</li>
 * </ol>
 *
 * <p>Run as a workload:</p>
 * <pre>
 *   java -javaagent:postman-java-agent.jar \
 *        -cp postman-java-agent.jar \
 *        com.postman.insights.agent.testdata.HelloHttps
 * </pre>
 */
public final class HelloHttps {

    private static final String PORT_PROP = "hello.port";
    private static final String DEFAULT_KEYSTORE = "/tmp/hello-https-keystore.p12";
    private static final String KEYSTORE_PASS = "changeit";

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(System.getProperty(PORT_PROP, "8443"));
        String ksPath = System.getProperty("hello.keystore", DEFAULT_KEYSTORE);

        File ks = new File(ksPath);
        ensureKeystore(ks);
        SSLContext sslCtx = buildSslContext(ks);

        HttpsServer server = HttpsServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(sslCtx));
        server.createContext("/phase5b2", new HelloHandler());
        server.createContext("/", new HelloHandler());
        server.setExecutor(Executors.newFixedThreadPool(4));
        server.start();

        System.err.println("HelloHttps: listening on https://127.0.0.1:" + port + "/phase5b2");

        String durationEnv = System.getenv("HELLO_DURATION_SEC");
        if (durationEnv != null) {
            int dur = Integer.parseInt(durationEnv);
            System.err.println("HelloHttps: will stop after " + dur + " s");
            try { Thread.sleep(dur * 1000L); } catch (InterruptedException ignored) {}
            server.stop(0);
            System.err.println("HelloHttps: stopped");
            // HttpsServer's default executor uses non-daemon threads — the
            // JVM will hang here unless we force-exit. Could fix by passing
            // a daemon ThreadFactory above, but System.exit is simpler and
            // this is a test workload.
            System.exit(0);
        }
        // Otherwise run forever; user kills with SIGINT/SIGTERM.
    }

    private static class HelloHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange ex) throws IOException {
            // Drain any request body.
            try (InputStream in = ex.getRequestBody()) {
                byte[] buf = new byte[1024];
                while (in.read(buf) > 0) { /* drop */ }
            }
            byte[] body = ("hello-from-hello-https phase=5b2\n").getBytes();
            ex.getResponseHeaders().set("Content-Type", "text/plain");
            ex.sendResponseHeaders(200, body.length);
            try (OutputStream out = ex.getResponseBody()) {
                out.write(body);
            }
        }
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

    /** If the keystore doesn't exist, shell out to {@code keytool} (which
     *  ships with the JDK) to create a fresh self-signed RSA cert. */
    private static void ensureKeystore(File keystorePath) throws Exception {
        if (keystorePath.exists()) {
            return;
        }
        System.err.println("HelloHttps: generating self-signed cert at " + keystorePath);

        // keytool -genkeypair -alias hello -keyalg RSA -keysize 2048
        //   -storetype PKCS12 -keystore <ks> -storepass changeit
        //   -dname CN=localhost -validity 365
        ProcessBuilder pb = new ProcessBuilder(
                "keytool",
                "-genkeypair",
                "-alias",     "hello",
                "-keyalg",    "RSA",
                "-keysize",   "2048",
                "-storetype", "PKCS12",
                "-keystore",  keystorePath.toString(),
                "-storepass", KEYSTORE_PASS,
                "-dname",     "CN=localhost",
                "-validity",  "365");
        pb.redirectErrorStream(true);
        Process p = pb.start();
        try (InputStream in = p.getInputStream()) {
            in.transferTo(System.err);
        }
        int rc = p.waitFor();
        if (rc != 0 || !keystorePath.exists()) {
            throw new IOException("keytool exited rc=" + rc +
                    " — make sure 'keytool' is on PATH (ships with the JDK)");
        }
    }
}
