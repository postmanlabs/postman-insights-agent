package com.postman.insights.testapps;

import java.io.FileInputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * HTTPS servers and clients on the frameworks the Java agent must capture,
 * for the Insights agent's real-JVM tests (ebpf/node_collector_jvm_linux_test.go).
 *
 * <pre>
 * java -cp 'test-apps/*' com.postman.insights.testapps.Main &lt;app&gt; &lt;keystore.p12&gt; [url]
 * </pre>
 *
 * A server serves {@code GET /hello} with {@code {"hello":"jvm"}} on an
 * ephemeral port on 127.0.0.1 and prints {@code listening <port>}. A client
 * prints {@code client started} and requests url?n=0, url?n=1, ... every 200
 * ms, trusting any certificate. The keystore's password is {@code changeit}.
 *
 * <p>Compiled for Java 8, so the apps that run on JDK 8 (Netty) start there;
 * the others (Java 11 or 17 frameworks) are in a separate source set and
 * loaded by name only when asked for.
 */
public final class Main {
    private Main() {}

    static final byte[] BODY = "{\"hello\":\"jvm\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    static final char[] PASSWORD = "changeit".toCharArray();

    public static void main(String[] args) throws Exception {
        String app = args[0];
        String keystore = args[1];
        String url = args.length > 2 ? args[2] : null;
        switch (app) {
            case "netty-jdk":
                NettyServer.start(keystore, false, false);
                break;
            case "netty-openssl":
                NettyServer.start(keystore, true, false);
                break;
            case "netty-epoll":
                NettyServer.start(keystore, false, true);
                break;
            default:
                // A Java 11+ app: TomcatServer, JettyServer, UndertowServer, JdkHttpClient.
                Class<?> c = Class.forName("com.postman.insights.testapps." + className(app));
                Method m = c.getMethod("start", String.class, String.class);
                m.invoke(null, keystore, url);
        }
    }

    private static String className(String app) {
        switch (app) {
            case "tomcat":
                return "TomcatServer";
            case "jetty":
                return "JettyServer";
            case "undertow":
                return "UndertowServer";
            case "jdk-httpclient":
                return "JdkHttpClient";
            default:
                throw new IllegalArgumentException("unknown app " + app);
        }
    }

    /** The keystore, for frameworks that take one. */
    public static KeyStore keyStore(String path) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = new FileInputStream(path)) {
            ks.load(in, PASSWORD);
        }
        return ks;
    }

    /** A server context from the keystore. */
    public static SSLContext serverContext(String keystore) throws Exception {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore(keystore), PASSWORD);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, null);
        return ctx;
    }

    /** A client context that trusts any certificate. */
    public static SSLContext trustAll() throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, new TrustManager[] {new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) {}

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) {}

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        }}, null);
        return ctx;
    }

    public static void listening(int port) {
        System.out.println("listening " + port);
        System.out.flush();
    }
}
