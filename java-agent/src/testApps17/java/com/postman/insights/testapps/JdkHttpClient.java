package com.postman.insights.testapps;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * The JDK's HttpClient (java.net.http), over SSLEngine: a request to url every
 * 200 ms. Run with -Djdk.internal.httpclient.disableHostnameVerification=true,
 * since the test certificate does not name the server's address.
 */
public final class JdkHttpClient {
    private JdkHttpClient() {}

    public static void start(String unused, String url) throws Exception {
        HttpClient client = HttpClient.newBuilder()
                .sslContext(Main.trustAll())
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(5))
                .build();
        System.out.println("client started");
        System.out.flush();
        for (;;) {
            try {
                client.send(HttpRequest.newBuilder(URI.create(url)).GET().build(),
                        HttpResponse.BodyHandlers.ofString());
            } catch (Exception e) {
                System.out.println("client error " + e);
            }
            Thread.sleep(200);
        }
    }
}
