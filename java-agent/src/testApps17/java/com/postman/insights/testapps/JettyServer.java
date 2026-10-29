package com.postman.insights.testapps;

import java.nio.ByteBuffer;

import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.util.Callback;
import org.eclipse.jetty.util.ssl.SslContextFactory;

/** Jetty 12 with its SslConnection over JSSE. */
public final class JettyServer {
    private JettyServer() {}

    public static void start(String keystore, String unused) throws Exception {
        Server server = new Server();
        SslContextFactory.Server ssl = new SslContextFactory.Server();
        ssl.setKeyStorePath(keystore);
        ssl.setKeyStorePassword(new String(Main.PASSWORD));
        ssl.setKeyStoreType("PKCS12");
        // The test certificate is for CN=localhost; clients connect to 127.0.0.1.
        ssl.setSniRequired(false);
        HttpConfiguration config = new HttpConfiguration();
        SecureRequestCustomizer secure = new SecureRequestCustomizer();
        secure.setSniHostCheck(false);
        config.addCustomizer(secure);
        ServerConnector connector = new ServerConnector(server,
                new SslConnectionFactory(ssl, "http/1.1"), new HttpConnectionFactory(config));
        connector.setHost("127.0.0.1");
        connector.setPort(0);
        server.addConnector(connector);
        server.setHandler(new Handler.Abstract() {
            @Override
            public boolean handle(Request request, Response response, Callback callback) {
                response.getHeaders().put(HttpHeader.CONTENT_TYPE, "application/json");
                response.getHeaders().put(HttpHeader.CONTENT_LENGTH, Main.BODY.length);
                response.write(true, ByteBuffer.wrap(Main.BODY), callback);
                return true;
            }
        });
        server.start();
        Main.listening(connector.getLocalPort());
        server.join();
    }
}
