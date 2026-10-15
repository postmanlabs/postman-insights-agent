package com.postman.insights.testapps;

import java.io.File;
import java.nio.file.Files;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.catalina.Context;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;

/** Embedded Tomcat with its NIO connector and JSSE: what Spring Boot MVC runs. */
public final class TomcatServer {
    private TomcatServer() {}

    public static void start(String keystore, String unused) throws Exception {
        Tomcat tomcat = new Tomcat();
        File base = Files.createTempDirectory("tomcat").toFile();
        tomcat.setBaseDir(base.getAbsolutePath());

        Connector https = new Connector("org.apache.coyote.http11.Http11NioProtocol");
        https.setPort(0);
        https.setProperty("address", "127.0.0.1");
        https.setSecure(true);
        https.setScheme("https");
        https.setProperty("SSLEnabled", "true");
        SSLHostConfig host = new SSLHostConfig();
        SSLHostConfigCertificate cert = new SSLHostConfigCertificate(host, SSLHostConfigCertificate.Type.RSA);
        cert.setCertificateKeystoreFile(keystore);
        cert.setCertificateKeystorePassword(new String(Main.PASSWORD));
        cert.setCertificateKeystoreType("PKCS12");
        host.addCertificate(cert);
        https.addSslHostConfig(host);
        tomcat.setConnector(https);

        Context ctx = tomcat.addContext("", base.getAbsolutePath());
        Tomcat.addServlet(ctx, "hello", new HttpServlet() {
            private static final long serialVersionUID = 1L;

            @Override
            protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws java.io.IOException {
                resp.setContentType("application/json");
                resp.setContentLength(Main.BODY.length);
                resp.getOutputStream().write(Main.BODY);
            }
        });
        ctx.addServletMappingDecoded("/hello", "hello");
        tomcat.start();
        Main.listening(https.getLocalPort());
        tomcat.getServer().await();
    }
}
