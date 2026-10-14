package com.postman.insights.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/** A self-signed localhost certificate, made with the running JDK's keytool. */
final class Tls {
    private static Tls instance;

    final KeyManagerFactory keys;
    final TrustManagerFactory trust;
    final SSLContext context;

    private Tls() throws Exception {
        File dir = Files.createTempDirectory("agent-test-tls").toFile();
        File ks = new File(dir, "test.p12");
        ks.deleteOnExit();
        dir.deleteOnExit();
        char[] pw = "changeit".toCharArray();
        String keytool = new File(System.getProperty("java.home"), "bin/keytool").getAbsolutePath();
        Process p = new ProcessBuilder(keytool, "-genkeypair", "-alias", "test", "-keyalg", "RSA", "-keysize", "2048",
                "-dname", "CN=localhost", "-ext", "SAN=dns:localhost,ip:127.0.0.1", "-validity", "2",
                "-storetype", "PKCS12", "-keystore", ks.getAbsolutePath(), "-storepass", "changeit")
                .redirectErrorStream(true).start();
        String output = new String(readAll(p.getInputStream()), StandardCharsets.UTF_8);
        assertEquals(0, p.waitFor(), "keytool failed: " + output);

        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = new FileInputStream(ks)) {
            store.load(in, pw);
        }
        keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(store, pw);
        trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trust.init(store);
        context = SSLContext.getInstance("TLS");
        context.init(keys.getKeyManagers(), trust.getTrustManagers(), null);
    }

    static synchronized Tls get() throws Exception {
        if (instance == null) {
            instance = new Tls();
        }
        return instance;
    }

    static byte[] readAll(InputStream in) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        for (int n; (n = in.read(buf)) > 0; ) {
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }
}
