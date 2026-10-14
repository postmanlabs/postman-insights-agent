package com.postman.insights.agent;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Loads the agent's own classes (installer, advice, Byte Buddy) from the
 * {@code inst/} entries of the agent jar, where they are stored as
 * {@code .classdata} so no other class loader can find them.
 *
 * <p>The parent is the bootstrap class loader, so these classes see the JDK
 * and the agent's {@code bootstrap} package, and nothing of the application.
 *
 * <p>Multi-release jars: dependencies' {@code META-INF/versions/N/} entries are
 * kept under {@code inst/META-INF/versions/N/}, and the highest N not above the
 * running Java version wins, as {@link JarFile} would do for a normal jar.
 */
final class AgentClassLoader extends ClassLoader {
    static {
        registerAsParallelCapable();
    }

    private static final String PREFIX = "inst/";
    private static final String VERSIONS = "inst/META-INF/versions/";
    private static final Pattern VERSION_DIR = Pattern.compile("^inst/META-INF/versions/(\\d+)/");

    private final JarFile jar;
    private final URL base;
    /** Multi-release versions present in the jar that apply here, highest first. */
    private final List<Integer> versions;

    AgentClassLoader(File jarPath) throws IOException {
        super(null);
        this.jar = new JarFile(jarPath, false);
        this.base = new URL("jar:" + jarPath.toURI() + "!/");
        this.versions = applicableVersions(jar, javaFeatureVersion());
    }

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
        JarEntry entry = entry(name.replace('.', '/') + ".class");
        if (entry == null) {
            throw new ClassNotFoundException(name);
        }
        byte[] bytes;
        try {
            bytes = read(entry);
        } catch (IOException e) {
            throw new ClassNotFoundException(name, e);
        }
        definePackageFor(name);
        return defineClass(name, bytes, 0, bytes.length);
    }

    @Override
    protected URL findResource(String name) {
        JarEntry entry = entry(name);
        if (entry == null) {
            return null;
        }
        try {
            return new URL(base, entry.getName());
        } catch (MalformedURLException e) {
            return null;
        }
    }

    @Override
    protected Enumeration<URL> findResources(String name) {
        URL url = findResource(name);
        return url == null ? Collections.<URL>emptyEnumeration() : Collections.enumeration(Collections.singletonList(url));
    }

    /** Maps a resource name to its inst/ entry; class files are stored as .classdata. */
    private JarEntry entry(String resource) {
        String stored = resource.endsWith(".class")
                ? resource.substring(0, resource.length() - ".class".length()) + ".classdata"
                : resource;
        for (Integer v : versions) {
            JarEntry e = jar.getJarEntry(VERSIONS + v + "/" + stored);
            if (e != null) {
                return e;
            }
        }
        return jar.getJarEntry(PREFIX + stored);
    }

    private byte[] read(JarEntry entry) throws IOException {
        InputStream in = jar.getInputStream(entry);
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream(Math.max(0, (int) entry.getSize()));
            byte[] buf = new byte[8192];
            for (int n; (n = in.read(buf)) > 0; ) {
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        } finally {
            in.close();
        }
    }

    @SuppressWarnings("deprecation") // getPackage(String) is the only form on Java 8.
    private void definePackageFor(String className) {
        int dot = className.lastIndexOf('.');
        if (dot <= 0) {
            return;
        }
        String pkg = className.substring(0, dot);
        if (getPackage(pkg) == null) {
            try {
                definePackage(pkg, null, null, null, null, null, null, null);
            } catch (IllegalArgumentException alreadyDefinedConcurrently) {
                // Another thread defined it first.
            }
        }
    }

    private static List<Integer> applicableVersions(JarFile jar, int feature) {
        List<Integer> found = new ArrayList<Integer>();
        for (Enumeration<JarEntry> en = jar.entries(); en.hasMoreElements(); ) {
            Matcher m = VERSION_DIR.matcher(en.nextElement().getName());
            if (m.find()) {
                Integer v = Integer.valueOf(m.group(1));
                if (v <= feature && !found.contains(v)) {
                    found.add(v);
                }
            }
        }
        Collections.sort(found, Collections.<Integer>reverseOrder());
        return found;
    }

    /** 8 for "1.8.0_402", 21 for "21.0.8". */
    static int javaFeatureVersion() {
        String v = System.getProperty("java.specification.version", "1.8");
        if (v.startsWith("1.")) {
            v = v.substring(2);
        }
        int dot = v.indexOf('.');
        try {
            return Integer.parseInt(dot < 0 ? v : v.substring(0, dot));
        } catch (NumberFormatException e) {
            return 8;
        }
    }
}
