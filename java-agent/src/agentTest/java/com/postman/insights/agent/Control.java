package com.postman.insights.agent;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

/**
 * The control file the agent reads (see build.gradle.kts), standing in for
 * the Insights agent, which writes it for monitored pods.
 */
final class Control {
    static final File FILE = new File(System.getProperty("control.file"));

    private Control() {}

    /** Replaces the file atomically, as the Insights agent must. */
    static void write(String content) throws Exception {
        File tmp = new File(FILE.getParentFile(), FILE.getName() + ".tmp");
        Files.write(tmp.toPath(), content.getBytes(StandardCharsets.UTF_8));
        Files.move(tmp.toPath(), FILE.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    static void enable() throws Exception {
        write("version=1\nenabled=1\n");
    }

    static void disable() throws Exception {
        write("version=1\nenabled=0\n");
    }
}
