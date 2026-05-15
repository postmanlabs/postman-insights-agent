// Postman Java Agent — Gradle build (Phase 5b)
//
// What this build produces today (5b.1 spike scope):
//   build/libs/postman-java-agent.jar           — JAR with Main + JNI loader
//   src/main/c/build/libpostman_jni.so          — JNI native library
//                                                  (built by `make -C src/main/c`,
//                                                  NOT by Gradle — see Makefile.jni)
//
// In 5b.2 we'll fold the native build into Gradle and pack the .so into
// META-INF/native/<os>-<arch>/libpostman_jni.so so the JAR is single-
// artefact. For now, run with:
//
//   make -C src/main/c
//   java -Djava.library.path=src/main/c/build -jar build/libs/postman-java-agent.jar SEND
//
// or with -Dpostman.agent.native.lib=/abs/path/to/libpostman_jni.so.

plugins {
    java
    application
}

group = "com.postman.insights"
version = "0.5b1-SNAPSHOT"

java {
    // Phase 5b targets JDK 17; broader compat (8/11/21) is a 5c concern.
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

repositories {
    mavenCentral()
}

dependencies {
    // No runtime deps for 5b.1 — pure JDK + JNI. ByteBuddy lands in 5b.2.
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
}

application {
    mainClass.set("com.postman.insights.agent.Main")
}

tasks.test {
    useJUnitPlatform()
}

// Default platform encoding on minimal Linux containers is US-ASCII, which
// rejects em-dashes etc. in source comments. Force UTF-8 for all javac runs.
tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
}

// Single-artefact JAR. Real shading (relocating ByteBuddy etc.) comes in 5b.2.
tasks.jar {
    manifest {
        attributes(
            "Implementation-Title" to "postman-java-agent",
            "Implementation-Version" to project.version,
            "Main-Class" to "com.postman.insights.agent.Main"
        )
    }
    archiveBaseName.set("postman-java-agent")
    // Drop the version suffix so downstream scripts don't have to track it.
    archiveVersion.set("")
}
