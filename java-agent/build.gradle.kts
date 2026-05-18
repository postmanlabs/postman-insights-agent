// Postman Java Agent — Gradle build (Phase 5b)
//
// Build artefact (after 5b.2):
//   build/libs/postman-java-agent.jar
//     ├── com/postman/insights/agent/**     agent + advice + IoctlPacket + NativeMemory
//     ├── net/bytebuddy/**                  shaded ByteBuddy
//     └── META-INF/native/<os>-<arch>/libpostman_jni.so   JNI shim, unpacked at runtime
//
// Manifest attributes:
//   Premain-Class:           com.postman.insights.agent.Agent
//   Can-Retransform-Classes: true
//   Main-Class:              com.postman.insights.agent.Main   (so the 5b.1 spike CLI still works)
//
// Build:
//   make -C src/main/c                            # produces libpostman_jni.so
//   gradle --no-daemon shadowJar                  # produces the shaded fat JAR
//
// Run as agent:
//   java -javaagent:build/libs/postman-java-agent.jar -cp build/libs/postman-java-agent.jar \
//        com.postman.insights.agent.testdata.HelloHttps

plugins {
    java
    application
    id("com.github.johnrengelman.shadow") version "8.1.1"
}

group = "com.postman.insights"
version = "0.5b2-SNAPSHOT"

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

repositories {
    mavenCentral()
}

dependencies {
    // ByteBuddy for the agent's class-transformation work. Shaded so it
    // can't conflict with whatever ByteBuddy version the host app uses.
    implementation("net.bytebuddy:byte-buddy:1.14.13")
    implementation("net.bytebuddy:byte-buddy-agent:1.14.13")

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

// Native-lib packaging.
//
// CI / release will build for linux-amd64 AND linux-arm64; in this dev
// container we only build whatever the host arch is.
val nativeLibDir = "src/main/c/build"
val osArch: String = run {
    val arch = System.getProperty("os.arch").lowercase()
    val normArch = when (arch) {
        "x86_64", "amd64" -> "amd64"
        "aarch64", "arm64" -> "arm64"
        else -> arch
    }
    "linux-$normArch"
}

// --------------------------------------------------------------------------
// bootstrapJar — the small subset that gets appended to the JVM's bootstrap
// class loader at premain.
//
// Contents:
//   com/postman/insights/agent/ebpf/IoctlPacket.class
//   com/postman/insights/agent/ebpf/NativeMemory.class
//   com/postman/insights/agent/instrumentations/SSLEngineInst$Hooks.class
//   META-INF/native/<arch>/libpostman_jni.so
//
// These are the only classes called at runtime from inside JDK classes
// (sun.security.ssl.SSLEngineImpl, etc.) via inlined ByteBuddy advice.
// They MUST be reachable from bootstrap (java.base in module-system terms)
// because JDK classes can't see classes in the app loader. ByteBuddy itself
// is NOT here — keeping it bootstrap-free avoids loader-constraint clashes
// between Agent.class (app-loaded) and ByteBuddy types.
// --------------------------------------------------------------------------
val bootstrapJar = tasks.register<Jar>("bootstrapJar") {
    dependsOn("classes")
    archiveBaseName.set("postman-java-agent-bootstrap")
    archiveVersion.set("")
    destinationDirectory.set(layout.buildDirectory.dir("bootstrap-libs"))

    from(layout.buildDirectory.dir("classes/java/main")) {
        // Note the trailing wildcards — nested classes like
        // NativeMemory$FinalizableBuffer and any future nested helpers
        // MUST be in the bootstrap JAR or <clinit> will fail with
        // NoClassDefFoundError.
        include("com/postman/insights/agent/ebpf/IoctlPacket*.class")
        include("com/postman/insights/agent/ebpf/NativeMemory*.class")
        include("com/postman/insights/agent/instrumentations/SSLEngineInst\$Hooks*.class")
    }
    from("$nativeLibDir/libpostman_jni.so") {
        into("META-INF/native/$osArch")
    }
}

// Stage the bootstrap JAR under a non-.jar extension so shadow's CopySpec
// treats it as an opaque binary instead of unzipping it. Agent.premain
// reads this resource and renames it back to a .jar at runtime.
val stageBootstrapAsBlob = tasks.register<Copy>("stageBootstrapAsBlob") {
    dependsOn(bootstrapJar)
    from(bootstrapJar.flatMap { it.archiveFile })
    rename { "postman-agent-bootstrap.jarblob" }
    into(layout.buildDirectory.dir("bootstrap-blob/META-INF"))
}

tasks.named<Jar>("jar") {
    enabled = false  // we ship the shadowJar instead
}

tasks.named<com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar>("shadowJar") {
    dependsOn(stageBootstrapAsBlob)
    archiveBaseName.set("postman-java-agent")
    archiveClassifier.set("")
    archiveVersion.set("")
    mergeServiceFiles()

    // Relocate ByteBuddy so it can't collide with the host app's copy.
    relocate("net.bytebuddy", "com.postman.insights.agent.shaded.bytebuddy")

    manifest {
        attributes(
            "Implementation-Title"    to "postman-java-agent",
            "Implementation-Version"  to project.version,
            "Main-Class"              to "com.postman.insights.agent.Main",
            "Premain-Class"           to "com.postman.insights.agent.Agent",
            "Can-Retransform-Classes" to "true",
            "Can-Redefine-Classes"    to "true"
        )
    }

    // (a) Embed the staged .jarblob (which IS a JAR, just renamed so shadow
    //     leaves it intact). Agent.premain extracts it and feeds it to
    //     inst.appendToBootstrapClassLoaderSearch.
    from(layout.buildDirectory.dir("bootstrap-blob"))

    // (b) Keep libpostman_jni.so directly accessible from the main JAR for
    //     the 5b.1 spike path (Main loaded by the app classloader doesn't
    //     go through the bootstrap JAR).
    from("$nativeLibDir/libpostman_jni.so") {
        into("META-INF/native/$osArch")
    }
}

tasks.named("build") {
    dependsOn("shadowJar")
}
