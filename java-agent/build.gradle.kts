// Postman Java agent: hooks javax.net.ssl.SSLEngine inside a JVM and hands the
// plaintext to the Insights agent's eBPF programs (see
// ebpf/programs/java_tls.bpf.c). Built as Java 8 bytecode so it loads into
// every supported JVM (JDK 8 through 25).

plugins {
    java
}

group = "com.postman.insights"
version = (findProperty("agentVersion") as String?) ?: "0.0.0-dev"

repositories {
    mavenCentral()
}

// Tests that run a JVM with the packaged agent attached at startup, as a
// customer's -javaagent would. They see the agent only through the frames it
// writes (to a log file instead of the kernel, so they need no eBPF), so the
// agent's classes are deliberately not on their classpath.
val agentTest by sourceSets.creating

dependencies {
    implementation("net.bytebuddy:byte-buddy:1.18.15")

    for (cfg in listOf("testImplementation", "agentTestImplementation")) {
        cfg(platform("org.junit:junit-bom:5.13.4"))
        cfg("org.junit.jupiter:junit-jupiter")
        cfg("com.google.code.gson:gson:2.13.1")
    }
    for (cfg in listOf("testRuntimeOnly", "agentTestRuntimeOnly")) {
        cfg("org.junit.platform:junit-platform-launcher")
    }

    // Netty with its OpenSSL (BoringSSL) engine, whose unwrap shapes differ
    // from the JDK's. Netty 4.1 still runs on JDK 8, like the agent.
    "agentTestImplementation"(platform("io.netty:netty-bom:4.1.139.Final"))
    "agentTestImplementation"("io.netty:netty-handler")
    "agentTestImplementation"("io.netty:netty-codec-http")
    // The native library for each platform the tests run on; Gradle does
    // not follow the artifact's dependencies on its own classifiers.
    for (platform in listOf("linux-x86_64", "linux-aarch_64", "osx-x86_64", "osx-aarch_64")) {
        "agentTestRuntimeOnly"("io.netty:netty-tcnative-boringssl-static:2.0.84.Final:$platform")
    }
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(8)
    options.encoding = "UTF-8"
    // -options: compiling for Java 8 with a newer JDK warns that release 8 is
    // obsolete; that is intended. -classfile: Byte Buddy's class files refer to
    // annotations (SpotBugs) that are not on the classpath, which is harmless.
    options.compilerArgs.addAll(listOf("-Xlint:all,-options,-classfile", "-Werror"))
}

// The agent jar layout (see AgentMain for why):
//   top level      AgentMain, AgentClassLoader and the bootstrap package, the
//                  only classes the JVM's own class loaders ever load
//   inst/          everything else (installer, advice, Byte Buddy) as
//                  .classdata entries, loaded only by AgentClassLoader, so
//                  application class loaders can never see them
val topLevelClasses = listOf(
    "com/postman/insights/agent/AgentMain.class",
    "com/postman/insights/agent/AgentMain$*.class",
    "com/postman/insights/agent/AgentClassLoader.class",
    "com/postman/insights/agent/AgentClassLoader$*.class",
    "com/postman/insights/agent/bootstrap/**",
)

fun CopySpec.asClassData() {
    into("inst")
    rename("(.+)\\.class$", "$1.classdata")
}

val agentJar by tasks.registering(Jar::class) {
    description = "Builds the Java agent jar."
    group = "build"
    archiveFileName.set("postman-java-agent.jar")
    destinationDirectory.set(layout.buildDirectory.dir("agent"))
    duplicatesStrategy = DuplicatesStrategy.FAIL

    val main = sourceSets.main.get()
    from(main.output) {
        include(topLevelClasses)
    }
    from(main.output) {
        exclude(topLevelClasses)
        asClassData()
    }
    from(configurations.runtimeClasspath.map { cp -> cp.map { zipTree(it) } }) {
        // Byte Buddy's own metadata is not needed at runtime; its module
        // descriptor would make no sense under inst/. Keep its licenses.
        exclude("META-INF/MANIFEST.MF", "META-INF/maven/**", "META-INF/versions/9/module-info.class")
        exclude("META-INF/LICENSE", "META-INF/NOTICE", "META-INF/licenses/**")
        includeEmptyDirs = false
        asClassData()
    }
    from(configurations.runtimeClasspath.map { cp -> cp.map { zipTree(it) } }) {
        include("META-INF/LICENSE", "META-INF/NOTICE", "META-INF/licenses/**")
        eachFile { path = path.replaceFirst("META-INF/", "META-INF/licenses/byte-buddy/") }
        includeEmptyDirs = false
    }

    manifest {
        attributes(
            "Premain-Class" to "com.postman.insights.agent.AgentMain",
            "Agent-Class" to "com.postman.insights.agent.AgentMain",
            "Can-Retransform-Classes" to "true",
            "Can-Redefine-Classes" to "true",
            "Implementation-Title" to "Postman Insights Java agent",
            "Implementation-Version" to project.version,
        )
    }
}

tasks.assemble {
    dependsOn(agentJar)
}

tasks.test {
    useJUnitPlatform()
    // The examples shared with the Go side (ebpf/javatls).
    systemProperty("frames.vectors", file("../ebpf/javatls/testdata/frames-v1.json").absolutePath)
    systemProperty("payloads.vectors", file("../ebpf/javatls/testdata/payloads-v1.json").absolutePath)
}

val agentTestTask = tasks.register<Test>("agentTest") {
    description = "Runs tests in a JVM with the packaged agent loaded through -javaagent."
    group = "verification"
    testClassesDirs = agentTest.output.classesDirs
    classpath = agentTest.runtimeClasspath
    useJUnitPlatform()
    dependsOn(agentJar)
    val jar = agentJar.flatMap { it.archiveFile }
    val frameLog = layout.buildDirectory.file("agent-test/frames.bin")
    val controlFile = layout.buildDirectory.file("agent-test/control")
    inputs.file(jar)
    doFirst {
        val log = frameLog.get().asFile
        log.parentFile.mkdirs()
        log.delete()
        // What the Insights agent writes for a monitored pod; the agent is
        // dormant without it.
        controlFile.get().asFile.writeText("version=1\nenabled=1\n")
    }
    jvmArgumentProviders.add(CommandLineArgumentProvider {
        listOf(
            "-javaagent:${jar.get().asFile.absolutePath}=cap=4096",
            "-Dpostman.insights.agent.frameLog=${frameLog.get().asFile.absolutePath}",
            "-Dpostman.insights.agent.controlFile=${controlFile.get().asFile.absolutePath}",
        )
    })
    systemProperty("frames.log", frameLog.get().asFile.absolutePath)
    systemProperty("control.file", controlFile.get().asFile.absolutePath)
    // -PagentTestJavaHome=<JDK dir> runs these tests on another JDK (8 to 25),
    // independent of the JDK that runs Gradle.
    (findProperty("agentTestJavaHome") as String?)?.let { executable = "$it/bin/java" }
}

tasks.check {
    dependsOn(agentTestTask)
}
