// Phase 5b.2 — minimal HTTPS test workload.
//
// Standalone JDK HttpsServer that exercises the SSLEngine path our agent
// instruments. No external dependencies — uses only JDK built-ins.
//
// Build:
//   cd java-agent/testdata/hello-https && gradle --no-daemon shadowJar
//   # produces build/libs/hello-https.jar
//
// Run as a Kind workload (see test/kind/java-https-workload.yaml):
//   java -javaagent:/postman/postman-java-agent.jar \
//        -Dhello.keystore=/tls/hello-https-keystore.p12 \
//        -cp /testdata/hello-https.jar \
//        com.postman.insights.testdata.HelloHttps

plugins {
    java
    id("com.github.johnrengelman.shadow") version "8.1.1"
}

group = "com.postman.insights.testdata"
version = "0.5b2-SNAPSHOT"

java { toolchain { languageVersion.set(JavaLanguageVersion.of(21)) } }

repositories { mavenCentral() }

// No external dependencies — JDK HttpsServer + SSLEngine only.

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
}

tasks.named<com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar>("shadowJar") {
    archiveBaseName.set("hello-https")
    archiveClassifier.set("")
    archiveVersion.set("")
    manifest { attributes("Main-Class" to "com.postman.insights.testdata.HelloHttps") }
}

tasks.named<Jar>("jar") { enabled = false }

tasks.named("build") { dependsOn("shadowJar") }
