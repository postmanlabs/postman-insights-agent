// Phase 5c.2 — Tomcat HTTPS workload. Same shape as spring-boot-https
// but explicitly forces the Tomcat connector (default servlet stack)
// instead of webflux/Netty.
//
// Empirical question this workload answers: does the JDK's
// sun.security.ssl.SSLSocketImpl internally drive SSLEngine such that
// our existing SSLEngineInst already captures Tomcat? If yes → no new
// advice needed. If no → we need SSLSocketInst.

plugins {
    java
    id("org.springframework.boot") version "3.2.5"
    id("io.spring.dependency-management") version "1.1.4"
}

group = "com.postman.insights.testdata"
version = "0.5c2-SNAPSHOT"

java {
    toolchain { languageVersion.set(JavaLanguageVersion.of(17)) }
}

repositories { mavenCentral() }

dependencies {
    // -starter-web brings in Tomcat by default. Explicit and unambiguous.
    implementation("org.springframework.boot:spring-boot-starter-web")
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
}

tasks.named<org.springframework.boot.gradle.tasks.bundling.BootJar>("bootJar") {
    archiveBaseName.set("tomcat-https")
    archiveVersion.set("")
}
