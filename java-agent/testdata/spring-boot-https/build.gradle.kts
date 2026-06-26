// Phase 5c.1 — Spring Boot HTTPS workload for validating the Java agent
// against a real enterprise framework (webflux/Netty path).
//
// Standalone Gradle build — independent of the agent JAR's build. Run
// with `gradle bootJar` and you get build/libs/spring-boot-https.jar
// that launches a Spring Boot 3.2 webflux app on https://127.0.0.1:8443.
//
// Then attach the agent:
//   java -javaagent:postman-java-agent.jar -jar spring-boot-https.jar

plugins {
    java
    id("org.springframework.boot") version "3.5.14"
    id("io.spring.dependency-management") version "1.1.7"
}

group = "com.postman.insights.testdata"
version = "0.5c1-SNAPSHOT"

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

repositories {
    mavenCentral()
}

dependencies {
    // webflux explicitly — Netty I/O path, not Tomcat (Tomcat is 5c.2's job).
    implementation("org.springframework.boot:spring-boot-starter-webflux")
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
}

tasks.named<org.springframework.boot.gradle.tasks.bundling.BootJar>("bootJar") {
    archiveBaseName.set("spring-boot-https")
    archiveVersion.set("")
}
