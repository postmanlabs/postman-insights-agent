// Phase 5c.2 — gRPC-Java HTTPS workload.
//
// Standalone gRPC-Java server using OkHttp's gRPC channel + Netty server
// transport. TLS via JDK SSLEngine (we deliberately don't use
// netty-tcnative here to exercise the JdkSslEngine path that Spring Boot
// webflux also uses).
//
// A simple Greeter service: unary RPC SayHello(name) → message="hi name".

plugins {
    java
    application
    id("com.google.protobuf") version "0.9.4"
    id("com.github.johnrengelman.shadow") version "8.1.1"
}

group = "com.postman.insights.testdata"
version = "0.5c2-SNAPSHOT"

java { toolchain { languageVersion.set(JavaLanguageVersion.of(17)) } }

repositories { mavenCentral() }

val grpcVersion = "1.62.2"
val protobufVersion = "3.25.3"

dependencies {
    // grpc-netty-shaded bundles Netty + the DNS NameResolverProvider into
    // one artifact with relocated packages — sidesteps the SPI-merge
    // hassle when we build a fat JAR with the default Jar task.
    implementation("io.grpc:grpc-netty-shaded:$grpcVersion")
    implementation("io.grpc:grpc-protobuf:$grpcVersion")
    implementation("io.grpc:grpc-stub:$grpcVersion")
    implementation("com.google.protobuf:protobuf-java:$protobufVersion")
    implementation("javax.annotation:javax.annotation-api:1.3.2")
}

protobuf {
    protoc { artifact = "com.google.protobuf:protoc:$protobufVersion" }
    plugins {
        create("grpc") {
            artifact = "io.grpc:protoc-gen-grpc-java:$grpcVersion"
        }
    }
    generateProtoTasks {
        all().forEach { task ->
            task.plugins { create("grpc") }
        }
    }
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
}

application {
    mainClass.set("com.postman.insights.testdata.GrpcServer")
}

// Use shadow to build the fat JAR — it merges META-INF/services/ files
// correctly, which is essential for gRPC's NameResolverProvider SPI lookup.
tasks.named<com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar>("shadowJar") {
    archiveBaseName.set("grpc-java")
    archiveClassifier.set("")
    archiveVersion.set("")
    mergeServiceFiles()
    manifest { attributes("Main-Class" to "com.postman.insights.testdata.GrpcServer") }
}

tasks.named<Jar>("jar") { enabled = false }

tasks.named("build") { dependsOn("shadowJar") }
