// Postman Java agent — JMH benchmark module.
//
// Standalone project (not a subproject of the main java-agent build) so
// JMH and its annotation processors never end up in the shipped agent
// JAR. The agent JAR is consumed as a precompiled artefact: rebuild
// it first with `cd .. && gradle shadowJar`, then run:
//
//   gradle jmh
//
// Results are printed to stdout and also written to
// build/results/jmh/results.json. The README.md alongside this file
// quotes representative numbers.

plugins {
    java
    id("me.champeau.jmh") version "0.7.2"
}

group = "com.postman.insights"
version = "0.5b2-SNAPSHOT"

repositories {
    mavenCentral()
}

// We don't pin a toolchain version — the JVM that runs JMH is whatever
// JAVA_HOME points at when `gradle jmh` is invoked. Bytecode level
// matches the agent's (JDK 8) so the JMH harness can call into the
// shaded agent on any JDK from 8 up.
java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

dependencies {
    // Pull in the shaded agent JAR built by the parent project. JMH
    // benchmarks reference the agent's internal `Hooks.afterWrap` etc.
    // through the SHADED package names so we measure the bytecode
    // operators actually execute at runtime.
    jmh(files("../build/libs/postman-java-agent.jar"))
}

jmh {
    warmupIterations.set(3)
    iterations.set(5)
    fork.set(2)
    benchmarkMode.set(listOf("avgt"))         // average time per op
    timeOnIteration.set("3s")
    warmup.set("2s")
    timeUnit.set("ns")
    failOnError.set(true)
    includes.set(listOf("Postman.*"))         // only our benchmarks
    // Useful when iterating locally: comment in to skip a specific class.
    // excludes.set(listOf("Postman.*Slow.*"))
    jvmArgsAppend.set(listOf(
        "--add-opens=java.base/sun.misc=ALL-UNNAMED",
        "--add-opens=java.base/java.nio=ALL-UNNAMED",
    ))
}
