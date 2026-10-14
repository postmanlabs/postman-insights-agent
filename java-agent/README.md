# Postman Java agent

A Java agent that captures decrypted HTTPS traffic from inside a JVM, for the Postman Insights Agent.

It hooks every `javax.net.ssl.SSLEngine` implementation (the JDK's, Netty's, and others) and hands the plaintext of each `wrap` and `unwrap` call to the kernel as a frame: a positional write to `/dev/null` at a magic offset.
The Insights Agent's eBPF programs (`ebpf/programs/java_tls.bpf.c`) read the frame on syscall entry and feed it into the same pipeline as the libssl uprobes.
The bridge to the kernel is pure Java (no JNI, no `Unsafe`), and the agent runs on JDK 8 through 25.

## Contract with the Insights Agent

The frame format and the names both sides use are defined three times, and tests keep the copies in sync:

| Copy | Location |
|---|---|
| Kernel | `ebpf/programs/java_frame.h` |
| Go | `ebpf/javatls/` (`frame.go`, `contract.go`) |
| Java | `src/main/java/com/postman/insights/agent/bootstrap/` (`Frame.java`, `Contract.java`) |

The example frames in `ebpf/javatls/testdata/frames-v1.json` are checked by both the Go tests and `FrameTest`.
A format change updates all three copies and the examples together, and adds a frame version rather than changing an existing one: an agent loaded into a JVM cannot be unloaded, so the Insights Agent must keep reading older frames.

## Jar layout and class loading

See `AgentMain` and the `agentJar` task in `build.gradle.kts`.
In short, the JVM's own class loaders only ever see `AgentMain`, `AgentClassLoader` and the `bootstrap` package; the installer, the advice and Byte Buddy live under `inst/` as `.classdata` entries and are loaded by `AgentClassLoader`.
Applications therefore never see the agent's Byte Buddy, and the agent never sees theirs.

## Building and testing

Requires JDK 17 or newer to run Gradle; the output is Java 8 bytecode.

```sh
./gradlew agentJar   # build/agent/postman-java-agent.jar
./gradlew check      # unit tests, then tests in a JVM started with -javaagent
```

The `-javaagent` tests (`src/agentTest`) run against the packaged jar and check the frames it writes for real TLS traffic.
They write frames to a file instead of the kernel (the `postman.insights.agent.frameLog` system property, for tests only), so they need no eBPF.
To run them on another JDK:

```sh
./gradlew agentTest -PagentTestJavaHome=/path/to/jdk8
```

Without a local JDK, run Gradle in Docker:

```sh
docker run --rm -v "$PWD/..:/w" -w /w/java-agent eclipse-temurin:21-jdk ./gradlew --no-daemon check
```

For an end-to-end check with the eBPF agent in kind, see `test/kind/deploy-java-service.sh`.

## Status

Java HTTPS capture is experimental.
The Insights Agent loads the eBPF side only when `POSTMAN_INSIGHTS_EXPERIMENTAL_JAVA_TLS=true` is set; the agent itself is loaded with `-javaagent` for now.
Dynamic attach from the DaemonSet and `--https-libraries` are planned (INS-365).
