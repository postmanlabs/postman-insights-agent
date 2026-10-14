# Postman Java agent

A Java agent that captures decrypted HTTPS traffic from inside a JVM, for the Postman Insights Agent.

It hooks every `javax.net.ssl.SSLEngine` implementation (the JDK's, Netty's, and others) and hands the plaintext of each `wrap` and `unwrap` call to the kernel as a frame: a positional write to `/dev/null` at a magic offset.
The Insights Agent's eBPF programs (`ebpf/programs/java_tls.bpf.c`) read the frame on syscall entry and feed it into the same pipeline as the libssl uprobes.
The bridge to the kernel is pure Java (no JNI, no `Unsafe`), and the agent runs on JDK 8 through 25.

## How it works

- **Hooks:** every public `wrap` and `unwrap` shape, not only the abstract 4-argument ones.
  Engines may override the other shapes without delegating to the abstract ones: Netty's OpenSSL engine does, and its `SslHandler` never calls the abstract `unwrap`.
  Only the outermost hooked call on a thread emits, so an overload that delegates to another, or a wrapper engine that delegates to another engine, does not emit twice.
- **No allocation per call on JDK 16+:** the per-thread call state is reused, and frames are built in a small pool of direct buffers shared by all threads (twice the CPUs, 4 to 32), each with its own `/dev/null` channel.
  On JDK 8 to 15, copying from a direct or read-only buffer (Netty uses direct buffers) needs a view of it: one small, short-lived object per such buffer per call.
  Heap buffers, which Tomcat and the JDK's HTTP server use, are copied without one on every JDK.
  When every buffer is busy, the frame is dropped and counted rather than making the application wait.
- **Control file:** the agent captures only while `/tmp/.postman-insights/control` is fresh (under 60 s old), has a version it knows and says `enabled=1`; otherwise it is dormant, and the hooks return at once.
  The Insights Agent writes the file into the container of every JVM in the pods it monitors, and refreshes it every 10 s, so capture stops on its own when the pod is no longer monitored or the Insights Agent is removed.
  The agent checks it every 5 s, on its own daemon thread (`postman-insights-agent`).
- **HEARTBEAT frames:** at start and every 30 s, whether capturing or dormant, the agent sends its version, the JVM's version and vendor, its state and its counters.
- **JDK tools:** loaded through `JAVA_TOOL_OPTIONS`, the agent starts in every JVM in the container; it does nothing in the JDK's own tools (`jcmd`, `keytool`, `javac` and so on).
- **Safety:** the advice never throws into application code, and 100 internal errors within any 10 minutes switch the agent off until the JVM restarts.

## Contract with the Insights Agent

The frame format, the control file, the HEARTBEAT payload and the names both sides use are defined three times, and tests keep the copies in sync:

| Copy | Location |
|---|---|
| Kernel | `ebpf/programs/java_frame.h` |
| Go | `ebpf/javatls/` (`frame.go`, `contract.go`) |
| Java | `src/main/java/com/postman/insights/agent/bootstrap/` (`Frame.java`, `Contract.java`) |

The examples in `ebpf/javatls/testdata/` are checked by both the Go and the Java tests: frames in `frames-v1.json`, control files and HEARTBEAT payloads in `payloads-v1.json`.
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
They write frames to a file instead of the kernel, and read the control file from the build directory (the `postman.insights.agent.frameLog` and `postman.insights.agent.controlFile` system properties, for tests only), so they need no eBPF.
They cover every hook shape on the JDK's engine, on Netty's OpenSSL engine and on a wrapper engine, a real Netty server, and dormant mode.
To run them on another JDK:

```sh
./gradlew agentTest -PagentTestJavaHome=/path/to/jdk8
```

Without a local JDK, run Gradle in Docker:

```sh
docker run --rm -v "$PWD/..:/w" -w /w/java-agent eclipse-temurin:21-jdk ./gradlew --no-daemon check
```

For an end-to-end check with the eBPF agent in kind, see `test/kind/deploy-java-service.sh`.

## Packaging

`build-scripts/Dockerfile.ebpf` builds the jar and puts it at `/opt/postman/postman-java-agent.jar` in the eBPF image, with its SHA-256 in `postman-java-agent.jar.sha256` and the `postman-jvm-attach` helper next to it.
The build arg `AGENT_VERSION` sets the jar's version.

## Status

Java HTTPS capture is in preview, and off by default until the preview release.
`--https-libraries=openssl,java` (on `kube run` and `apidump`, with `--enable-https-capture`) turns it on.
Without `java`, the Insights Agent switches off the agents already running in the JVMs of the pods it monitors, at the next control-file refresh.
Run as a sidecar (`apidump`), the Insights Agent captures Java only in its own pod's network namespace, even with `hostPID`.
The Insights Agent writes the control file for the JVMs in the pods it monitors (`ebpf/jvm`), so a JVM started with `-javaagent` in a monitored pod captures within seconds.
It also loads the agent into running JVMs that do not have it, through the `postman-jvm-attach` helper (`cmd/postman-jvm-attach`), which it runs as each JVM's own user.
On JDK 21 and newer, the JVM then prints four `WARNING: A Java agent has been loaded dynamically ...` lines to its stderr; they are harmless.
What happens to each JVM (attached, agent already running, skipped or failed, with the reason) is logged once and counted in the pod's telemetry as `java_jvm_*` events; the `ebpf-stats` line shows the node's totals.
