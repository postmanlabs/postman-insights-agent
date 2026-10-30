# Postman Insights Java agent

A Java agent that captures decrypted HTTPS traffic from inside a JVM, for the Postman Insights Agent.

It hooks every `javax.net.ssl.SSLEngine` implementation (the JDK's, Netty's, and others) and hands the plaintext of each `wrap` and `unwrap` call to the kernel as a frame: a positional write to `/dev/null` at a magic offset.
The Insights Agent's eBPF programs (`ebpf/programs/java_tls.bpf.c`) read the frame on syscall entry and feed it into the same pipeline as the libssl uprobes.
The bridge to the kernel is pure Java (no JNI, no `Unsafe`), and the agent runs on JDK 8 through 25.

## How it works

- **Hooks:** every public `wrap` and `unwrap` shape, not only the abstract 4-argument ones.
  Engines may override the other shapes without delegating to the abstract ones: Netty's OpenSSL engine does, and its `SslHandler` never calls the abstract `unwrap`.
  Only the outermost hooked call on a thread emits, so an overload that delegates to another, or a wrapper engine that delegates to another engine, does not emit twice.
- **Blocking `SSLSocket`:** the JDK's `SSLSocket` (`sun.security.ssl.SSLSocketImpl`, JDK 8u261 and newer) uses no `SSLEngine`, so its application streams' `read` and `write` are hooked too, with the socket as the connection; `close` is hooked for its CLOSE frame.
  This covers blocking clients: `HttpsURLConnection`, Apache HttpClient's classic API, OkHttp.
  Other providers' sockets (BouncyCastle JSSE, Conscrypt) are not hooked.
- **No allocation per call on JDK 16+:** the per-thread call state is reused, and frames are built in a small pool of direct buffers shared by all threads (twice the CPUs, 4 to 32), each with its own `/dev/null` channel.
  On JDK 8 to 15, copying from a direct or read-only buffer (Netty uses direct buffers) needs a view of it: one small, short-lived object per such buffer per call.
  Heap buffers, which Tomcat and the JDK's HTTP server use, are copied without one on every JDK.
  When every buffer is busy, the frame is dropped and counted rather than making the application wait.
- **Control file:** the agent captures only while `/tmp/.postman-insights/control` is fresh (under 60 s old), has a version it knows and says `enabled=1`; otherwise it is dormant, and the hooks return at once.
  The Insights Agent writes and refreshes the file, so capture stops on its own when the pod is no longer monitored or the Insights Agent is removed.
  The agent checks it every 5 s, on its own daemon thread (`postman-insights-java-agent`).
- **HEARTBEAT frames:** at start and every 30 s, whether capturing or dormant, the agent sends its version, the JVM's version and vendor, its state and its counters.
  The Insights Agent logs each agent once when it first hears from it and whenever its state changes, and its `ebpf-stats` line shows the agents alive and capturing in each pod (`java_agents_alive`, `java_agents_capturing`).
- **Connection addresses:** the kernel gives each connection's events their addresses, and the agent helps it tie connections to sockets.
  For a blocking `SSLSocket`, it sends the socket's addresses in an ADDRESS frame before the first data frame, and marks the socket's frames `SOCKET`.
  For an `SSLEngine`, it sends an empty RECV frame at the connection's first unwrap that consumed TLS bytes, and an empty SEND frame (`FLAG_BEFORE_WRITE`) at every wrap that produced TLS bytes without plaintext, so the kernel can tie the connection to a socket: a RECV frame by the socket the thread last read (within 50 ms before), a `FLAG_BEFORE_WRITE` SEND frame by the socket the thread writes next (within 10 ms after).
  How the kernel ties them, and the limits: "Connection addresses" in [`docs/https-capture-design.md`](../docs/https-capture-design.md).
- **CLOSE frames:** once a connection can carry no more responses (the server's side closed, or the client's inbound side), the agent sends a CLOSE frame.
  The Insights Agent then completes a response delimited by the close and frees the connection's state at once, instead of after 30 s idle.
  Connections that end without a TLS close_notify are freed when idle.
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
./gradlew agentJar   # build/agent/postman-insights-java-agent.jar
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

The Insights agent's real-JVM tests (`ebpf/node_collector_jvm_linux_test.go`, root and the `insights_bpf` tag) run the packaged agent in real JVMs and check what comes out of the kernel, connection addresses included.
They need a JDK and the jar, and for the framework tests the apps in `src/testApps` (Netty on NIO, epoll and its OpenSSL engine; Tomcat, Jetty and Undertow servers; the JDK's `HttpClient`), built by `./gradlew testAppsDist` into `build/test-apps`:

```sh
POSTMAN_TEST_JAVA_HOME=/path/to/jdk17 \
POSTMAN_TEST_AGENT_JAR=$PWD/java-agent/build/agent/postman-insights-java-agent.jar \
POSTMAN_TEST_APPS_DIR=$PWD/java-agent/build/test-apps \
  go test -tags insights_bpf -p 1 -run 'TestNodeCollectorJVM' ./ebpf/
```

For an end-to-end check with the eBPF agent in kind, see `test/kind/deploy-java-service.sh`.

## Packaging

`build-scripts/java-capture-files.sh` builds the jar and puts it, with its SHA-256 in `postman-insights-java-agent.jar.sha256` and the `postman-insights-jvm-attach` helper, where the Insights Agent loads them from: `/opt/postman` in the eBPF image (`build-scripts/Dockerfile.ebpf`, and the release image).
The build arg `AGENT_VERSION` of `Dockerfile.ebpf` sets the jar's version; release images use the Insights Agent's version.

## Use with the Insights Agent

Java HTTPS capture is in preview, and on by default with `--enable-https-capture` (`--https-libraries=openssl` turns it off).
As a DaemonSet (`kube run`), the Insights Agent loads the agent into running JVMs; as a sidecar (`apidump`), the JVMs need `-javaagent` with a copy of the jar.
How the Insights Agent writes the control file, loads the agent, removes other versions' copies and reports each JVM: "Java capture" in [`docs/https-capture-design.md`](../docs/https-capture-design.md).
