# Phase 5 — Java support via agent + ioctl bridge

**Starting branch:** `feat/https-capture-ebpf` after Phase 2 has merged. Best after Phase 4 too (Java agent inherits Phase 4's redaction story).

**Working branch:** `feat/https-capture-ebpf-phase5`.

**Requires:** Linux dev host, JDK 17 (for building the agent), Gradle, and a Kubernetes cluster for admission-webhook validation. This phase is **the most cross-disciplinary** — it touches BPF C, Go (loader + webhook), Java (agent), and K8s (admission control).

**Effort:** 6 weeks. Plan it as 3 sub-projects: Java agent (3w), eBPF kprobe + ingestion (1w), mutating webhook (2w).

---

## Goal

JVMs running JSSE-based HTTPS (Tomcat, Jetty, Spring Boot, gRPC-Java, Netty) have their plaintext captured by a small Java agent that ships bytes through `ioctl()` to an eBPF kprobe, unified into the same event pipeline as native and Go captures.

## Hard exit criteria

1. A Spring Boot HTTPS service is fully captured (request method, path, headers, body up to cap, response status, body).
2. A gRPC-Java service over TLS is captured (unary + streaming).
3. A Tomcat HTTPS service is captured.
4. A Jetty HTTPS service is captured.
5. Works on OpenJDK 8, 11, 17, 21.
6. Mutating webhook auto-injects `JAVA_TOOL_OPTIONS=-javaagent:...` into pods in `decrypt: true` namespaces with Java workloads, validated by a kind cluster end-to-end test.
7. JVM startup overhead from the agent ≤ 500ms (ByteBuddy class transformation cost).
8. Per-request overhead ≤ 50µs (measured via JMH benchmark comparing instrumented vs. uninstrumented `SSLEngine.wrap`/`unwrap`).

## Prerequisites — read these first

In the agent repo:
- All prior phases merged
- `cmd/internal/kube/` — current K8s integration

In OBI (`../insights-ebpf-research/obi/`):
- `bpf/generictracer/java_tls.c` — the kernel-side ioctl kprobe. **Read this first.**
- `pkg/internal/java/agent/src/main/java/io/opentelemetry/obi/java/Agent.java` — Java agent entry point (the `premain` method)
- `pkg/internal/java/agent/src/main/java/io/opentelemetry/obi/java/instrumentations/SSLEngineInst.java`
- `pkg/internal/java/agent/src/main/java/io/opentelemetry/obi/java/instrumentations/SSLSocketInst.java`
- `pkg/internal/java/agent/src/main/java/io/opentelemetry/obi/java/instrumentations/NettySSLHandlerInst.java`
- `pkg/internal/java/agent/src/main/java/io/opentelemetry/obi/java/ebpf/IOCTLPacket.java` — wire format
- `pkg/internal/java/agent/src/main/java/io/opentelemetry/obi/java/ebpf/NativeMemory.java` — the JNI shim
- `pkg/internal/java/agent/src/main/c/` — JNI C source
- `pkg/internal/java/agent/Makefile.jni`
- `pkg/internal/java/agent/build.gradle.kts`
- `pkg/webhook/` — OBI's K8s mutating webhook
- `javaagent.Dockerfile` — how the Java JAR is built

External reading:
- ByteBuddy docs: https://bytebuddy.net/
- JVMTI agents (we use ByteBuddy, but understanding the alternative helps)
- Kubernetes mutating admission webhooks: https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/

## Tasks (in order)

### 1. The eBPF kprobe — small first step

Create `ebpf/programs/java_tls.bpf.c` adapted from OBI. Strip OBI's extra context-propagation code; we only need the raw plaintext path.

The wire format (matches OBI's `IOCTLPacket.java`):
```
struct java_packet {
    uint8_t  operation;        // 1=SEND, 2=RECV
    struct connection_info {
        uint32_t local_ip;
        uint16_t local_port;
        uint32_t remote_ip;
        uint16_t remote_port;
        // padded to 36 bytes
    } conn;
    uint32_t buf_len;
    // followed by buf_len bytes of plaintext
}
```

The kprobe attaches to `sys_ioctl`. It checks:
- `fd == 0` (sentinel — JVM never does real ioctl on stdin)
- `cmd == 0x0b10b1` (magic id agreed with the Java agent)
- `arg` points to a `java_packet`

If all match, copy the buffer into a ringbuf event using the same `ssl_event` struct as libssl (with `direction` set from the `operation` byte). **Reuse the same ringbuf** that libssl uses — userspace doesn't need to distinguish source.

The PID allowlist applies the same way as libssl.

Add to the loader: `java_tls` is loaded conditionally (only if Java capture is enabled — saves verifier budget).

### 2. Java agent project skeleton

Create new top-level directory `java-agent/`:

```
java-agent/
├── build.gradle.kts
├── settings.gradle.kts
├── src/main/java/com/postman/insights/agent/
│   ├── Agent.java                          premain(...) entry
│   ├── ebpf/
│   │   ├── IoctlPacket.java
│   │   ├── NativeMemory.java               JNI to call ioctl()
│   │   └── OperationType.java
│   └── instrumentations/
│       ├── SSLEngineInst.java              JSSE direct
│       ├── SSLSocketInst.java              older blocking I/O
│       ├── SSLSocketStreamInst.java
│       └── NettySSLHandlerInst.java        Spring Boot, gRPC-Java
└── src/main/c/
    ├── postman_jni.c                       ioctl() syscall wrapper
    └── Makefile.jni
```

Build outputs a single shaded JAR: `postman-java-agent.jar` (~1.5 MB including ByteBuddy + JNI native libs for amd64+arm64).

The `Agent` class's `premain(String agentArgs, Instrumentation inst)` method is the JVM entry point. It registers ByteBuddy transformations for each `Inst` class.

### 3. Instrumentation classes

For each Inst class, the pattern is (cribbed from OBI):

```java
public class SSLEngineInst {
    public static AgentBuilder.Transformer transformer() {
        return (builder, type, classLoader, module, protectionDomain) ->
            builder
                .visit(Advice.to(UnwrapAdvice.class).on(
                    ElementMatchers.named("unwrap")
                        .and(ElementMatchers.takesArgument(1, ByteBuffer.class))))
                .visit(Advice.to(WrapAdvice.class).on(
                    ElementMatchers.named("wrap")
                        .and(ElementMatchers.takesArgument(0, ByteBuffer.class))));
    }

    public static class UnwrapAdvice {
        @Advice.OnMethodExit
        public static void onExit(
                @Advice.This SSLEngine engine,
                @Advice.Argument(1) ByteBuffer dst,
                @Advice.Return SSLEngineResult result) {
            if (result.bytesProduced() <= 0) return;
            byte[] plaintext = ByteBufferExtractor.b(dst, result.bytesProduced());
            IoctlPacket.send(OperationType.RECV, engine, plaintext);
        }
    }

    // WrapAdvice symmetric for SSLEngine.wrap()
}
```

Critical implementation notes:
- **`@Advice.OnMethodExit`** is what we use; entry advice can race with the engine's internal state.
- **Read state AFTER the underlying call returns** — for unwrap, plaintext lands in `dst` after the method returns.
- **The `SSLEngine` itself is not a `Socket`** — getting the remote address requires walking back to the owning `SSLSocket` or `SocketChannel`. See OBI's `NettyChannelExtractor.java` for the pattern.
- **ByteBuffer state is fragile.** Position, limit, mark all change. Make a copy immediately; never hold a `ByteBuffer` reference past advice exit.

Port from OBI rather than writing from scratch. Their tests catch real edge cases.

### 4. JNI for the ioctl syscall

`src/main/c/postman_jni.c`:
```c
#include <jni.h>
#include <sys/ioctl.h>

JNIEXPORT jint JNICALL
Java_com_postman_insights_agent_ebpf_NativeMemory_doIoctl(
        JNIEnv *env, jclass clazz,
        jint fd, jlong cmd, jlong arg) {
    return (jint) ioctl(fd, (unsigned long) cmd, (void *) arg);
}
```

Built per-architecture, packed into the JAR under `native/linux-amd64/`, `native/linux-aarch64/`. The `NativeMemory` Java class unpacks the right one at startup using `System.load`.

Buffer management: use `sun.misc.Unsafe` or `java.lang.foreign.MemorySegment` (Java 21+) to allocate off-heap memory, build the `java_packet` in it, pass its address to `doIoctl`. This avoids per-call GC pressure.

OBI uses `Unsafe`. For new code on JDK 17+, prefer `MemorySegment`. Maintain a `JAVA_VERSION` switch in `NativeMemory.java`.

### 5. Thread-safety + performance

JVMs are multi-threaded; many threads will hit `SSLEngine.wrap` concurrently. The ioctl call itself is thread-safe (it's a syscall) but the buffer allocation must be either:
- Thread-local off-heap buffer (preferred — zero contention)
- Pool of buffers with checkout/return

Use thread-local. Allocate 64 KiB per thread on first use; reuse for the life of the thread.

Benchmark with JMH:
```
src/jmh/java/com/postman/insights/agent/bench/SSLEngineBench.java
```
Measure `wrap()`/`unwrap()` with and without instrumentation, asserting <50µs added overhead per call.

### 6. Mutating admission webhook

New directory: `cmd/internal/kube-webhook/`.

Standard Go-based admission webhook (look at OBI's `pkg/webhook/` for the pattern). It:

1. Receives `AdmissionReview` requests for `Pod` create/update.
2. Determines if the pod is a Java workload (check container images, env vars, command — heuristic).
3. Checks namespace's discovery config (`decrypt: true`).
4. If both: patch the pod to add:
   - An init container that copies `postman-java-agent.jar` into a shared volume
   - A shared `emptyDir` volume
   - `JAVA_TOOL_OPTIONS=-javaagent:/postman/postman-java-agent.jar` env var on Java containers
5. Sign the response with a JSON patch.

The webhook itself is just another command on the main binary: `postman-insights-agent kube-webhook`. Deployed as a separate Deployment (not the DaemonSet) since admission webhooks need to be cluster-scoped HA.

TLS certs for the webhook: bootstrap via `cert-manager` (preferred) or self-generate with a sidecar.

### 7. Helm chart updates

Update `cmd/internal/kube/daemonset/templates/` to include:
- A new Helm chart for the webhook
- An optional value `https-capture.java.enabled` that gates webhook deployment
- The `MutatingWebhookConfiguration` resource

### 8. End-to-end validation

Create test workloads in `java-agent/testdata/`:
- `spring-boot-https/` — Spring Boot app exposing HTTPS endpoint
- `grpc-java-tls/` — gRPC-Java echo service over TLS
- `tomcat-https/` — Tomcat war
- `jetty-https/` — Jetty embedded

For each, write a script in `scripts/test-java-https.sh JDK_VERSION WORKLOAD` that:
1. Builds the workload Docker image with the chosen JDK
2. Deploys to kind
3. Generates HTTPS load
4. Asserts the agent captured the request/response

Run the matrix: 4 JDK versions × 4 workloads = 16 combinations. Some will fail; document which.

## Common failure modes

1. **JVM in container can't find ioctl shim's native library.** The JAR includes platform-specific .so files but they must be extracted to a writeable path. `/tmp` is usually fine; some hardened containers mount `/tmp` noexec. Document the requirement.

2. **`fd=0` ioctl conflicts with weird apps.** Some JVMs are launched with stdin redirected from a pipe; `fd=0` may be a real file in those cases. Add a sanity check: the agent verifies our magic cmd is actually our magic before doing anything. The kernel-side kprobe already checks this. The Java side should too (return early without ioctl if `System.console() == null` etc.) — belt and suspenders.

3. **ByteBuddy class transformation cost on startup.** Big apps with thousands of classes see noticeable startup hit. Mitigation: lazy transformation, only transform classes when first loaded. ByteBuddy supports this.

4. **JSSE provider variations.** Bouncy Castle and Conscrypt replace JSSE entirely. Our `SSLEngine` advice may not fire because `BouncyCastleJsseProvider` provides a different `SSLEngine` subclass. Mitigation: match by type hierarchy, not concrete class. `ElementMatchers.isSubTypeOf(SSLEngine.class)` (already in OBI).

5. **mTLS client cert in `X-Forwarded-Client-Cert` after termination.** Not directly a Java bug, but appears here for the first time because Java services are common in mTLS architectures. The Phase 4 redactor already covers this header — confirm.

6. **Webhook becomes single point of failure for pod creation.** A bad webhook deployment can break **all pod creation** in the cluster. Use `failurePolicy: Ignore` in the `MutatingWebhookConfiguration` to fail open. Document this trade-off for customers (some prefer fail closed).

7. **JDK 8 lacks `MemorySegment`.** Use `sun.misc.Unsafe` fallback for JDK 8/11. Tests confirm.

8. **Spring Boot uses Netty, not JSSE direct.** Even though Spring Boot is "Java", many of its HTTPS paths bypass `SSLEngine` and go through Netty's `SslHandler`. `NettySSLHandlerInst.java` is critical for the demo to work. Don't skip it.

## Validation

```sh
# 1. Default agent build clean (Java path is opt-in).
go build ./...

# 2. eBPF build with new java_tls program clean.
make build-ebpf

# 3. Java agent builds.
cd java-agent && ./gradlew build
# Output: java-agent/build/libs/postman-java-agent.jar
file java-agent/build/libs/postman-java-agent.jar  # confirm shaded

# 4. JMH benchmarks.
cd java-agent && ./gradlew jmh
# Verify <50µs per call overhead.

# 5. End-to-end matrix.
./scripts/test-java-https.sh 17 spring-boot-https
./scripts/test-java-https.sh 17 grpc-java-tls
./scripts/test-java-https.sh 17 tomcat-https
./scripts/test-java-https.sh 17 jetty-https
# Repeat for 8, 11, 21.

# 6. Webhook end-to-end.
kind create cluster
helm install postman-insights ./charts/postman-insights --set https-capture.java.enabled=true
kubectl apply -f docs/phases/phase-5-test-pod.yaml
# Verify JAVA_TOOL_OPTIONS was injected; verify capture works.

# 7. Failure mode: deploy with webhook unavailable, verify failurePolicy: Ignore lets pods create.
```

## Handoff — phase delivery complete

Update:
- `ebpf/README.md` — Java support ✅, all phases ✅
- `docs/https-capture-design.md` — final "GA-ready" callout
- `docs/phases/phase-5-results.md` — JDK matrix results
- `README.md` — add Java to the supported runtimes list
- `CLAUDE.md` — final architectural overview reflects all five phases

At this point: **HTTPS capture is feature-complete across the target runtime matrix.** Open questions for v1.1+:
- Rust (rustls) — defer
- HTTP/3 / QUIC — fundamentally different transport, requires new design
- macOS — out of scope per design doc
