# Phase 5 — Execution plan (scoped into 5a / 5b / 5c)

**Status:** scoping decision. Supplements [`phase-5.md`](phase-5.md) (the
full 6-week reference brief). Read this first when starting any Phase 5
session; read `phase-5.md` for deeper context on a specific sub-task.

**Decision recorded:** Phase 5 is **the biggest, riskiest phase by a wide
margin**. We will not try to execute it in one push. We split it into
**three independent sessions (5a, 5b, 5c)**, each with its own exit
criteria and PR-able checkpoint. Each session can stand on its own; if
priorities shift after any of them, we can stop without leaving
half-finished components.

---

## Why split (the honest assessment)

|                         | Phases 1–4                | Phase 5                                                 |
| ----------------------- | ------------------------- | ------------------------------------------------------- |
| Effort estimate         | ~1 week each              | 6 weeks (Java 3w + eBPF 1w + webhook 2w)                |
| Languages added         | Go + BPF C                | Go + BPF C + Java + JNI C                               |
| New build systems       | —                         | Gradle (Java agent)                                     |
| New infrastructure      | —                         | Mutating admission webhook                              |
| Validation surface      | A handful of binaries     | 4 JDKs × 4 frameworks = 16 combinations                 |
| Risk concentration      | Low, incremental          | High — JVMTI / ByteBuddy / JNI shim / webhook TLS       |
| Reference code reuse    | Some OBI bits             | Heavy port from OBI's `pkg/internal/java/agent/`        |

Three concrete risks that argue for splitting:

1. **Blast radius.** A misconfigured `MutatingWebhookConfiguration` with
   `failurePolicy: Fail` can break **all** pod creation in a cluster. We
   want that piece isolated to its own session with a clean rollback
   story (built `failurePolicy: Ignore` from day one).
2. **Validation cost.** Java validation needs a non-trivial workload
   (Spring Boot, gRPC-Java, Tomcat, Jetty). Building those images is
   doable but not zero-cost like `/tmp/gohttps`.
3. **The OBI port isn't blind copy-paste.** OBI's agent has its own
   opinions (OTel context propagation glued in) that we need to strip.
   Worth doing once, carefully, in a session focused on it.

Doing 5a first **validates the architecture before we invest in Java**.
If the ioctl-bridge approach has a problem we missed, we find it in a
~200-line BPF program and a 50-line C harness — not in a 3-week Java
agent.

---

## Session 5a — eBPF foundation (~1 week)

**Branch:** `feat/https-capture-ebpf` (rolling PR #173 — see SESSION-RESUME).

**Goal in one sentence:** kernel side wired end-to-end against a tiny C
harness — no Java involved yet.

### Scope

1. `ebpf/programs/java_tls.bpf.c` — sys_ioctl kprobe, adapted from OBI's
   `bpf/generictracer/java_tls.c`. Strip OBI's context-propagation code;
   keep only the raw plaintext path.
2. `ebpf/loader/` — conditional load of `java_tls` (only when Java capture
   is enabled, to save verifier budget).
3. `cmd/internal/apidump-javatls/` — spike CLI mirroring the existing
   `apidump-ebpf` and `apidump-gotls` skeletons.
4. `test/java-tls-harness/harness.c` — minimal C program that allocates a
   `java_packet`, fills it with a real HTTP request, and calls
   `ioctl(0, 0x0b10b1, &packet)`.

### Wire format (frozen for 5a — must match OBI's `IOCTLPacket.java`)

```c
struct java_packet {
    uint8_t  operation;        // 1 = SEND, 2 = RECV
    struct {
        uint32_t local_ip;
        uint16_t local_port;
        uint32_t remote_ip;
        uint16_t remote_port;
    } conn;                    // padded so total header is 36 bytes
    uint32_t buf_len;
    // followed by buf_len bytes of plaintext
};
```

Magic: `cmd == 0x0b10b1`, `fd == 0`. Both are checked kernel-side; the
Java agent will also check `System.console() == null`-style guards later
(belt and suspenders).

### Reuses existing infrastructure

* Same `ssl_event` struct as libssl, with `direction` derived from
  `operation` byte. **Same ringbuf** that libssl writes to — userspace
  doesn't need to distinguish source.
* Same PID-allowlist mechanism.
* Same `ebpf/events/Adapter` — bytes feed the existing akinet parser.

### Exit criteria (binary pass/fail)

1. `make build-ebpf` clean with `java_tls.bpf.c` compiled and bundled.
2. `apidump-javatls --duration 10s` launches and attaches the kprobe.
3. Running `test/java-tls-harness/harness` (sends one synthetic
   `GET / HTTP/1.1\r\n...\r\n\r\n` followed by an `HTTP/1.1 200 OK`
   response) results in **one `REQ method=GET` and one `RESP status=200`**
   in the agent's output.
4. PID-filter test: running the harness with `--pid` set to an
   unrelated PID produces **zero** events.
5. Negative test: a normal `ioctl(0, TCGETS, ...)` produces zero events
   (the magic check works).

### Out of scope (deferred to 5b / 5c)

* All Java code, Gradle, ByteBuddy, JNI.
* Spring Boot / Netty / Tomcat / Jetty test workloads.
* Mutating admission webhook.
* JMH benchmarks.

### Files this session will touch

```
ebpf/programs/java_tls.bpf.c          (new)
ebpf/loader/loader_linux.go            (extend — conditional load)
ebpf/collect_javatls_linux.go          (new — mirrors collect_gotls_linux.go)
ebpf/collect_stub.go                   (extend with javatls stub)
cmd/internal/apidump-javatls/main.go   (new)
cmd/root.go                            (register subcommand)
test/java-tls-harness/harness.c        (new)
test/java-tls-harness/Makefile         (new)
docs/phases/phase-5a-results.md        (new — at end of session)
```

### Validation script (run before claiming done)

```sh
# 1. Build clean.
make build-ebpf
go build ./...

# 2. Build harness.
make -C test/java-tls-harness

# 3. End-to-end (in dev container).
sudo bin/postman-insights-agent apidump-javatls --duration 10s &
sleep 1
./test/java-tls-harness/harness
wait
# Expect: REQ method=GET path=/, RESP status=200.

# 4. Negative test (wrong ioctl).
sudo bin/postman-insights-agent apidump-javatls --duration 5s &
sleep 1
./test/java-tls-harness/harness --wrong-cmd
wait
# Expect: zero events.

# 5. PID filter.
sudo bin/postman-insights-agent apidump-javatls --pid 1 --duration 5s &
sleep 1
./test/java-tls-harness/harness
wait
# Expect: zero events (harness PID ≠ 1).
```

### Handoff at end of 5a

Write `docs/phases/phase-5a-results.md` capturing:
* Final wire format (any deviations from OBI's).
* Verifier complexity of the program (`bpftool prog show`).
* Any gotchas hit (likely: 36-byte header padding, sentinel-fd edge cases).
* Confirmation that 5b is unblocked.

Update `docs/phases/SESSION-RESUME.md` "Next task" to point at 5b.

---

## Session 5b — Java agent MVP (~2–3 weeks)

**Goal:** `java -javaagent:postman-java-agent.jar HelloHttps` captures
REQ + RESP end-to-end against the **5a BPF program**.

### Scope

1. `java-agent/` Gradle project (`build.gradle.kts`, `settings.gradle.kts`).
2. ByteBuddy `Agent.premain(...)` + **`SSLEngineInst` only**. Skip
   `SSLSocketInst`, `SSLSocketStreamInst`, `NettySSLHandlerInst`.
3. JNI shim (`src/main/c/postman_jni.c`) + `NativeMemory.java`. Build for
   linux-amd64 and linux-arm64; pack natives under `native/<os>-<arch>/`.
4. Off-heap thread-local buffer (64 KiB per thread, allocated lazily).
5. One workload: minimal `HttpsServer.create(...)` in
   `java-agent/testdata/hello-https/`. No Spring Boot, no Tomcat.

### Exit criteria

1. `./gradlew build` produces a single shaded JAR `~1.5 MB`.
2. Running the hello-https workload with the agent attached, against
   `apidump-javatls`, captures one REQ + one RESP per HTTP transaction.
3. Works on **JDK 17** only at this stage (8 / 11 / 21 deferred to 5c).
4. No crashes under a 1000-request load.

### Out of scope (deferred to 5c)

* Netty / Spring Boot / gRPC-Java / Tomcat / Jetty.
* JDK 8 / 11 / 21 (we'll widen the matrix in 5c).
* JMH benchmarks.
* Webhook.

### Decision points to surface during 5b

* `Unsafe` vs `MemorySegment` — start with `MemorySegment` on JDK 17.
  Add `Unsafe` fallback only when 5c needs JDK 8/11.
* Remote-address extraction for `SSLEngine` (engine is not a socket).
  Lift OBI's `NettyChannelExtractor` pattern but only the
  `SocketChannel` path — Netty extraction comes in 5c.

---

## Session 5c — Framework matrix + webhook (~2 weeks)

**Goal:** at least 8 of 16 (JDK × framework) matrix combos green;
webhook auto-injects `JAVA_TOOL_OPTIONS` in a kind cluster.

### Scope

1. `NettySSLHandlerInst` (unlocks Spring Boot + gRPC-Java).
2. `SSLSocketInst` (unlocks Tomcat).
3. `SSLSocketStreamInst` (Jetty).
4. Mutating admission webhook in `cmd/internal/kube-webhook/`,
   `failurePolicy: Ignore` from day one.
5. Helm chart updates under `cmd/internal/kube/daemonset/templates/`.
6. Matrix run: 4 JDKs × 4 frameworks. Document failures honestly in
   `docs/phases/phase-5-results.md`.
7. JMH benchmark — assert <50 µs added per `wrap`/`unwrap`.

### Exit criteria

The seven from `phase-5.md` §"Hard exit criteria" (Spring Boot, gRPC-Java,
Tomcat, Jetty captured; JDK 8/11/17/21; webhook injection works in
kind; ≤500 ms JVM startup added; ≤50 µs per call).

### High-risk items to flag at the start of 5c

* `MutatingWebhookConfiguration` blast radius — use `failurePolicy: Ignore`,
  and rehearse rollback before deploying.
* JSSE provider variations (Bouncy Castle, Conscrypt) — match by
  `isSubTypeOf(SSLEngine.class)`, not concrete class.
* `/tmp` `noexec` in hardened containers — JNI native unpack target.

---

## Why this order works

* **5a is fast and self-contained.** A working ringbuf-fed adapter
  fronted by a C harness gives us confidence in the architecture before
  touching Java.
* **5b proves the Java side** against a known-good BPF program. If
  something is wrong, it's in the Java agent, not the kernel path.
* **5c is the matrix-and-infra session** — the parts that have the
  biggest validation cost and biggest blast radius. By the time we
  enter 5c, both ends of the pipe are proven.

If after 5a we learn the ioctl-bridge approach has a fundamental issue,
we **stop and reassess** before paying the Java cost. That's the whole
point of the split.
