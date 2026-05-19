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

## Session 5b — Java agent MVP (~2–3 weeks, split into 5b.1 / 5b.2 / 5b.3)

**Why split:** the original 5b brief bundles three risks together —
JNI tooling, ByteBuddy instrumentation, and JDK build packaging. Same
rationale as the 5a split: prove the new ingredient in isolation before
layering the next one. Decided at the start of 5b.1; sessions 5b.1, 5b.2,
and 5b.3 each have their own commit + results doc.

### Session 5b.1 — Java→ioctl bridge spike (~1 session) ✅

**Goal:** prove the JNI + off-heap path against the **5a BPF program**,
with the minimum new ingredients. The Java-side analogue of 5a's C
harness.

**Scope:**
1. Add `openjdk-17-jdk-headless` + Gradle to `Dockerfile.dev`.
2. `java-agent/` Gradle project skeleton (`build.gradle.kts`,
   `settings.gradle.kts`).
3. `postman_jni.c` + `Makefile` — single JNI native method wrapping
   `ioctl(2)`.
4. `NativeMemory.java` — library loading + off-heap allocator via
   `sun.misc.Unsafe`.
5. `IoctlPacket.java` — 41-byte packed header builder + `send()`.
6. `Main.java` — CLI with `pair` / `send` / `recv` / `wrong-cmd` /
   `bad-op` / `burst N` modes.

**Exit criteria (all green per [`phase-5b1-results.md`](phase-5b1-results.md)):**
* `java -jar postman-java-agent.jar pair` against `apidump-javatls`
  emits one `REQ method=GET url=/phase5b1` + one `RESP status=200`.
* Negative tests (wrong-cmd, bad-op) emit zero events.
* Burst 1000 pairs: 2000 events emitted, zero ringbuf drops.

**Deferred to 5b.2:** ByteBuddy, `Agent.premain`, `SSLEngineInst`, off-
heap thread-local pool, native-lib unpack-from-JAR, real HTTPS workload.

### Session 5b.2 — ByteBuddy + `SSLEngineInst` (~1-2 sessions) ✅

**Outcome:** completed in one session. All four exit criteria green.
See [`phase-5b2-results.md`](phase-5b2-results.md).

**Goal:** `java -javaagent:postman-java-agent.jar HelloHttps` captures
one REQ + RESP per HTTPS transaction on JDK 17.

**Scope:**
1. Add ByteBuddy dependency + `Premain-Class:` manifest attribute.
2. Use `com.github.johnrengelman.shadow` (or equivalent) to produce a
   single shaded JAR.
3. `Agent.premain(String, Instrumentation)` registers `SSLEngineInst`.
4. `SSLEngineInst` — advice on `wrap(ByteBuffer src, ByteBuffer dst)`
   and `unwrap(ByteBuffer src, ByteBuffer dst)` exit, reading plaintext
   from `dst` after the method returns.
5. `SocketChannelExtractor` — walk back to the engine's owning channel
   to recover remote `InetSocketAddress` (port-zero is acceptable for
   spike).
6. Off-heap thread-local 64 KiB buffer in `NativeMemory` instead of
   per-call `allocateMemory`.
7. Native-lib unpack from `META-INF/native/<os>-<arch>/` so the JAR is
   single-artefact.
8. `java-agent/testdata/hello-https/HelloHttps.java` — minimal HTTPS
   server using `HttpsServer.create(...)` from JDK built-ins.
9. End-to-end validation against `apidump-javatls`.

**Exit criteria:**
1. `gradle build` produces one shaded JAR ~1.5 MB.
2. `HelloHttps` workload + agent + curl → one REQ + one RESP captured.
3. 1000-request load: no crashes, no leaks (RSS stable).
4. JDK 17 only; 8 / 11 / 21 deferred to 5c.

### Session 5b.3 — hardening (~half a session, before 5c) ✅

**Outcome:** completed in the same session as 5b.2. All four 5b.3
exit criteria + the original 5b hard-exit criteria are green. See
[`phase-5b3-results.md`](phase-5b3-results.md).

**Phase 5b is now fully closed.**

**Goal:** close the 5b exit criteria from the original brief.

**Scope:**
* Stress test: 10k requests, no crashes, no FD leaks.
* Error-handling cleanup (advice classes must NOT throw into user code).
* JDK 17 startup-overhead measurement (target ≤ 500 ms per design).
* Per-request overhead measurement via simple wallclock (JMH is a 5c
  task, not a 5b.3 task).

**Out of scope (still deferred to 5c):**
* Netty / Spring Boot / gRPC-Java / Tomcat / Jetty.
* JDK 8 / 11 / 21.
* JMH benchmarks.
* Webhook.

### Decision points surfaced during 5b.1

* `Unsafe` vs `MemorySegment` — **landed on `Unsafe`.** Works JDK 8–21
  with no preview flags or `--add-opens` on JDK 17. The plan brief
  said "prefer `MemorySegment` on JDK 17+" but the incubator/preview
  module flags make it noisier than `Unsafe` for a spike. 5c may add a
  `MemorySegment` fast-path on JDK 21+ once we have a JMH measurement
  that justifies it.
* JNI return packing — use a 64-bit `jlong` packing `errno` in the high
  32 bits and the `ioctl` rc in the low 32. Avoids a second JNI hop
  just to read errno.
* Native-lib loading — 5b.1 uses `-Djava.library.path` /
  `-Dpostman.agent.native.lib=…`. 5b.2 adds the unpack-from-JAR path.

---

## Session 5c — Framework matrix + webhook (~2 weeks, split into 5c.1 / 5c.2 / 5c.3)

**Why split:** same rationale as 5b. The original 5c bundles three
independent workstreams (Java framework instrumentation, JDK matrix
plumbing, K8s admission webhook). The webhook in particular has
**high blast radius** — a misconfigured `MutatingWebhookConfiguration`
can break ALL pod creation in a cluster. Isolating it lets us focus
entirely on safety + rollback rehearsal in its own session.

### Session 5c.1 — Spring Boot + Netty (~1 session) ✅

**Outcome:** ✅ all 5c.1 exit criteria green with **zero new agent
code**. See [`phase-5c1-results.md`](phase-5c1-results.md).

**Key finding:** 5b.2's `ElementMatchers.isSubTypeOf(SSLEngine.class)`
matcher already catches Netty's `JdkSslEngine`, `OpenSslEngine`, and
`ReferenceCountedOpenSslEngine` for free. The framework gap closed
without writing `NettySSLHandlerInst`.

**Validation:** Spring Boot 3.2 webflux + agent + 10000 parallel
curls → 10001/10001 REQ + RESP parsed, zero ringbuf drops, JVM stable.

### Session 5c.2 — Tomcat + Jetty + JDK matrix + gRPC-Java (~1 session) ✅

**Outcome:** completed with mixed results. See
[`phase-5c2-results.md`](phase-5c2-results.md) for the full tally.

* **Frameworks:** Spring Boot ✅ + Tomcat ✅ (full REQ+RESP);
  Jetty 12 🟡 REQ only; gRPC-Java 🟡 RESP only.
* **JDK matrix:** JDK 11 / 17 / 21 ✅ all green (HelloHttps + 3
  curls). JDK 8 ❌ deferred (agent uses `Module.redefineModule`).
* **JMH:** deferred — 5b.3 curl-level latency already shows agent
  overhead below noise floor; JMH gives microsecond precision but
  doesn't change the conclusion.
* **Three follow-up items documented**, none blocking 5c.3.

**Open empirical question to answer FIRST** (same approach as 5c.1):
does the JDK's `SSLSocketImpl` internally use `SSLEngine` such that
our existing advice already covers Tomcat? Build a Tomcat workload,
attach the existing agent, see what happens. **Possible outcome:**
5c.2 also lands with zero new instrumentation.

If new advice IS needed:
* `SSLSocketInst` — Tomcat default connector (blocking I/O).
* `SSLSocketStreamInst` — Jetty (specialised buffer pool path).

Regardless:
* gRPC-Java workload (unary + streaming) — validate via existing advice.
* JDK 8 / 11 / 21 container matrix — re-run the 5b/5c.1 validation
  suite against each JDK. `Unsafe` already works on all four; the
  work is container plumbing.
* JMH benchmark harness — `SSLEngine.wrap`/`unwrap` overhead in
  microseconds. Target: ≤ 50 µs added per call.

### Session 5c.3 — Mutating admission webhook (~1 session)

**Goal:** auto-inject `JAVA_TOOL_OPTIONS=-javaagent:/postman/postman-java-agent.jar`
into pods in `decrypt: true` namespaces with Java workloads.

**High-risk piece. Done in isolation with explicit safety story:**
* `failurePolicy: Ignore` from line 1 of the
  `MutatingWebhookConfiguration` — a broken webhook fails open,
  doesn't break the cluster.
* Rehearsed rollback procedure documented BEFORE any real cluster
  deploys.
* Kind-cluster end-to-end test as the only validation surface for
  this session.
* Workload heuristic: check container images / env vars / commands to
  identify Java workloads.
* Init container copies the agent JAR + native libs into a shared
  `emptyDir` volume; mutates the main container's env to add
  `JAVA_TOOL_OPTIONS`.
* TLS bootstrap via `cert-manager` (preferred) or self-generate.

**Goal (original):** at least 8 of 16 (JDK × framework) matrix combos
green; webhook auto-injects `JAVA_TOOL_OPTIONS` in a kind cluster.

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
