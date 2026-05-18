# Phase 5b.2 — Results

**Session goal (per the 5b split in [`phase-5-plan.md`](phase-5-plan.md)):**
`java -javaagent:postman-java-agent.jar HelloHttps` captures one REQ + one
RESP per HTTPS transaction on JDK 17.

**Branch:** `feat/https-capture-ebpf` (rolling PR #173).

**Outcome:** ✅ all four 5b.2 exit criteria green. 5b.3 hardening is
unblocked.

---

## TL;DR

- A real JDK `HttpsServer` driven by `curl` is now captured end-to-end:
  `curl https://127.0.0.1:8443/phase5b2` → `REQ method=GET url=/phase5b2`
  + `RESP status=200` in `apidump-javatls`.
- 1000 parallel HTTPS requests (50 in flight): **1000 / 1000 REQ + RESP
  parsed**, JVM survived, zero ringbuf drops, zero read failures, 1.46 s
  wall-clock.
- Agent attach overhead: **178 ms** (target ≤ 500 ms — 1/3 of budget).
- Shaded JAR is **4.7 MB** (target was ~1.5 MB; the diff is full
  ByteBuddy — strip-down deferred to 5c if it actually matters).

## What landed

```
java-agent/
├── build.gradle.kts                                         updated
└── src/main/java/com/postman/insights/agent/
    ├── Agent.java                                           new — premain
    ├── ebpf/NativeMemory.java                               updated — unpack-from-JAR + thread-local 64 KiB buffer + double-load tolerance
    ├── ebpf/IoctlPacket.java                                updated — sendThreadLocal() fast path
    ├── instrumentations/SSLEngineInst.java                  new — ByteBuddy wrap/unwrap advice + Hooks
    └── testdata/HelloHttps.java                             new — JDK HttpsServer + auto self-signed cert via keytool
```

### The 4-stage build

```
make -C src/main/c                                 → libpostman_jni.so
gradle --no-daemon shadowJar
   ├─ compileJava                                  → class files
   ├─ bootstrapJar                                 → build/bootstrap-libs/postman-java-agent-bootstrap.jar  (helper classes only, 19 KB)
   ├─ stageBootstrapAsBlob                         → build/bootstrap-blob/META-INF/postman-agent-bootstrap.jarblob  (renamed to opaque-blob extension)
   └─ shadowJar                                    → build/libs/postman-java-agent.jar  (4.7 MB shaded fat JAR)
                                                     ├── com/postman/insights/agent/**            agent + advice
                                                     ├── com/postman/insights/agent/shaded/bytebuddy/**   relocated
                                                     ├── META-INF/postman-agent-bootstrap.jarblob the bootstrap JAR (extracted at premain)
                                                     └── META-INF/native/linux-arm64/libpostman_jni.so
```

## The hard part — what was actually subtle

5b.2 looked like "drop in ByteBuddy advice and we're done." It wasn't.
The three issues that ate the bulk of the session:

### 1. Wrong method signature → silent no-op

JDK's `sun.security.ssl.SSLEngineImpl` does NOT override the convenience
two-arg `wrap(ByteBuffer, ByteBuffer)` / `unwrap(ByteBuffer, ByteBuffer)`.
Those are concrete on the abstract `SSLEngine` and delegate to:

```java
SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst)
SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length)
```

My initial matcher (cribbed from OBI, but their target class differs)
looked for the two-arg variants. ByteBuddy's listener showed
`TRANSFORM sun.security.ssl.SSLEngineImpl` cheerfully — but ZERO advice
applied, because the matcher matched nothing. **Lesson:** when
ByteBuddy says `TRANSFORM`, that means it visited the type; it does NOT
mean any of your matchers actually matched any method. Always confirm
events flow before trusting the listener output.

### 2. Cross-loader unreachability → `NoClassDefFoundError`-shaped silent failure

Advice methods get **inlined as bytecode** into the target class. Once
inlined, `Hooks.afterWrap(...)` becomes a real CONSTANT_Methodref inside
`sun.security.ssl.SSLEngineImpl` (loaded by the bootstrap class loader,
module `java.base`). The bootstrap loader cannot see classes in the app
class loader, so when the advice runs, it tries to resolve `Hooks` from
bootstrap → fails → silently swallowed by our `suppress = Throwable.class`.

**Standard fix:** put the helper classes on the bootstrap class loader.
Done via `Instrumentation.appendToBootstrapClassLoaderSearch(JarFile)`
in `Agent.premain`.

### 3. "But not too much on bootstrap" — loader-constraint LinkageError

First attempt: append the **whole** agent JAR to bootstrap. Result:

```
java.lang.LinkageError: loader constraint violation:
when resolving interface method
'…ElementMatcher$Junction.or(…ElementMatcher)'
the class loader 'app' of the current class, com/postman/insights/agent/Agent,
and the class loader 'bootstrap' for the method's defining class,
…ElementMatcher$Junction, have different Class objects for the type
…ElementMatcher used in the signature
```

`Agent` (app-loaded) called `ByteBuddy.or(...)`. The JVM looked up the
result type via two different loaders and found two different `Class`
objects — instant LinkageError.

**Fix:** split the agent into **two** JARs.

| JAR | What's in it | Where it lives at runtime |
| --- | --- | --- |
| `postman-java-agent.jar` (main, 4.7 MB) | `Agent`, `Main`, `SSLEngineInst` + advice classes, shaded ByteBuddy, native lib, embedded bootstrap blob | App class loader (via `-javaagent:` and `-cp`) |
| `postman-java-agent-bootstrap.jar` (19 KB) | `IoctlPacket`, `NativeMemory` (+ `$FinalizableBuffer` nested), `SSLEngineInst$Hooks`, libpostman_jni.so | Bootstrap class loader (extracted from main JAR's `META-INF/postman-agent-bootstrap.jarblob` at premain) |

ByteBuddy stays in **only** the app loader. JDK classes' inlined advice
calls into `Hooks` → bootstrap loader has it → resolves. Zero collision.

### 4. The shadow-plugin trap

The shadow Gradle plugin treats any `.jar` file passed to `from()` as a
JAR to MERGE, not as an opaque resource. My first attempt to embed the
bootstrap JAR as a resource quietly unzipped its contents into the main
JAR. **Workaround:** stage the bootstrap JAR under a `.jarblob`
extension so shadow doesn't recognise it, and rename back to `.jar`
semantics at runtime (file content is identical — just the filename
masks it from shadow's heuristic).

## Wire-format / API stability

All inherited from 5b.1 unchanged:

* 41-byte packed `java_packet` header — same.
* `IoctlPacket.sendOnce` — kept for the 5b.1 spike CLI (`Main`).
* `IoctlPacket.sendThreadLocal` — NEW, agent advice uses this. Reuses a
  per-thread 64 KiB off-heap buffer instead of `allocateMemory` per
  call.
* `NativeMemory.IOCTL_FD` / `IOCTL_MAGIC` — unchanged.

## Validation — full matrix

Ran in `pia-bpf-dev` on arm64 Linux with JDK 17.0.19. Listener is
`apidump-javatls`; workload is `HelloHttps` (JDK `HttpsServer` on
`127.0.0.1:8443`, auto-generated self-signed RSA cert via `keytool`).

| # | Test | Expected | Observed |
| --- | --- | --- | --- |
| 1 | Smoke: 3 curls against agent-attached HelloHttps | 3× REQ + 3× RESP, agent attaches < 500 ms | ✅ exact match, attach 178 ms |
| 2 | 1000 parallel curls (xargs `-P 50`) | 1000 REQ + 1000 RESP, no crashes, no ringbuf drops | ✅ 1000/1000, 1.46 s wall-clock, zero drops |
| 3 | RSS stability after load | bounded growth, no leak slope | RSS 145 MB → 259 MB (JIT + ByteBuddy class data + per-thread buffers; bounded, not growing per-request) |
| 4 | 5b.1 regression (`java -jar postman-java-agent.jar pair`) | unchanged from 5b.1 results | ✅ `REQ method=GET url=/phase5b1` + `RESP status=200`, emitted=2 bytes=190 |

### Sample output (smoke)

```
$ java -javaagent:postman-java-agent.jar -cp postman-java-agent.jar com.postman.insights.agent.testdata.HelloHttps
OpenJDK 64-Bit Server VM warning: Sharing is only supported for boot loader classes
[postman-insights] appended to bootstrap CL: /tmp/postman-agent-bootstrap-…jar
[postman-insights] agent attached via premain in 178 ms (args=)
HelloHttps: generating self-signed cert at /tmp/hello-https-keystore.p12
HelloHttps: listening on https://127.0.0.1:8443/phase5b2

$ for i in 1 2 3; do curl -sk https://127.0.0.1:8443/phase5b2; done

# meanwhile in another shell:
REQ  pid=ebpf-pid-208562 method=GET url=/phase5b2
RESP pid=ebpf-pid-208562 status=200
REQ  pid=ebpf-pid-208562 method=GET url=/phase5b2
RESP pid=ebpf-pid-208562 status=200
REQ  pid=ebpf-pid-208562 method=GET url=/phase5b2
RESP pid=ebpf-pid-208562 status=200
javatls-stats: emitted=9 ringbuf_drops=0 read_fail=0 bytes=663 bad_cmd=3
```

(The `emitted=9` for 3 requests means 6 of those events are the HTTPS
request/response themselves; the other 3 are TLS handshake `wrap`/
`unwrap` fragments that the akinet HTTP parser correctly ignores. The
`bad_cmd=3` is curl's `ioctl(0, TIOCGWINSZ, …)` for terminal-size
queries — one per `curl` process, unrelated to our magic ioctl.)

## Gotchas captured for future Java sessions

1. **ByteBuddy `TRANSFORM` log line ≠ advice applied.** Confirm by
   tracing actual byte flow, not by trusting the listener.
2. **JDK's `SSLEngine` two-arg methods are convenience wrappers.** All
   impls override only the 4-arg variants.
3. **Bootstrap append is mandatory for JDK-class advice.** Without it
   the failure is silent (suppressed by `Throwable` catch in advice).
4. **Don't append the whole agent JAR.** Split into a tiny bootstrap
   JAR with only the helper classes; keep ByteBuddy app-loader-only.
5. **shadow plugin unzips any `.jar` in `from()`.** Use a non-JAR
   extension (`.jarblob`) to embed a JAR as an opaque resource.
6. **Nested classes need wildcard includes in the bootstrap JAR.**
   `NativeMemory.class` alone is NOT enough — `NativeMemory$FinalizableBuffer.class`
   is referenced from `<clinit>` via the `ThreadLocal` initializer.
7. **`Executors.newFixedThreadPool` creates non-daemon threads.** A
   test workload using `HttpsServer.setExecutor(...)` will hang the JVM
   forever on `server.stop(0)` because the executor's idle workers
   keep the JVM alive. Either use a daemon `ThreadFactory` or
   `System.exit(0)` after stop. Bit us during 5b.2 development; cost ~20
   minutes of "why is the test hanging?".

## What 5b.3 inherits

* All public API stable (`IoctlPacket.sendThreadLocal`, `NativeMemory.*`,
  `Agent.premain` semantics, manifest attributes).
* Build pipeline is reproducible (single `gradle shadowJar`).
* Agent attach is a single self-contained operation; no external state.

## What 5b.3 still needs

* 10k-request soak test (we've done 1k; design wants ≥10k).
* Per-request overhead measurement (wallclock latency with and without
  agent). JMH is a 5c deliverable, not 5b.3.
* FD leak audit (`/proc/<pid>/fd` count stable across N requests).
* Crash-resilience: deliberately throw inside advice and confirm host
  HTTPS path is unaffected (`suppress = Throwable.class` test).

## Commands to reproduce

```sh
# In pia-bpf-dev:

cd /workspace/java-agent
make -C src/main/c                  # libpostman_jni.so
gradle --no-daemon shadowJar        # postman-java-agent.jar + bootstrap blob

JAR=/workspace/java-agent/build/libs/postman-java-agent.jar

# Terminal A — listener
cd /workspace
sudo bin/postman-insights-agent apidump-javatls --duration 60s

# Terminal B — workload (any of these)
java -javaagent:$JAR -cp $JAR com.postman.insights.agent.testdata.HelloHttps

# Terminal C — generate load
curl -sk https://127.0.0.1:8443/phase5b2                            # one request
seq 1 1000 | xargs -P 50 -I{} curl -sk https://127.0.0.1:8443/phase5b2  # 1000 parallel

# Diagnostics: turn on ByteBuddy listener
java -Dpostman.agent.debug=1 -javaagent:$JAR -cp $JAR com.postman.insights.agent.testdata.HelloHttps
```
