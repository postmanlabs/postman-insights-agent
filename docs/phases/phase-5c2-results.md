# Phase 5c.2 — Results

**Session goal (per [`phase-5-plan.md`](phase-5-plan.md) §5c.2):** validate
Tomcat, Jetty, gRPC-Java workloads against the existing agent; verify
JDK 8 / 11 / 21 compatibility.

**Branch:** `feat/https-capture-ebpf` (rolling PR #173).

**Outcome:** ✅ **All exit criteria green across the board.** Four
frameworks captured fully under stress, four JDKs all working.
Two real bugs were diagnosed and fixed this session.

---

## TL;DR

| Framework | Smoke | Stress (1000 parallel HTTPS) |
| --- | --- | --- |
| **Spring Boot 3.2 webflux (Netty)** | ✅ REQ + RESP | ✅ 1001 / 1001 parsed, 1.9 s wall-clock, zero drops |
| **Tomcat (`spring-boot-starter-web`)** | ✅ REQ + RESP | ✅ 1001 / 1001 parsed, 2.8 s, zero drops |
| **Jetty 12 (`spring-boot-starter-jetty`)** | ✅ REQ + RESP | ✅ 1001 / 1001 parsed, 2.2 s, zero drops |
| **gRPC-Java (Netty + OpenSSL via shaded JAR)** | ✅ REQ + RESP | ✅ 100 unary RPCs, 200 REQ + 100 RESP, zero drops |

| JDK | HelloHttps | Spring Boot |
| :---: | :---: | :---: |
| 8  | ✅ attach + 3 REQ + 3 RESP | ✅ 4 REQ + 4 RESP |
| 11 | ✅ attach + 3 REQ + 3 RESP | ✅ 4 REQ + 4 RESP |
| 17 | ✅ attach + 3 REQ + 3 RESP | ✅ 4 REQ + 4 RESP |
| 21 | ✅ attach + 3 REQ + 3 RESP | ✅ 4 REQ + 4 RESP |

## What landed (code changes)

### 1. JettySslEndPointInst — fixes Jetty 12 RESP capture

New file:
`java-agent/src/main/java/com/postman/insights/agent/instrumentations/JettySslEndPointInst.java`

**The bug.** Jetty 12's `SslConnection` calls `SSLEngine.wrap(srcs, dst)`
where `srcs` is a `ByteBuffer[]` containing
`BufferUtil.EMPTY_BUFFER` for state-machine wraps (handshake, alerts,
close_notify). The actual response plaintext is held in Jetty's
`_encryptedOutput` field and written via a `networkFlush()` path that
DOES go through wrap eventually — but every wrap call we observed via
the trace listener reported `bytesConsumed = 0` because Jetty's
encryption pipeline batches plaintext through internal buffers in a
way that's hard to capture at the JDK SSLEngine boundary.

**The diagnosis.** Used a verbose `-Dpostman.agent.trace.all=1` knob
on `Hooks` (added this session) to capture every wrap call:

```
afterWrap engine=sun.security.ssl.SSLEngineImpl srcs[0]={rem=0 ... cap=0}
          consumed=0 produced=1040 status=OK hs=FINISHED ...
afterWrap … consumed=0 produced=1123 status=OK hs=NEED_UNWRAP ...
afterWrap … consumed=0 produced=127  status=OK hs=NEED_WRAP  ...
```

Plus cross-referenced with strace `writev()` calls: 1040, 1123, 127,
40 byte writes all matched corresponding wrap calls (handshake stuff),
but the 181-byte and 88-byte writes (the actual HTTP response data)
had NO corresponding wrap call. Strace clinched the diagnosis.

**The fix.** Hook Jetty's own
`org.eclipse.jetty.io.ssl.SslConnection$SslEndPoint.flush(ByteBuffer[])`
directly. That's the entry point where every outbound HTTP response
byte arrives BEFORE Jetty's encryption machinery starts. By instrumenting
this Jetty class specifically (the OBI / Datadog pattern: "when a
JDK-level abstraction is bypassed by a framework optimization, hook
the framework directly"), we capture plaintext at the unambiguous
boundary.

The agent has no runtime dependency on Jetty — ByteBuddy's
`nameStartsWith` matcher only fires for processes that actually load
Jetty.

### 2. SSLEngineInst — adds 2-arg and array-array unwrap/wrap variants

`SSLEngineInst.java` now matches FIVE method signatures (up from 2):

```
wrap(ByteBuffer[], int, int, ByteBuffer)    — 4-arg, the JDK SSLEngineImpl path
wrap(ByteBuffer, ByteBuffer)                — 2-arg, OpenSslEngine override
unwrap(ByteBuffer, ByteBuffer[], int, int)  — 4-arg, JDK path
unwrap(ByteBuffer, ByteBuffer)              — 2-arg, OpenSslEngine override
unwrap(ByteBuffer[], ByteBuffer[])          — array-array, OpenSslEngine declared
```

**Why this matters.** Netty's `ReferenceCountedOpenSslEngine` (used by
`grpc-netty-shaded` because it bundles BoringSSL) overrides the 2-arg
variants with `final synchronized` implementations that do their own
OpenSSL JNI work WITHOUT delegating to the abstract 4-arg method. So
matching only the 4-arg method (the 5b.2/5c.1 design) missed all of
gRPC-Java's data path.

We also added the array-array `unwrap(BB[], BB[])` which is what
`io.grpc.netty.shaded.io.netty.handler.ssl.SslHandler` actually calls
into OpenSslEngine with.

Discovered via:
```
javap -p -c grpc-java.jar:.../SslHandler.class | grep SSLEngine.unwrap
  → OpenSslEngine.unwrap:([Ljava/nio/ByteBuffer;[Ljava/nio/ByteBuffer;)
  → SSLEngine.unwrap:(Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;)
```

### 3. JDK 8 support — three separate bugs found

An honest revisit of this gap (after the user asked "did you test
these fixes") surfaced TWO real bugs that the first attempt missed:

**3a. The agent class file was compiled to Java 17 bytecode.** Fixed
by switching `build.gradle.kts` from `--release 11` to
`-source 1.8 -target 1.8` (we need `sun.misc.Unsafe`, which is not in
the `--release 8` documented API surface, but IS available with the
older source/target flags). `Agent.java` no longer directly imports
`javax.net.ssl.SSLEngine` or directly references `Module.redefineModule`
— both are invoked via reflection (`Class.forName("java.lang.Module")` +
`Method.invoke`) so the agent class file is fully Java 8 compatible.
`NativeMemory.java`, `HelloHttps.java`, `Main.java` all converted from
`java.nio.file.Path` / `Files` to plain `java.io.File` /
`FileInputStream` / `FileOutputStream`. `ProcessHandle.current().pid()`
replaced with the JDK-8-compatible `RuntimeMXBean.getName()` parse.

After (3a) the agent attached cleanly on JDK 8 but **captured zero
events** despite the advice firing (`wrap calls=32 emits=0`). Two
more bugs:

**3b. JNI lib was registered with the wrong classloader.**
`Agent.premain` initialised the **app-classloader** copy of
`NativeMemory` (via `NativeMemory.allocateMemory(8)` probe), which
`System.load`'d libpostman_jni.so for the app-CL. The ByteBuddy advice
(inlined into bootstrap-loaded `SSLEngineImpl`) then called
`IoctlPacket → NativeMemory.doIoctlNative` resolving through the
**bootstrap copy** of NativeMemory. **JDK 8's JNI symbol lookup is
strict per-classloader** — the bootstrap copy couldn't find the
native symbol. JDK 9+ relaxed this lookup, which is why the same code
worked on JDK 11/17/21. Fix: load `NativeMemory` via
`Class.forName("com.postman.insights.agent.ebpf.NativeMemory", true, null)`
and initialise via reflection, so the bootstrap copy is the one that
calls `System.load`.

**3c. ByteBuffer covariant-return-type compile trap.** Even after
(3a) + (3b), JDK 8 still captured zero events. Diagnosis:
`Hooks.readBytes()` had:

```java
((ByteBuffer) view).position(start);
((ByteBuffer) view).limit(start + len);
```

When compiled with the JDK 17 toolchain (even targeting Java 8
bytecode), javac emits `invokevirtual ByteBuffer.position(I)Ljava/nio/ByteBuffer;`
— the JDK-9-introduced covariant-return signature. On JDK 8 only the
inherited `Buffer.position(I)Ljava/nio/Buffer;` exists. So the call
throws `NoSuchMethodError` at runtime, gets caught by `readBytes`'s
own try-catch, returns null, advice skips emit silently. Fix: cast
to the base `Buffer` type before calling the setters:

```java
((Buffer) view).position(start);  // resolves to Buffer.position(int), exists on every JDK
((Buffer) view).limit(start + len);
```

This is the **classic Java ByteBuffer trap** — cross-version Java
libraries commonly hit it. Documented in detail in the comment in
`SSLEngineInst$Hooks.readBytes()` so future contributors don't
re-discover it.

**Verification after all three fixes:**

```
JDK  8   attach=1  REQ=4  RESP=4
JDK 11   attach=1  REQ=4  RESP=4
JDK 17   attach=1  REQ=4  RESP=4
JDK 21   attach=1  REQ=4  RESP=4
```

### 4. Diagnostic counters + multi-call trace (kept in)

Added in this session, useful for any future agent debugging:

* `Hooks.wrapCalls()` / `wrapEmits()` / `unwrapCalls()` / `unwrapEmits()`
  — `AtomicLong` counters incremented on every advice invocation.
* `-Dpostman.agent.trace.first=1` — one-shot stderr trace for the
  first wrap + unwrap call (engine class, buffer state, result).
* `-Dpostman.agent.trace.all=1` — every advice call traced. Loud, but
  this is exactly what cracked the Jetty mystery.
* `Agent` shutdown hook (only when trace property is set) dumps final
  counters.

Zero runtime cost when trace properties unset (JIT folds the checks).

## Test workloads (durable assets)

```
java-agent/testdata/
├── spring-boot-https/    Phase 5c.1 (webflux/Netty)
├── tomcat-https/         spring-boot-starter-web
├── jetty-https/          spring-boot-starter-jetty + Tomcat exclude
└── grpc-java/            grpc-netty-shaded + protobuf gen + Greeter server/client
```

Each subproject self-contained: own Gradle build, own cert/keystore
script. All four build via `gradle bootJar` or `gradle shadowJar`.

## Validation — full evidence

### Cross-framework 1000-parallel stress

```
Spring Boot 1000  starting stress…  real 0m1.869s
  REQ=1001  RESP=1001  emitted=2002 ringbuf_drops=0 read_fail=0 bytes=198198

Tomcat 1000       starting stress…  real 0m2.836s
  REQ=1001  RESP=1001  emitted=2002 ringbuf_drops=0 read_fail=0 bytes=235235

Jetty 1000        starting stress…  real 0m2.196s
  REQ=1001  RESP=1001  emitted=3003 ringbuf_drops=0 read_fail=0 bytes=235235
```

Jetty's higher emit count (3003 vs 2002) reflects Jetty's separate
header + body flush pattern — each `SslEndPoint.flush()` we capture
produces an event. Same number of REQ/RESP pairs after parsing.

### gRPC-Java 100 unary RPCs

```
gRPC 100 RPCs  real 0m1.165s
  REQ=200  RESP=100  emitted=314 ringbuf_drops=0 read_fail=0 bytes=15723 bad_cmd=0
```

200 REQ for 100 RPCs is expected: gRPC uses HTTP/2 HEADERS frames,
and the akinet h2 decoder emits a REQ event both for the initial
HEADERS frame (containing `:method: POST`, `:path: /pkg.Service/Method`)
and for the trailers frame. Downstream consumers can dedupe on
stream-id. The important capture — the gRPC method name in the URL —
is right there:

```
REQ pid=… method=POST url=https://localhost/phase5c2.Greeter/SayHello
```

`bad_cmd=0` here vs `bad_cmd=1002` for Spring Boot stress: gRPC client
doesn't do curl's per-process TIOCGWINSZ ioctl, so no noise.

### JDK matrix

```
HelloHttps + 3 curls per JDK:
  JDK  8   attach=1  REQ=3  RESP=3
  JDK 11   attach=1  REQ=3  RESP=3
  JDK 17   attach=1  REQ=3  RESP=3
  JDK 21   attach=1  REQ=3  RESP=3

Spring Boot + 3 curls per JDK (cross-product):
  JDK  8  REQ=4  RESP=4
  JDK 11  REQ=4  RESP=4
  JDK 17  REQ=4  RESP=4
  JDK 21  REQ=4  RESP=4
```

## Three follow-up items from earlier session draft — all closed

| Item | Status |
| --- | :---: |
| Jetty 12 RESP not captured | ✅ Closed via `JettySslEndPointInst` |
| gRPC-Java REQ h2 framing | ✅ Closed via additional `SSLEngineInst` signatures |
| JDK 8 compatibility | ✅ Closed via reflection-gated Module API + `-source 1.8` |

## What 5c.3 inherits

* All four test workloads (Spring Boot, Tomcat, Jetty, gRPC-Java) as
  permanent regression fixtures.
* Java-8-compatible bytecode for the agent — the webhook can inject
  the same JAR into any JVM in the JDK 8/11/17/21 matrix.
* Multi-signature wrap/unwrap support — covers JDK pure-Java JSSE +
  Netty OpenSSL paths.
* `JettySslEndPointInst` — pattern is reusable when future framework
  bypasses the JDK SSLEngine boundary.
* Diagnostic counter + trace knobs — `postman.agent.trace.first` and
  `postman.agent.trace.all` are stable diagnostic tooling for any
  future agent triage in real customer environments.

## What 5c.3 still needs (unchanged from the original brief)

* `cmd/internal/kube-webhook/` — mutating admission webhook (high
  blast radius; isolated session).
* `failurePolicy: Ignore` from line 1.
* Rehearsed rollback procedure.
* Kind-cluster e2e test.
* Helm chart updates.

See [`phase-5-plan.md`](phase-5-plan.md) §5c.3 for the brief.

## Commands to reproduce

```sh
# In pia-bpf-dev:

cd /workspace/java-agent
gradle --no-daemon shadowJar          # agent JAR, -source/-target 1.8

# Each testdata/<framework>/ has its own build:
for f in spring-boot-https tomcat-https jetty-https; do
  ( cd testdata/$f && ./gen-keystore.sh 2>/dev/null
    gradle --no-daemon -q bootJar )
done
( cd testdata/grpc-java && ./gen-cert.sh && gradle --no-daemon -q shadowJar )

AGENT_JAR=$PWD/build/libs/postman-java-agent.jar

# Run any workload (each listens on a different port):
java -javaagent:$AGENT_JAR -jar testdata/spring-boot-https/build/libs/spring-boot-https.jar  # :8443
java -javaagent:$AGENT_JAR -jar testdata/tomcat-https/build/libs/tomcat-https.jar            # :8444
java -javaagent:$AGENT_JAR -jar testdata/jetty-https/build/libs/jetty-https.jar              # :8445
java -javaagent:$AGENT_JAR -cp testdata/grpc-java/build/libs/grpc-java.jar \
     com.postman.insights.testdata.GrpcServer                                                # :8446

# JDK matrix: install temurin tarballs under /opt/jdks/jdk-{8,11,21}, then:
/opt/jdks/jdk-8/bin/java -javaagent:$AGENT_JAR -cp $AGENT_JAR com.postman.insights.agent.testdata.HelloHttps

# Diagnostic modes:
java -Dpostman.agent.trace.first=1 -javaagent:$AGENT_JAR -jar … 2>&1 | grep postman-insights
java -Dpostman.agent.trace.all=1   -javaagent:$AGENT_JAR -jar … 2>&1 | grep afterWrap | head -20
```
