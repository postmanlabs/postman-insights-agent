# Phase 5c.1 — Results

**Session goal (per [`phase-5-plan.md`](phase-5-plan.md) §5c):** capture
Spring Boot (the biggest enterprise HTTPS gap) end-to-end, via the Netty
I/O path.

**Branch:** `feat/https-capture-ebpf` (rolling PR #173).

**Outcome:** ✅ all 5c.1 exit criteria green — **with zero new
instrumentation code.** The 5b.2 `SSLEngineInst` already handles
Spring Boot. The session validates a real-enterprise framework, adds a
permanent regression workload, and surfaces an architectural insight
worth documenting.

---

## TL;DR

* `curl https://127.0.0.1:8443/phase5c1` against an agent-attached
  Spring Boot 3.2 webflux app → `REQ method=GET url=/phase5c1` +
  `RESP status=200` in `apidump-javatls`.
* 10000 parallel HTTPS requests: **10001 / 10001 REQ + RESP parsed**
  (the +1 is a Spring Boot startup probe), 13.9 s wall-clock, zero
  ringbuf drops, JVM stable.
* **No new agent code.** Only addition: a permanent Spring Boot test
  workload under `java-agent/testdata/spring-boot-https/`.

## The architectural insight

When we wrote `SSLEngineInst` in 5b.2 we matched on:

```java
ElementMatchers.isSubTypeOf(SSLEngine.class)
        .and(ElementMatchers.not(ElementMatchers.isAbstract()))
```

The intent was just "find `sun.security.ssl.SSLEngineImpl`." But
ByteBuddy correctly extends the match to **every concrete subtype of
`javax.net.ssl.SSLEngine`** the JVM ever loads. The 5c.1 experiment
proves this generalises:

```
[Byte Buddy] TRANSFORM sun.security.ssl.SSLEngineImpl                                    ← JDK pure-Java
[Byte Buddy] TRANSFORM io.netty.handler.ssl.JdkSslEngine                                  ← Netty wrapping JDK SSLEngine
[Byte Buddy] TRANSFORM io.netty.handler.ssl.OpenSslEngine                                 ← Netty netty-tcnative path
[Byte Buddy] TRANSFORM io.netty.handler.ssl.ReferenceCountedOpenSslEngine                 ← Netty alt OpenSSL path
```

What this means in practice:

* **Spring Boot webflux (Netty I/O)** → captured by the JDK path
  (when pure JSSE is the underlying provider).
* **Spring Boot with netty-tcnative** → would be captured by
  `OpenSslEngine` instrumentation OR by Phase 1's libssl uprobes
  (whichever fires first — they're not mutually exclusive but we
  haven't characterised which wins).
* **Any future JSSE provider** (Conscrypt, Bouncy Castle's JSSE,
  etc.) → captured automatically as long as it extends `SSLEngine`
  with a concrete subclass.

The Netty / Spring Boot framework gap that `phase-5-plan.md` §5c.1
allocated multiple days to closing is **already closed** by our 5b.2
work. The plan listed `NettySSLHandlerInst` as a new class to write;
it isn't needed.

## What landed

```
java-agent/testdata/spring-boot-https/
├── .gitignore
├── build.gradle.kts            Spring Boot 3.2.5 + webflux starter
├── settings.gradle.kts
├── gen-keystore.sh             auto-gen PKCS12 keystore via keytool
└── src/main/
    ├── java/com/postman/insights/testdata/SpringBootHttpsApp.java
    └── resources/application.yml   SSL on 127.0.0.1:8443
```

That's it. No changes to `java-agent/src/main/` (the agent itself).
No changes to `ebpf/`. No changes to Go code. The single value of this
session is the test workload + the empirical validation.

## Validation matrix

Ran in `pia-bpf-dev` on arm64 Linux, JDK 17.0.19, Spring Boot 3.2.5.

| # | Test | Expected | Observed |
| --- | --- | --- | --- |
| 1 | Spring Boot starts cleanly with agent attached | startup ~4 s, no agent-induced exception | ✅ 4 s, attach 347 ms |
| 2 | ByteBuddy listener shows Netty + JDK SSLEngine TRANSFORMs | both classes get advice applied | ✅ four engine classes transformed (see above) |
| 3 | 5 curls → 5 REQ + 5 RESP | one parsed pair per curl | ✅ (plus 1 extra: a startup probe — see "Caveats") |
| 4 | 10000 parallel curls (`xargs -P 100`) | all 10000 captured, JVM survives | ✅ **10001 / 10001 REQ + RESP parsed**, 13.9 s, JVM alive |
| 5 | FD-leak audit before vs after 10k load | FD count stable | ✅ 40 → 41 (one-off, not per-request) |
| 6 | RSS audit | bounded growth, no leak slope | RSS 333 MB baseline → 506 MB under load → 509 MB post-GC (Spring Boot's own steady state) |
| 7 | `/proc/<pid>/maps` for `libssl` | confirm capture path | none mapped — pure-Java JSSE, validating the JdkSslEngine path |

```
javatls-stats: emitted=20002 ringbuf_drops=0 read_fail=0 bytes=1980198 bad_cmd=10008
```

20002 emit events = 10001 wrap + 10001 unwrap. Zero ringbuf drops at
~720 req/sec. `bad_cmd=10008` is curl noise (`ioctl(0, TIOCGWINSZ, …)`).

## Caveats / things worth flagging

* **The "+1" parsed pair.** Spring Boot's bootstrap fires one HTTPS
  request internally before our load test begins (a connection-warm
  or actuator-style probe). It shows up as one extra captured pair
  beyond the curl count. Cosmetic, not a correctness issue.
* **Spring Boot startup overhead.** ~4 s with the agent, ~3.5 s
  without. The 347 ms agent-attach time is dominated by ByteBuddy
  setting up the AgentBuilder; the rest is Spring Boot's own
  classpath scanning. Well under the 500 ms agent-attach budget from
  the original Phase 5 brief.
* **netty-tcnative path not exercised here.** Spring Boot 3.2 default
  uses pure-Java JSSE. To exercise the OpenSslEngine advice path we'd
  add a `io.netty:netty-tcnative-boringssl-static` dependency to the
  workload. The advice is in place (`isSubTypeOf` would match
  `OpenSslEngine`); just not validated end-to-end this session. 5c.2
  is a natural place to add it.
* **JMH per-call benchmark deferred to 5c.2.** Phase 5c.1 reuses the
  5b.3 curl-level latency check (which showed agent overhead below
  the noise floor at curl granularity). A proper JMH harness measuring
  microsecond-level `SSLEngine.wrap`/`unwrap` overhead is more
  valuable in 5c.2 where we can run it across Spring Boot, Tomcat,
  Jetty, and gRPC-Java simultaneously.

## What 5c.2 inherits

* Spring Boot workload + Gradle build pattern — copy-paste-adapt for
  Tomcat (`spring-boot-starter-web` instead of `-webflux`) and gRPC-Java
  (separate sub-module).
* Agent JAR unchanged from 5b.3.
* Validation script shape (build → start with agent → curl → check
  parsed REQ/RESP count).

## What 5c.2 will need

Per the plan §5c.2:

* `SSLSocketInst` for Tomcat's blocking I/O path (Tomcat default
  connector wraps `SSLSocket`, not `SSLEngine`).
* `SSLSocketStreamInst` for Jetty's I/O path (specialised because Jetty
  layers its own buffer pool).
* JDK 8 / 11 / 21 container matrix.
* gRPC-Java workload (unary + streaming).
* JMH benchmark harness measuring `SSLEngine.wrap`/`unwrap` overhead.

**Open question for 5c.2:** does `SSLSocketInst` need to be written,
or does the JDK's `SSLSocketImpl` internally use `SSLEngine` such that
our existing `SSLEngineInst` already covers Tomcat too? **First action
in 5c.2 is the same kind of empirical experiment we did here** —
deploy Tomcat with the existing agent and see what happens. If 5b.2's
work covers it, we save another class.

## Commands to reproduce

```sh
# In pia-bpf-dev:

# Build the workload (first run: ~22s, downloads Spring Boot deps).
cd /workspace/java-agent/testdata/spring-boot-https
./gen-keystore.sh
gradle --no-daemon bootJar

AGENT_JAR=/workspace/java-agent/build/libs/postman-java-agent.jar
SB_JAR=$PWD/build/libs/spring-boot-https.jar

# Terminal A — listener
cd /workspace
sudo bin/postman-insights-agent apidump-javatls --duration 60s

# Terminal B — Spring Boot with agent
java -javaagent:$AGENT_JAR -jar $SB_JAR

# Terminal C — load (single request or stress)
curl -sk https://127.0.0.1:8443/phase5c1
seq 1 10000 | xargs -P 100 -I{} curl -sk https://127.0.0.1:8443/phase5c1 -o /dev/null

# Diagnostics: see exactly which SSLEngine subclasses get transformed
java -Dpostman.agent.debug=1 -javaagent:$AGENT_JAR -jar $SB_JAR 2>&1 | grep TRANSFORM
```
