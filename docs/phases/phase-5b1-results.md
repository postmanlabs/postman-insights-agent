# Phase 5b.1 — Results

**Session goal (per the 5b split in [`phase-5-plan.md`](phase-5-plan.md)):**
prove the Java→JNI→ioctl→kernel→adapter bridge end-to-end with the
smallest possible Java program. No ByteBuddy, no SSLEngine, no
instrumentation. The Java-side analogue of `harness.c`.

**Branch:** `feat/https-capture-ebpf` (rolling PR #173).

**Outcome:** ✅ all four exit criteria green on the first end-to-end
run. Phase 5b.2 (ByteBuddy + `SSLEngineInst`) is unblocked.

---

## What landed

### Dev container

| File | Change |
| --- | --- |
| `build-scripts/Dockerfile.dev` | + `openjdk-17-jdk-headless`, + `unzip`, + Gradle 8.7, + `JAVA_HOME=/usr/lib/jvm/default-java` (materialised via `dpkg --print-architecture` so it works on amd64 + arm64), + `JAVA_HOME/bin` on PATH. |

Rebuild once with `./build-scripts/dev-container.sh build`; the JDK and
JNI headers are then permanent. No impact on the existing libssl / Go
toolchain.

### New `java-agent/` project

```
java-agent/
├── build.gradle.kts                                  Gradle Kotlin DSL
├── settings.gradle.kts
└── src/main/
    ├── c/
    │   ├── Makefile                                  builds libpostman_jni.so
    │   └── postman_jni.c                             JNI shim → ioctl(2)
    └── java/com/postman/insights/agent/
        ├── Main.java                                 spike entry point (this session)
        └── ebpf/
            ├── IoctlPacket.java                      41-byte packed layout + send()
            └── NativeMemory.java                     Unsafe + System.loadLibrary glue
```

* `Main.java` understands `pair` (default), `send`, `recv`,
  `wrong-cmd`, `bad-op`, `burst N`.
* JNI returns are 64-bit packed (`high32=errno, low32=rc`) so the spike
  prints meaningful diagnostics with no extra cross-language hop.
* Off-heap memory via `sun.misc.Unsafe` (works JDK 8–21 with no
  preview flags or `--add-opens` on JDK 17). 5c will add a
  `MemorySegment` fast-path for JDK 21+ if measurements justify it.
* No native-lib unpack-from-JAR yet — pass the path explicitly via
  `-Djava.library.path=…` or `-Dpostman.agent.native.lib=/abs/path`.
  That trick lands in 5b.2 once we need to ship a single artefact.

## Wire format (frozen — same as 5a)

The Java side writes the exact 41-byte packed header the kernel kprobe
expects: `op` (1) + `s_addr` (16) + `d_addr` (17) + `s_port` (2) +
`d_port` (2) + `buf_len` (4) + buffer. Little-endian for the multi-byte
ints (matches host order on amd64 + arm64; the kernel BPF program
treats these as opaque hash inputs).

`Static_assert`-style guarantees:
* `IoctlPacket.HEADER_SIZE == 41` (a Java constant; tests in 5b.2 will
  assert this).
* The C-side BPF program uses the same `JP_OFF_*` offsets; documented
  in `java_tls.bpf.c` and `phase-5a-results.md`.

## Validation — full test matrix

Ran in `pia-bpf-dev` on arm64 Linux 6.x with JDK 17.0.19:

| # | Test | Expected | Observed |
| --- | --- | --- | --- |
| 1 | Happy path: `Main.java pair` → SEND + RECV via JNI | 1× `REQ method=GET url=/phase5b1`, 1× `RESP status=200`, `emitted=2, bytes=190, drops=0` | ✅ exact match |
| 2 | `wrong-cmd` (cmd=0xDEAD from JVM) | 0 events, `bad_cmd` counter increments, JNI returns errno=25 (ENOTTY) | ✅ `emitted=0, bad_cmd=1, rc=-1, errno=25` |
| 3 | `bad-op` (op=99, magic cmd) | 0 events, no counter movement (silent skip by design) | ✅ `emitted=0, bad_cmd=0` |
| 4 | Burst 1000 pairs in a single JVM | 2000 events emitted, all parsed, no drops | ✅ `emitted=2000, bytes=190000, ringbuf_drops=0`; 1000 REQ + 1000 RESP parsed; 58 ms wall-clock |

The burst result is **strictly better than the C harness** of 5a: the
JVM's natural per-`ioctl()` latency (~30 µs/pair through JNI) lets the
userspace ringbuf reader drain in real time, so we lose zero events
even at 1000-pair load. The C harness's 900k evt/s saturated the
ringbuf; a real JVM at ~17k evt/s does not.

## Validation evidence (raw output)

```
### TEST 1 — happy path
postman-java-agent spike: pid=188501 mode=pair done
REQ  pid=ebpf-pid-188501 method=GET url=/phase5b1
RESP pid=ebpf-pid-188501 status=200
javatls-stats: emitted=2 ringbuf_drops=0 read_fail=0 bytes=190 bad_cmd=0

### TEST 2 — wrong-cmd
ioctl(0, 0xdead, op=1) rc=-1 errno=25
javatls-stats: emitted=0 ringbuf_drops=0 read_fail=0 bytes=0 bad_cmd=1

### TEST 3 — bad-op
ioctl(0, 0xb10b1, op=99) rc=-1 errno=25
javatls-stats: emitted=0 ringbuf_drops=0 read_fail=0 bytes=0 bad_cmd=0

### TEST 4 — burst 1000
real  0m0.058s
Parsed REQ:  1000
Parsed RESP: 1000
javatls-stats: emitted=2000 ringbuf_drops=0 read_fail=0 bytes=190000 bad_cmd=0
```

## Gotchas hit & resolved

1. **Gradle's default `javac` charset is US-ASCII** on minimal Linux
   containers. Em-dashes / non-ASCII in source comments break the
   compile. Fix: `tasks.withType<JavaCompile>().configureEach {
   options.encoding = "UTF-8" }` in `build.gradle.kts`. Worth doing on
   every Java project.
2. **`openjdk-17-jdk-headless` does NOT create `/usr/lib/jvm/default-java`.**
   The full `openjdk-17-jdk` package does (via `update-alternatives`).
   We materialise the symlink ourselves in `Dockerfile.dev` so the
   per-arch path is hidden from `JAVA_HOME` users.
3. **JNI return value packing.** We pack `errno` into the high 32 bits
   of the `jlong` return so the spike can print useful errno strings
   without a second JNI hop. Pattern is worth keeping for 5b.2.
4. **`ioctl(0, magic, …)` returns -1/ENOTTY by design.** The kernel
   doesn't have a handler for our magic command; the kprobe runs first
   and emits the ringbuf event. The Java-side log line "rc=-1 errno=25"
   is the expected successful path, not a failure.

## What 5b.2 inherits (no work required)

* `IoctlPacket.send(...)` API — ByteBuddy advice will call this from
  `SSLEngine.wrap()` / `unwrap()` exit hooks. Same signature.
* `NativeMemory` — library loading, allocator, byte/u16/u32 putters.
  Thread-local buffer pool sits on top; the underlying `allocateMemory`
  call doesn't change.
* JNI shim — unchanged for 5b.2. Stable interface.
* Gradle build skeleton — 5b.2 adds the ByteBuddy dependency and a
  `Premain-Class:` manifest entry; the rest is in place.

## What 5b.2 still needs

* `Agent.premain(String, Instrumentation)` entry point + manifest
  attribute.
* ByteBuddy dependency in `build.gradle.kts` (probably shaded into the
  JAR via `com.github.johnrengelman.shadow` plugin).
* `SSLEngineInst` — advice on `wrap(ByteBuffer src, ByteBuffer dst)`
  and `unwrap(ByteBuffer src, ByteBuffer dst)`.
* `SocketChannelExtractor` — get remote address from the engine's
  owning channel (OBI's `NettyChannelExtractor` minus the Netty parts).
* Off-heap thread-local 64 KiB buffer (instead of per-call
  `allocateMemory`).
* One workload: `HelloHttps.java` using JDK's built-in
  `HttpsServer.create(...)`. No Spring Boot / Tomcat / Netty.
* End-to-end: `java -javaagent:postman-java-agent.jar HelloHttps`
  captures one REQ + RESP per HTTPS transaction.

See [`phase-5-plan.md`](phase-5-plan.md) §"Session 5b.2" (updated this
session) for the full brief.

## Commands to reproduce

```sh
# In pia-bpf-dev (rebuild it if needed via build-scripts/dev-container.sh build):

cd /workspace/java-agent
make -C src/main/c
gradle --no-daemon -q build

JAR=build/libs/postman-java-agent.jar
NATLIB=src/main/c/build

# Happy path (two shells):
cd /workspace && sudo bin/postman-insights-agent apidump-javatls --duration 10s
java -Djava.library.path=java-agent/$NATLIB -jar java-agent/$JAR pair

# Negative tests:
java -Djava.library.path=java-agent/$NATLIB -jar java-agent/$JAR wrong-cmd
java -Djava.library.path=java-agent/$NATLIB -jar java-agent/$JAR bad-op

# Burst stress:
java -Djava.library.path=java-agent/$NATLIB -jar java-agent/$JAR burst 1000
```
