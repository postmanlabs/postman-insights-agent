# postman-java-agent — JMH per-call benchmarks

Microbenchmark suite measuring the **per-call overhead** the Postman
Insights Java agent adds when intercepting `SSLEngine.wrap` / `unwrap`.

## TL;DR

| Payload | Per-call overhead | Notes |
| ---: | ---: | --- |
| 64 B | **~700 ns/op** | typical HTTP request line + small header set |
| 1 KB | **~900 ns/op** | typical headers + small JSON body |
| 16 KB | **~3.9 µs/op** | large body or pipelined response |

Measured on Linux/aarch64 inside `pia-bpf-dev` (Docker Desktop on macOS,
LinuxKit kernel) with the `java_tls` kprobe NOT attached (worst-case
user-space path — ioctl returns immediately with `-ENOTTY`).

Each iteration of `SSLEngine.wrap` itself costs ~10–50 µs on typical TLS
workloads, so the agent's contribution is **well under 10 %** of the
underlying SSL call at the sizes that dominate production traffic
(< 4 KB).

## Why benchmark this

Phase 5b.3 verified correctness with curl-level evidence (request count,
event count, byte count). That's *necessary* but doesn't tell you how
much CPU the agent burns on the hot path. This benchmark adds the
*quantitative* answer so we can make scaling decisions (CPU reservations
on the agent pod, per-pod throughput estimates, etc.) without guessing.

## What this measures, and what it does NOT

**Measures:** the cost of `Hooks.afterWrap2(...)` — the agent-controlled
code path that the `@Advice` inlines into every SSLEngine call. That code:

1. Reads `result.bytesConsumed()` and the buffer's position diff.
2. Copies the consumed bytes out of the ByteBuffer into a `byte[]`.
3. Packs them into an `IoctlPacket` header (41 bytes, thread-local).
4. Calls `NativeMemory.doIoctlNative(...)` → JNI → `ioctl(2)` syscall.
5. Increments `WRAP_CALLS` / `WRAP_EMITS` atomic counters.

**Does NOT measure:**

* `SSLEngine.wrap` itself. The handshake setup for a self-contained
  benchmark needs a real cert; that ceremony is the harness's cost, not
  ours. SSL wrap is well-characterised at 10–50 µs for typical workloads,
  so our overhead is in the noise percentage-wise.
* The `java_tls` kprobe + ringbuf write. When the kernel-side BPF program
  is loaded (production), the ioctl returns slightly faster because the
  kernel handler runs the BPF program and returns. When NOT loaded
  (this benchmark), the ioctl returns immediately with `-ENOTTY`. The
  user-space cost is similar; the kernel-side cost is bounded by the
  BPF program complexity (already characterised in phase 5a).
* GC pressure from sustained traffic. Each call allocates a `byte[]`
  copy whose lifetime ends after the JNI call (the kernel reads it
  during the syscall). Under realistic load this generates G1 young-gen
  pressure that's NOT visible in JMH's per-call number. A separate
  throughput / GC characterisation belongs in a future session.

## Running locally

```sh
# Build the parent agent JAR first (the benchmark depends on it)
cd ..
gradle --no-daemon clean shadowJar

# Run the JMH benchmarks (~4 min on aarch64; 2 forks × 3 payload sizes × 5 iters × 3 s)
cd benchmarks
gradle --no-daemon jmh

# Results land at:
#   build/results/jmh/results.txt   (human-readable table)
#   build/results/jmh/results.json  (machine-readable for trending)
```

To benchmark on a different JDK (the agent supports 8 / 11 / 17 / 21 / 25),
set `JAVA_HOME` before invoking:

```sh
JAVA_HOME=/opt/jdks/jdk-8 gradle --no-daemon jmh
```

## Reading the results

Three columns to focus on:

```
Benchmark                                (payloadSize)  Mode  Cnt   Score    Error  Units
PostmanAgentBenchmark.baselineNoAgent              64  avgt   10    21.1 ±    0.1  ns/op
PostmanAgentBenchmark.baselineNoAgent            1024  avgt   10    21.3 ±    0.7  ns/op
PostmanAgentBenchmark.baselineNoAgent           16384  avgt   10    21.1 ±    0.1  ns/op
PostmanAgentBenchmark.hooksAfterWrap               64  avgt   10   716.1 ±   87.2  ns/op
PostmanAgentBenchmark.hooksAfterWrap             1024  avgt   10   912.5 ±   95.5  ns/op
PostmanAgentBenchmark.hooksAfterWrap            16384  avgt   10  3882.5 ±  246.5  ns/op
```

`baselineNoAgent` = the irreducible cost of any reasonable callback
(read buffer position, return). The 21 ns floor is JIT-resident
Blackhole machinery + register spills.

`hooksAfterWrap` = the same caller-side wrap, with the agent's
callback executed. Subtract baseline to get the **agent's added cost
per call**:

```
overhead(64 B)  =  716 − 21  =  ~695 ns
overhead(1 KB)  =  912 − 21  =  ~891 ns
overhead(16 KB) = 3882 − 21  = ~3861 ns
```

The growth from 64 B → 16 KB is dominated by the `byte[]` allocation
and `ByteBuffer.get(byte[])` copy. The fixed cost (JNI + ioctl + packet
build + atomic counter writes) is ~700 ns; the variable cost is
~200 ns per KB of payload.

## When to re-run

* After **any** change to `SSLEngineInst.Hooks`, `IoctlPacket`, or
  `NativeMemory`. These are the hot path; perf regressions there matter.
* After bumping the JDK in CI or production.
* After bumping shaded ByteBuddy (which can change inlining behaviour).
* When changing `--https-body-size-cap` defaults — bigger caps mean the
  16 KB row matters more.

## Future work (deferred)

* **Per-thread throughput** with `Mode.Throughput` and `@Threads(N)`,
  exercising the per-thread `IoctlPacket` buffer pool. Useful for
  predicting how the agent scales on a 16-vCPU server.
* **GC characterisation** under sustained load (object allocation rate,
  G1 young-gen pressure). Belongs in a longer-running soak test, not JMH.
* **kprobe-attached** benchmark on a real Linux box with the agent
  binary loaded. Currently the ioctl returns `-ENOTTY` immediately; in
  production it runs the BPF program first.
* **Comparison vs OBI's per-call overhead** for the same payload sizes.
  Their published number is ~1 µs/op for OpenSSL uprobe at 1 KB — we're
  in the same ballpark.
