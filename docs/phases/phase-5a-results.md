# Phase 5a — Results

**Session goal (from [`phase-5-plan.md`](phase-5-plan.md)):** wire the
kernel side of the Java ioctl-bridge end-to-end against a tiny C harness.
No Java involved.

**Branch:** `feat/https-capture-ebpf` (rolling PR #173).

**Outcome:** ✅ all five exit criteria met on the first run. Phase 5b is
unblocked.

---

## What landed

| File | What it does |
| --- | --- |
| `ebpf/programs/java_tls.bpf.c` | Single `sys_ioctl` kprobe. Filters `fd==0 && cmd==0x0b10b1`. Reads a 41-byte `java_packet` header + payload from user memory and emits an `ssl_event` on a dedicated ringbuf. |
| `ebpf/loader/loader_javatls_linux.go` | `LoadJavaTLS(maxCaptureBytes, enforceAllowlist)`. Sets load-time constants, exposes `Attach()` (kprobe), `AddTargetPID/RemoveTargetPID`, ringbuf, and counter accessors. |
| `ebpf/loader/javatls_arm64_bpfel.{go,o}` | bpf2go output (host arch only — same convention as libssl/gotls). amd64 generated in-CI. |
| `ebpf/collect_javatls_linux.go` | `JavaTLSCollector` — thin wrapper that owns the loader + a ringbuf reader and feeds an `events.Adapter`. Idempotent `Attach()`. |
| `cmd/internal/apidump-javatls/{cmd,run_linux,run_stub}.go` | Hidden spike CLI. Flags: `--duration`, `--pid` (repeatable, implies allowlist), `--max-capture-bytes`, `--enforce-allowlist`. Mirrors the shape of `apidump-gotls`. |
| `test/java-tls-harness/{harness.c,Makefile}` | 50-line C program that builds a `java_packet` for either a synthetic GET request or a 200 response and calls `ioctl(0, 0x0b10b1, &packet)`. Modes: default (1 REQ + 1 RESP), `--wrong-cmd`, `--bad-op`, `--burst N`, `--verbose`. |
| `cmd/root.go` | Registers `apidump-javatls` as a hidden subcommand. |

## Wire format (frozen for 5b)

```
struct java_packet (packed, 41-byte header):
  offset  size  field
  ------  ----  -----
       0     1  operation       (1=SEND, 2=RECV; others ignored)
       1    16  s_addr          (IPv6; IPv4 in first 4 bytes for v4 sockets)
      17    16  d_addr
      33     2  s_port          (host byte order)
      35     2  d_port
      37     4  buf_len         (host byte order)
      41   ...  buffer          (raw plaintext; up to buf_len bytes)
```

This matches OBI's `IOCTLPacket.java` byte-for-byte so a 5b Java agent
ported from OBI requires no wire translation. `_Static_assert` in
`harness.c` and matching offsets (`JP_OFF_*`) in `java_tls.bpf.c`
defend the layout.

`fd == 0` + `cmd == 0x0b10b1` is the kernel-side magic. `ioctl()` always
returns `-1 / ENOTTY` to userspace (the kernel itself doesn't handle the
command); the kprobe fires before the kernel rejects, which is the whole
mechanism of the bridge.

## Mapping to the existing pipeline

* **Ringbuf:** `java_events` is its own 2 MiB ringbuf, NOT shared with
  libssl. That lets the program be loaded conditionally without bloating
  libssl's verifier budget, and lets us attach a dedicated reader. The
  event struct (`ssl_event`) is identical.
* **`ssl_ctx`:** synthesised from the conn tuple
  (`hash(s_ip4 ^ d_ip4, s_port ^ d_port)`) so SEND and RECV from the
  same logical connection share a flow key in the adapter.
* **`fd`:** set to `-1` (we don't have one); userspace tolerates this
  the same way it does for unresolved libssl `SSL*`s.
* **PID allowlist:** same map shape as libssl (`hash<u32, u8>`). Empty
  map + `enforce_pid_allowlist=0` = trace everyone (spike default).

## Validation — full test matrix

Ran in the `pia-bpf-dev` container on arm64 Linux 6.x kernel.

| # | Test | Expected | Observed |
| --- | --- | --- | --- |
| 1 | Happy path: harness sends one REQ + one RESP with magic cmd | 1× `REQ method=GET path=/phase5a`, 1× `RESP status=200`, `emitted=2, bytes=203` | ✅ exactly as expected |
| 2 | `--wrong-cmd` (`cmd=0xDEAD`) | 0 events, `bad_cmd` counter increments | ✅ `emitted=0, bad_cmd=2` |
| 3 | `--bad-op` (op=99, magic cmd) | 0 events, no counter movement (silent skip by design) | ✅ `emitted=0, bad_cmd=0` |
| 4 | `--pid 1` allowlist, harness has different PID | 0 events | ✅ `emitted=0` |
| 5 | Burst: 5000 REQ/RESP pairs in 11 ms | All ioctls fire; ringbuf may drop under sustained 900k evt/s; no crashes | ✅ `emitted=4732, ringbuf_drops=5268, read_fail=0, bad_cmd=0`; 2375 REQ + 2357 RESP parsed |

The 11 ms / 5000-pair burst rate (~900k events/s) is **far above any
plausible Java traffic rate** — real JVMs do ~1k–10k SSL ops/s under
load. Ringbuf saturation in the synthetic burst is expected and
benign; we'll revisit in 5c if a real workload ever pushes close.

## Verifier complexity (`bpftool prog show`)

```
1193: kprobe  name java_kprobe_sys_ioctl  tag 1e7021cfe12a7796  gpl
      xlated 2464B  jited 1584B  memlock 4096B
      map_ids 1102,1103,1104,1105,1106
```

Modest. For comparison libssl's largest single program (`SSL_read_ex`)
is ~3× larger. Plenty of headroom for the per-PID rate cap and IPv6
enrichment we'll add in 5b/5c.

## Gotchas hit & resolved

1. **`pflag` has no `Uint32SliceVar`** — only `UintSliceVar`. The CLI
   uses `[]uint` internally and casts at the allowlist API boundary.
   Worth a note for future BPF spike commands.
2. **Kprobe SEC name vs. attach symbol.** The BPF program uses
   `SEC("kprobe/sys_ioctl")` purely for human-readable `bpftool` output;
   the actual attach uses `link.Kprobe("sys_ioctl", ...)` which resolves
   the arch-prefixed kernel symbol (`__x64_sys_ioctl` /
   `__arm64_sys_ioctl`) automatically.
3. **Syscall-wrapper register unwrap.** On x86 and arm64, the kprobe's
   `ctx` is the syscall wrapper's `pt_regs *`, NOT the wrapped registers.
   We use `PT_REGS_PARM1(ctx)` to recover the wrapped `pt_regs *` and
   then `PT_REGS_PARM1..3` of THAT to get `fd`, `cmd`, `arg`. Same trick
   OBI uses; would be silently broken on older kernels without the
   syscall wrapper (we don't target those).
4. **Variable name collision with libssl constants.** I prefixed all
   java_tls maps and `volatile const` variables with `java_` so they
   don't collide with libssl's identically-named ones when the user
   inevitably wants to run both programs in the same agent process
   later (which is the steady-state for 5b+: libssl for native, java_tls
   for JVMs, both loaded). No code change needed; just a discipline.

## What 5b inherits (no work required)

* The wire format. Java agent's JNI `ioctl()` writes the same 41-byte
  header; no translation layer.
* The ringbuf reader + adapter path. `JavaTLSCollector.Run()` is
  Java-source-agnostic.
* The PID-allowlist API (`AddTargetPID`/`RemoveTargetPID`) — the
  webhook-driven discovery in 5c will populate this map.

## What 5b still needs

* Java agent (Gradle project, `Agent.premain`, `SSLEngineInst`).
* JNI shim (`postman_jni.c` + `NativeMemory.java`) that builds the
  `java_packet` off-heap and calls `ioctl(0, 0x0b10b1, addr)`.
* Off-heap thread-local buffer in Java.
* One real workload: minimal `HttpsServer.create(...)` from JDK
  built-ins (no Spring Boot / Tomcat yet — those land in 5c).

See [`phase-5-plan.md`](phase-5-plan.md) §"Session 5b" for the brief.

## Commands to reproduce

```sh
# From the dev container (pia-bpf-dev):
cd /workspace
make build-ebpf
make -C test/java-tls-harness

# Happy path (separate shells):
sudo bin/postman-insights-agent apidump-javatls --duration 10s
./test/java-tls-harness/harness

# Negative tests:
./test/java-tls-harness/harness --wrong-cmd        # 0 events, bad_cmd=2
./test/java-tls-harness/harness --bad-op           # 0 events
sudo bin/postman-insights-agent apidump-javatls --pid 1 --duration 5s
./test/java-tls-harness/harness                    # 0 events (wrong PID)

# Burst stress:
./test/java-tls-harness/harness --burst 5000

# Diagnostics:
JAVATLS_DEBUG_RAW=1 sudo bin/postman-insights-agent apidump-javatls --duration 10s
```
