# HTTPS Capture via eBPF — Progress

**Single source of truth for "where are we" on the HTTPS-capture program.**

**Last updated:** end of follow-up backlog closure session (commit `ad177b3`).

## TL;DR — program status

The HTTPS-capture-via-eBPF program is **feature-complete at the original
design-doc spec** and at **steady state**. Every track is closed:

* All 8 privacy gaps from `https-capture-design.md` §7.3 are closed.
* All Phase 5 (Java + webhook) milestones are shipped.
* All five post-launch follow-ups (ByteBuddy bump, CLI-tool skip, JMH
  benchmark, per-namespace `privacyMode`, CI smoke) are closed.

**For the next engineer**, start with [`HANDOFF.md`](HANDOFF.md) — it has
the full onboarding map.

## PR structure (current)

| PR | Branch | Scope | Status |
|---|---|---|---|
| **[#173](https://github.com/postmanlabs/postman-insights-agent/pull/173)** | `feat/https-capture-ebpf` | **Phases 1–5 + 4b + 4c + follow-ups** — the entire program | DRAFT |
| ~~[#174](https://github.com/postmanlabs/postman-insights-agent/pull/174)~~ | ~~`feat/https-capture-ebpf-libssl`~~ | Closed as a subset of #173 |

#173 is the **single review surface** for an external eBPF consultant.
Do not create sub-branches; everything lives on `feat/https-capture-ebpf`.

---

## Quick links

| Document | What it is |
|---|---|
| [`https-capture-design.md`](https-capture-design.md) | The complete architecture & research doc (12 sections). Start here for any deep work. |
| [`https-data-flow.md`](https-data-flow.md) | **Customer-facing.** End-to-end data flow with per-step visibility / encryption answers. |
| [`security-permissions.md`](security-permissions.md) | **Customer-facing.** Linux capabilities, syscalls hooked, RBAC, network egress, verification commands. |
| [`redaction-defaults.md`](redaction-defaults.md) | **Customer-facing.** ~40 default sensitive keys, ~150 regexes, compliance mappings. |
| [`phases/README.md`](phases/README.md) | Multi-session execution model. |
| [`phases/phase-1.md`](phases/phase-1.md) → [`phase-5.md`](phases/phase-5.md) | Self-contained execution briefs, one per phase. |
| [`phases/phase-1-results.md`](phases/phase-1-results.md) | Phase 1 outcomes (libssl spike). |
| [`phases/phase-2-results.md`](phases/phase-2-results.md) | Phase 2 outcomes (production integration + kind e2e). |
| [`phases/phase-3-results.md`](phases/phase-3-results.md) | Phase 3 outcomes (Go support; in progress). |
| [`phases/phase-4-results.md`](phases/phase-4-results.md) | Phase 4 outcomes (privacy hardening; 5 of 8 gaps closed). |
| [`phases/SESSION-RESUME.md`](phases/SESSION-RESUME.md) | Pre-compaction resume brief — dev-env recreate commands + tribal-knowledge gotchas + next-task starting points. |
| `progress.md` (this file) | Top-level program status. |

---

## TL;DR

| Phase | Goal | Status |
|---|---|:---:|
| 1 | Spike: decrypted HTTPS reaches `trace.Collector` | ✅ Done |
| 2 | Production integration into `apidump` (DaemonSet, sampling, telemetry, namespace filter, kind e2e) | ✅ Done — all 6 exit criteria |
| 3 | Go via DWARF inspector + crypto/tls uprobes | ✅ **~95% (sealed)** — foundation + HTTP/2 + bidirectional + gRPC + stripped + multi-version + amd64 disassembler; multi-layer dedup designed but deferred ([why](phases/phase-3-dedup.md)) |
| 4 | Privacy hardening (the 8 gaps from design §7.3) | 🟡 **~75% (5 of 8 gaps closed)** — standard/strict/dry-run modes, hash tokenisation, coverage telemetry, customer docs all live |
| 5 | Java agent + `ioctl` bridge + mutating webhook | ❌ Not started |

**Roughly 85% of the v1 program by design-doc scope.** Only Phase 5 (Java) remains as a major track.

---

## Coverage by language runtime (the customer view)

| Runtime | Status | How |
|---|:---:|---|
| C / C++ with system OpenSSL | ✅ | libssl uprobes |
| Python (system `ssl`, `requests`) | ✅ | libssl |
| Ruby (system OpenSSL) | ✅ | libssl (same path; not explicitly tested) |
| PHP (system OpenSSL) | ✅ | libssl |
| nginx | ✅ | libssl, verified in kind |
| Node.js (system OpenSSL, dynamic) | ✅ | libssl |
| Node.js (statically-linked BoringSSL — common default) | ❌ | Phase 3 task #4 (pclntab fallback) |
| **Go HTTP/1.1 server-side** (`net/http` + TLS) | ✅ | `crypto/tls.(*Conn).Write` uprobe |
| **Go HTTP/2 server-side** (Go default!) | ✅ | HTTP/2 frame decoder + HPACK |
| **Go HTTPS client-side** (`http.Get`) | ✅ | `crypto/tls.(*Conn).Read` via RET-instruction probing |
| Go gRPC | ✅ | gRPC method/service from `:path`; length-prefixed framing inside DATA stripped; mid-stream h2 detection. **Caveat:** start the agent before the connection opens (HPACK is stateful; mid-connection attach loses headers). |
| **Go (stripped, `-ldflags='-s -w'`)** | ✅ | pclntab fallback via `debug/gosym`. Verified 8/8 across Go 1.21–1.24 × stripped/unstripped matrix. |
| Java / JVM (Spring, Netty, Tomcat, gRPC-Java) | ❌ | Phase 5 |
| Rust (rustls) | ❌ | Out of scope for v1 per design §4.4 |

---

## Phase-by-phase detail

### Phase 1 — Spike

**Done.** Decrypted HTTP/1.1 from C/Python/Node HTTPS workloads reached
`trace.Collector` as `akinet.HTTPRequest` / `akinet.HTTPResponse` records,
indistinguishable from what `pcap.Collect` produces. The Phase-1 brief's
predicted dominant failure mode (BPF verifier rejection) didn't materialize —
the program loaded on first try.

**Key deliverables:**

- `ebpf/programs/libssl.bpf.c` — uprobes on `SSL_read{,_ex}` / `SSL_write{,_ex}` + `SSL_set_fd` / `SSL_free` for fd tracking.
- `ebpf/loader/` — cilium/ebpf-based loader, `bpf2go` integration committed.
- `ebpf/events/` — ringbuf reader, decoder, adapter feeding bytes into the existing akinet HTTP parsers.
- `ebpf/uprobes/` — `/proc/<pid>/maps` walking, dynamic libssl attachment via `link.Uprobe`.
- `ebpf/discovery/` — `/proc` polling for new libssl-loaded PIDs.
- `cmd/internal/apidump-ebpf/` — `apidump-ebpf` spike command (hidden).
- `build-scripts/Dockerfile.dev` + `dev-container.sh` — reproducible Linux dev environment for macOS.

**Results doc:** [`phases/phase-1-results.md`](phases/phase-1-results.md).

---

### Phase 2 — Production integration

**Done.** All 6 hard exit criteria verified end-to-end on a kind cluster
that uses the same containerd + cgroup-namespace + bind-mounted-`/proc`
pattern a real Kubernetes cluster does.

**Per-criterion summary:**

| # | Criterion | How met |
|---|---|---|
| 1 | `--enable-https-capture` flows through the unchanged `data_masks` / `rate_limit` / `backend_collector` chain | Dedicated HTTPS collector chain mirroring the matched-filter pcap chain minus TLS/TCP packet trackers. |
| 2 | Port 443 excluded from cBPF filter when eBPF is on | `apidump/net.go::excludePortFromBPF` + `--https-cbpf-exclude-port` (default 443). |
| 3 | DaemonSet in kind captures HTTPS from two namespaces with namespace filtering verified | CRI + cgroup-namespace-inode bridge (OBI/Datadog pattern). Verified by filter-flip: `[team-py,team-srv]` captures python+nginx, excludes node; `[team-node,team-srv]` captures only nginx. |
| 4 | Drop rate < 0.1% sustained at 1000 RPS | `ringbuf_drops=0` over 19,800+ resolved events. CPU thermostat throttles `max_capture_bytes` before drops happen. Per-PID rate cap verified separately. |
| 5 | Graceful detach within 10s of pod exit | `discovery.WatchWith` emits `Target{Removed:true}` ≤2s after PID disappears. |
| 6 | `ebpf_*` telemetry counters via existing pipeline | `httpsTelemetryWorker` emits structured stats line every 30s + `tracker.WorkflowStep`. |

**Key code additions:**

- `apidump/apidump.go` — `Args` gains HTTPS-capture fields (`EnableHTTPSCapture`, `HTTPSBodySizeCap`, `HTTPSTargetNamespaces`, `HTTPSRateCapPerSec`, `HTTPSCBPFExcludePort`, `PrivacyMode`, etc.). Dedicated HTTPS collector chain.
- `apidump/ebpf_integration.go` — `startHTTPSeBPFCapture` orchestrates `ebpf.Collect` → channel pump → collector chain. Telemetry worker. CRI-based namespace resolver wiring.
- `apidump/net.go::excludePortFromBPF` — cBPF filter mutation.
- `apidump/summary.go` — "HTTPS unsupported" warning gated off when capture is on.
- `cmd/internal/apidump/apidump.go` — 8 new flags surfaced.
- `cmd/internal/kube/{util,kube,inject,print_fragment}.go` — `--enable-https-capture` on `kube inject`, `helm-fragment`, `tf-fragment` adds CAP_BPF + CAP_PERFMON + host mounts + CRI socket.
- `ebpf/discovery/kube_linux.go` — `KubeNamespaceResolver` via kube_apis + cri_apis + cgroup-namespace inode.
- `ebpf/discovery/proc.go` — `WatchWith` with namespace filter + PID-exit detection.
- `ebpf/events/resolver.go` — `(pid, fd) → 4-tuple` via `/proc/<pid>/net/tcp{,6}`. Adapter caches by `(pid, ssl_ctx, fd)` to handle nginx-style SSL* reuse.
- `ebpf/ratecap_linux.go` — per-PID rate cap (sampling layer 2): BPF map + userspace refill goroutine.
- `ebpf/thermostat_linux.go` — CPU thermostat (sampling layer 5): polls `/proc/self/stat`, halves `max_capture_bytes` if 10s avg > 5%, doubles on recovery.
- `ebpf/preresolve_linux.go` — proactive resolver polls the BPF `ssl_ctx_to_fd` map every 5ms and caches resolutions before connections close.
- `ebpf/integrations/cri_apis.GetContainerPID()` — new public CRI method returning container init PID.
- `test/kind/{cluster,agent-daemonset,workloads,Dockerfile.agent}.yaml` — full e2e environment.
- `Makefile`: `make build-ebpf`, `make dev-build`, `make dev-shell`, `make dev-down`.

**Live demo evidence (from kind cluster):**

```
emitted=1302   ringbuf_drops=0   ratecap_drops=0   read_fail=0
ssl_set_fd=432 events_with_fd=864 resolver_hit=87894 miss=0 inode_ok=87894 inode_fail=0
```

```
REQ  10.244.0.6:37284 -> 10.96.30.123:8443  (ebpf-pid-75977 = python client → Service VIP)
REQ  10.244.0.6:37284 -> 10.244.0.5:8443    (ebpf-pid-76098 = nginx server pod IP)
RESP 10.244.0.5:8443  -> 10.244.0.6:37284   (ebpf-pid-76098 = nginx server)
RESP 10.96.30.123:8443-> 10.244.0.6:37284   (ebpf-pid-75977 = python client)

ebpf: thermostat throttling — 7.5% CPU over 10s exceeded 5.0%; max_capture_bytes 512 → 256
```

**Sampling stack — all 5 layers from design §6.2:**

| Layer | Status | Notes |
|---|:---:|---|
| 1 Body truncation | ✅ | BPF mask + `--https-body-size-cap` |
| 2 Per-PID rate cap (kernel token bucket) | ✅ | Verified: 30 curls × cap=3/s → 6 emitted + 54 drops |
| 3 Reservoir per (svc, route, status) | ✅ | Reuses `trace.SamplingCollector` |
| 4 `SharedRateLimit` final witness budget | ✅ | Reuses `trace/rate_limit.go` |
| 5 CPU thermostat | ✅ | Live-fires at 5.7% → halves cap; recovers at 3% |

**Results doc:** [`phases/phase-2-results.md`](phases/phase-2-results.md).

---

### Phase 3 — Go support (in progress, ~65%)

**Done so far:**

- ✅ **Foundation** (commit `43b604b`):
  - `ebpf/goexec/goexec.go` — ELF inspector. `IsGoBinary()`, `Inspect()` (symbol → file offset, Go version from `.go.buildinfo`).
  - `ebpf/programs/gotls.bpf.c` — `crypto/tls.(*Conn).Write` uprobe reads Go register-ABI args (x1/x2 arm64; rax/rbx/rcx amd64).
  - `ebpf/loader/loader_gotls_linux.go` — per-collection loader; bpf2go bindings.
  - `ebpf/collect_gotls_linux.go` — `GoTLSCollector` orchestrating load + reader + adapter.
  - `cmd/internal/apidump-gotls/` — hidden spike CLI `apidump-gotls --pid N`.
- ✅ **HTTP/2 frame decoder** (commit `34cf654`):
  - `ebpf/events/http2.go` — HPACK via `golang.org/x/net/http2/hpack`, stream-level multiplexing, HEADERS / CONTINUATION / DATA frame handling.
  - 7 unit tests in `http2_test.go`.
  - Routed from `adapter.Feed` on first-bytes detection.
- ✅ **`crypto/tls.(*Conn).Read` via RET-instruction probing** (commit `308d3ab`):
  - `ebpf/goexec/goexec.go::FindReturnOffsets` — arm64 + amd64 RET scan.
  - `ebpf/programs/gotls.bpf.c` — `gotls_read_in_flight` map keyed by goroutine pointer; entry probe stashes args; RET probes (one per RET site) emit on completion.
  - `goroutine_ptr(ctx)` + `go_ret(ctx)` helpers read the r14/x28 and rax/x0 registers.

**Not done:**

- ✅ **gRPC framing decoder + mid-stream h2 detection** (commit `<this commit>`):
  - `IsHTTP2Frame` heuristic in `ebpf/events/http2.go` — detects HTTP/2 mid-conversation by parsing a frame header and validating stream-id requirements (DATA/HEADERS on stream 0 = reject, SETTINGS on non-zero stream = reject). Kills false positives on all-zero / random garbage.
  - `handleData` strips 5-byte length-prefixed gRPC framing from DATA payloads, reassembles split messages across DATA frames, and surfaces count + total via `X-Pi-Grpc-Messages` / `X-Pi-Grpc-Total-Bytes` synthetic headers.
  - `hpackErrors` counter on each h2State surfaces the mid-connection-attach failure mode.
  - Verified live: gRPC health check (`/grpc.health.v1.Health/Check`) decodes as POST + status=200, 11 REQ/RESP pairs at 1Hz, zero drops.
- ❌ Multi-Go-version test matrix (Go 1.17 / 1.21 / 1.22 / 1.23).
- ❌ Stripped-binary pclntab fallback.
- ❌ Multi-layer dedup (`net/http` + `crypto/tls` + `net.netFD`).
- ❌ amd64 RET-scan via real disassembler (current byte-match is good-enough for arm64 but can false-positive on amd64).

**Live demo evidence (Go HTTPS client, RET probing):**

```
INFO ebpf: attached gotls probes pid=149471 (write + read_entry + 7 read_rets)
REQ  pid=ebpf-pid-149471 method=GET url=/         ← Write entry probe (egress)
RESP pid=ebpf-pid-149471 status=200               ← Read RET probe (ingress)
REQ  pid=ebpf-pid-149471 method=GET url=/
RESP pid=ebpf-pid-149471 status=200
...
gotls-stats: emitted=19 ringbuf_drops=0 read_fail=0 bytes=2192
```

**Results doc:** [`phases/phase-3-results.md`](phases/phase-3-results.md).

---

### Phase 4 — Privacy hardening

**~75% (5 of 8 gaps closed).** Brief: [`phases/phase-4.md`](phases/phase-4.md).
Results: [`phases/phase-4-results.md`](phases/phase-4-results.md).

| # | Gap | Status |
|---|---|:---:|
| 1 | `Authorization` + `cookie` + 11 more headers in default list | ✅ `data_masks/redaction_config.yaml` expanded; 40+ defaults |
| 2 | Body-size cap as redaction concept | ✅ `--https-body-size-cap` (BPF-enforced) |
| 3 | HIPAA preset (`--privacy-mode=strict`) | ✅ `data_masks/privacy_mode.go`; drops bodies + header allowlist |
| 4 | Per-namespace opt-out | ✅ `--https-target-namespaces` |
| 5 | Tokenization (hash-replace) | ✅ `--redaction-style=hash`; sha256(value)[:8] |
| 6 | Redaction-coverage telemetry | ✅ `data_masks/coverage.go`; per-rule atomic counters |
| 7 | Dry-run mode (`--privacy-mode=dry-run`) | ✅ `data_masks/dry_run.go`; per-window JSON reports with reservoir-sampled redacted samples |
| 8 | Customer-facing security docs | ✅ `docs/https-data-flow.md`, `docs/security-permissions.md`, `docs/redaction-defaults.md` |

**Remaining (lower priority):**
- Body-size cap as a *redactor-side* metadata enrichment (today truncation happens at BPF; redactor doesn't decorate the truncated body with `{_truncated: true, _original_length: N}` metadata).
- Discovery-config `decrypt: false` (per-namespace eBPF opt-out *at the kube layer*; the `--target-namespaces` whitelist is the simpler equivalent today).

**Status: HTTPS capture is now safe to enable for trial deployments that opt into `--privacy-mode=dry-run` for a customer-defined trust-building period.** Live mode (`standard` / `strict`) is appropriate after dry-run audit.

**Test coverage added this phase:**
- 13 new unit tests in `data_masks/` (privacy modes, tokenization, coverage counters, redaction corpus)
- Regression corpus with 14 sensitive samples + 36 safe strings; assert 100% sensitive detection + 0% false positives

---

### Phase 5 — Java agent + ioctl bridge

**Not started.** Brief: [`phases/phase-5.md`](phases/phase-5.md). Largest phase
(6 weeks estimate): new Gradle build for a ByteBuddy Java agent, kernel
`ioctl` bridge BPF kprobe, mutating webhook for Pod-spec injection.

---

## Recommended next-session ordering

Phases 1+2+3+4 are essentially done. Remaining work:

1. **Phase 5 — Java agent + ioctl bridge + webhook** (~6 weeks). Largest
   remaining piece. Java is the biggest enterprise gap. Needs a separate
   Gradle build for a ByteBuddy java-agent, a kprobe on `sys_ioctl` to
   pipe bytes from JVM userspace into the same redactor pipeline, and a
   mutating webhook to inject the agent into pod specs.
2. **PR split** (~30min). Extract Phase 1+2 into a separate stacked PR
   (`feat/https-capture-ebpf-libssl`) so reviewers can land the
   production-ready libssl path independently of remaining Java work.
   See [PR strategy](#pr-strategy) below.
3. **CI hardening** (~0.5 day) — Linux/amd64 runner that produces both
   `libssl_arm64_bpfel.o` and `libssl_amd64_bpfel.o` at release time.
4. **Phase 4 task 2** (redactor-side truncation metadata) and task 4
   (discovery-YAML `decrypt: false`) when customer feedback drives demand.
5. **Phase 3 task #6** (multi-layer dedup, design at
   [`phases/phase-3-dedup.md`](phases/phase-3-dedup.md)) when we add
   `net/http`-layer probes alongside `crypto/tls`.

## Commit timeline (this branch)

```
2b31e07 docs: session-resume brief + phase-3-results.md task #2 update
308d3ab ebpf: Phase 3 task #2 — Go crypto/tls.(*Conn).Read via RET probing
34cf654 ebpf: Phase 3 follow-up #1 — HTTP/2 frame decoder
2bd2602 docs: phase-3-results.md — Go capture foundation (25% of Phase 3)
43b604b ebpf: Phase 3 foundation — Go crypto/tls capture
f2e2459 docs: phase-2-results.md — namespace filter status flipped to ✅
2ccc9dd ebpf: Phase 2 closure — CRI+cgroup-ns namespace filter (works on real K8s)
612ce96 docs: phase-2-results.md — final honest tally after Rounds 1+2+3
a880dc5 test/kind: drop accidental .bak file
4647154 ebpf: Round 3 — kind cluster e2e demo
beee46c ebpf: Round 2C — namespace filtering via kube_apis + /proc/cgroup
b907f74 ebpf: Round 2B — fd → 4-tuple resolution
fef2874 ebpf: Round 2A — per-PID rate cap (sampling layer 2)
225866f ebpf+kube: Round 1C/1D/1E — thermostat, telemetry, kube subcommand wiring
b7a21d9 ebpf: Round 1A+1B — PID-exit detection, BPF counters
1b5a9f3 docs: Phase 1 + Phase 2 results, status table refresh
51b210c apidump: Phase 2 — wire --enable-https-capture end-to-end
6b63820 ebpf: Phase 1 — bpf2go bindings + adapter wired, tests green
84cd435 docs: phased delivery — one session brief per phase
7513ce7 ebpf: Phase 1 scaffold — libssl uprobes → akinet pipeline
1e42caf docs: HTTPS capture via eBPF — research, design, and phased plan
```

PR stats: **22 commits, +10,600 / −33** across ~35 new files in `ebpf/`,
`test/kind/`, `docs/phases/`.

---

## Architecture decisions made along the way

1. **Vendor cilium/ebpf, not BCC** — modern userspace eBPF loader, no
   runtime kernel headers needed, pure Go.
2. **One shared BPF collection for libssl** (all libssl-loaded PIDs share
   the same program) but **one BPF collection per Go binary** (different
   binaries have different symbol file offsets; collection itself stays
   shared, just per-target attach points). See `ebpf/collect_linux.go`
   vs `ebpf/collect_gotls_linux.go`.
3. **Reuse the existing `akinet` parser pipeline** for HTTP/1.1; bypass it
   with our own stateful decoder for HTTP/2 (HPACK is connection-stateful;
   akinet's single-use parser contract doesn't fit). See `ebpf/events/http2.go`.
4. **Namespace bridge via cgroup-ns inode**, not `/proc/<pid>/cgroup` path.
   Cgroup paths fail on modern K8s (cgroup namespace isolation default on
   1.24+). OBI/Datadog use the cgroup-ns-inode pattern.
5. **CRI socket is the source of truth for container init PIDs**, not the
   kube API. Kube tells us pods + their containers' UUIDs; CRI maps each
   container UUID to its init PID in the node's PID namespace.
6. **bpf2go `-target native`**, not `-target amd64,arm64`. Cross-arch fails
   on libbpf 1.1 (Debian bookworm). amd64 .o generation deferred to CI on
   a Linux/amd64 runner.
7. **RET-instruction probing for Go uretprobes**, not standard
   `link.Uretprobe`. Go's stack growth invalidates saved return addresses.
8. **Goroutine pointer as flow-correlation key** for Go probes, not PID/TID.
   r14 (amd64) / x28 (arm64) holds the current `g` struct pointer.
9. **Cache resolution by `(pid, ssl_ctx, fd)` not `(pid, ssl_ctx)`**.
   Nginx and other connection-pooling servers reuse SSL* pointers across
   distinct TCP connections.

---

## Tribal-knowledge gotchas (consolidated)

1. **HTTP/2 is Go's default over TLS.** Captures without the h2 decoder look
   like "encrypted noise with plaintext at the end" — actually HPACK-
   compressed HEADERS + DATA frames. Closed by commit `34cf654`.
2. **Go uretprobes don't work.** Use RET-instruction probing. Closed by commit `308d3ab`.
3. **Cgroup paths return `0::/../..` inside containers** — even on real K8s, not just kind. Use cgroup-ns inode bridge.
4. **`tcp_tw_reuse=2` on LinuxKit** means sequential loopback connections can legitimately reuse ephemeral ports. Not a bug.
5. **Kind has 3 nested PID namespaces** (LinuxKit → kind node → pod). `hostPID:true` shares the kind-node ns, not LinuxKit. Bind-mount `/proc` from LinuxKit as `/linuxkit-proc` in the kind node config.
6. **Go register ABI is NOT System V C.** amd64 args: `rax,rbx,rcx,rdi,rsi,r8,r9,r10,r11,r12`. Goroutine in `r14`. Return in `rax`. arm64 args in `x0..x7`, goroutine in `x28`, return in `x0`.
7. **cilium/ebpf attach modes:** `Uprobe(symbol, ...)` for named symbols (Go's mangled names work fine); `Uprobe("", ..., &UprobeOptions{Address: file_offset})` for absolute-offset (RET probes). Don't use `UprobeOptions.Offset` — it's relative to a resolved symbol.
8. **Static-libssl Node** isn't supported today; FindStaticLibSSL is a placeholder. Phase 3 task #4.
9. **kind image churn:** `kind load docker-image` may leave the OLD image alongside the new one. `docker exec <node> crictl rmi NAME:TAG` before reload, then verify with `crictl images`.

Full detail in [`SESSION-RESUME.md`](phases/SESSION-RESUME.md).

---

## Recommended next-session ordering

By customer impact + dependency:

1. **Phase 3 task #3 — gRPC framing decoder** (~5h). HTTP/2 layer already
   captures the wire frames; we just need to decode the length-prefixed
   protobuf framing inside DATA payloads. Big enterprise unlock.
2. **Phase 4 — Privacy hardening** (~2 weeks). Gates production deployment.
   Should land before any non-trial customer.
3. **Phase 3 task #4 — Stripped-binary pclntab fallback** (~3 days). Many
   production Go builds use `-ldflags="-s -w"` so the DWARF/symtab path
   currently misses them.
4. **Phase 3 task #6 — Multi-layer dedup** (~2 days). When we add
   `net/http`-layer probes later, we need to pick one source per
   goroutine. Goroutine-register reading is already in place.
5. **Phase 5 — Java + ioctl bridge** (~6 weeks). Large; defer until Phase 4
   ships and a Java customer is concretely on the roadmap.
6. **CI hardening** (~0.5 day). Cross-compile BPF objects on a Linux/amd64
   runner so we ship both `libssl_arm64_bpfel.o` and `libssl_amd64_bpfel.o`.
   Update `build-scripts/Dockerfile` to embed bpf2go output during release.

---

## PR strategy

**Today: 2 PRs (split executed 2026-05-14).** PR #174 targets `main` and
contains Phases 1+2 only — production-ready libssl path, can ship
independently. PR #173 (the original rolling PR) still targets `main`
and contains the full history including Phase 3+4 on top of #174; its
diff will auto-narrow to just Phase 3+4 commits once #174 merges.

Historical rationale (kept here for record): the project ran as a single
rolling PR for most of its history. Single-PR review trades reviewer-
friendliness for reduced merge-order coordination and a coherent
commit-message narrative. Once Phase 4 was substantially complete and
the branch was at ~13k LOC, we split to let Phases 1+2 land
independently.

**Original 4-PR plan (now partially executed):**

**Tradeoffs accruing as the PR grows:**

- +10,600 lines is past the realistic threshold for end-to-end human
  review. A reviewer has to trust the per-phase results docs as proxy.
- Cannot ship Phase 1+2 to customers independently of Phase 3+4. If a
  trial customer asks for libssl-only HTTPS today, we can't merge that
  without dragging in-progress Go work along.
- One huge fast-forward into `main` once it lands; bisect granularity at
  the merge boundary is poor.
- Conflict surface against `main` grows while Phases 3+4+5 finish.

| PR | Branch | Scope | Size | Status |
|---|---|---|---|---|
| **A (#174)** | `feat/https-capture-ebpf-libssl` | Phases 1+2 — libssl path. | ~8,000 LOC | ✅ **done** |
| **B+C (#173)** | `feat/https-capture-ebpf` | Phases 3+4 combined — Go + privacy. | ~13,400 LOC (auto-narrows to ~5,400 once A merges) | 🟡 **open**, depends on A |
| **D** | `feat/https-capture-ebpf-java` | Phase 5 — Java agent + ioctl bridge + webhook. | TBD | ⏳ not started |

We collapsed the originally-planned 4-PR split (A/B/C/D) into 3 because
Phase 3 and Phase 4 had interleaved commits that would have required
an invasive history rewrite to separate. The combined Phase 3+4 PR is
still reviewable per-phase via `docs/phases/phase-3-results.md` and
`docs/phases/phase-4-results.md`.

**Mechanics that worked:** PR A's branch is created at the historical
SHA where Phase 2 ended (`f2e2459`). No commit reordering or cherry-
picking required — #174's commits are a strict prefix of #173's. Once
#174 merges to main, #173's diff against the new main automatically
narrows to just the commits that aren't on #174. GitHub handles the
rebase implicitly. One small fix-up was applied to PR A: a non-Linux
build stub for `KubeNamespaceResolver` that had been left for Phase 4
to fix; cherry-picking it back onto the libssl branch makes #174
self-contained for cross-platform builds.

---

## Don't-forget items / open questions

1. **`--privacy-mode` semantics.** Today both `strict` and `dry-run` are
   passthroughs. Phase 4 must define what they do at the redaction layer.
2. **Cross-arch BPF objects.** Only `libssl_arm64_bpfel.{go,o}` committed.
   amd64 needs a Linux/amd64 CI runner.
3. **Adapter ↔ HTTP/2 ownership.** Adapter routes HTTP/2 to a stateful
   `h2State`. When we add net/http-layer Go probes, multi-layer dedup
   (task #6) needs to choose which source wins per goroutine.
4. **gRPC method tagging strategy.** Decode-from-wire (no Go-version
   coupling, simple, v1) vs probe-grpc-package (richer, requires per-
   version DWARF). Recommendation: wire-only for v1.
5. **The pre-existing `origin/feature/capture-https` branch** (Shrey, Nov 2025)
   is a parallel attempt; we ported `https/resolver.go`'s `/proc/<pid>/net/tcp`
   parsing pattern but otherwise superseded it. Confirm no further mining
   needed before closing that branch.

---

## How to resume work

```bash
cd ~/playground/postman-insights-agent

# Make sure the rolling PR is up to date locally.
git fetch && git checkout feat/https-capture-ebpf && git pull

# Restart the dev container (creates one if missing).
make dev-build      # one-time / on Dockerfile.dev change
make dev-shell      # interactive shell inside the Linux dev env

# Recreate the kind cluster (Phase 2 e2e).
kind create cluster --config test/kind/cluster.yaml
docker build -f test/kind/Dockerfile.agent -t pia-agent-ebpf:test --provenance=false .
kind load docker-image pia-agent-ebpf:test --name pia-https-test
kubectl apply -f test/kind/agent-daemonset.yaml
kubectl apply -f test/kind/workloads.yaml
kubectl -n postman-insights logs -f ds/postman-insights-agent
```

Read [`SESSION-RESUME.md`](phases/SESSION-RESUME.md) for the full
recreate-from-scratch steps and the next-task starting points.

---

## What you can safely demo to customers

**Strong story:**

- HTTPS capture works on real Kubernetes (the CRI + cgroup-ns inode bridge is the OBI/Datadog production pattern).
- Namespace filtering is provable (filter-flip demo).
- 100% IP-resolution success rate on the kind e2e (`resolver_hit=87894 miss=0`).
- Five sampling layers wired, CPU thermostat live-fires under load.
- Go HTTPS server-side captures for both HTTP/1.1 AND HTTP/2 (default for `net/http`).
- Go HTTPS client-side captures via RET-instruction probing.
- Zero ringbuf drops at the load we tested.

**Be upfront about:**

- Java services entirely uncovered → Phase 5.
- gRPC method/message decoding → Phase 3 task #3 (HTTP/2 layer works but we don't parse gRPC framing yet).
- Statically-linked Node 20 / Envoy-static → Phase 3 task #4.
- 7 of 8 privacy gaps open → **do not enable HTTPS capture for any non-trial customer until Phase 4**.
- Cross-arch BPF (we ship arm64 .o only; need amd64 CI runner).
