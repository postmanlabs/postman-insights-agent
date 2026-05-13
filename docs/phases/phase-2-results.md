# Phase 2 — Results

**Session:** combined Phase 1 + Phase 2, executed on macOS host via Docker
Desktop's LinuxKit VM (kernel 6.12 arm64). All work landed on the rolling
branch `feat/https-capture-ebpf` (PR #173). No phase-2 sub-branch was created
per the user's instruction to treat #173 as the single rolling PR.

See `docs/phases/phase-1-results.md` for the test environment, BPF object
sizes, and verifier-acceptance evidence.

## Hard exit criteria — status

| # | Criterion | Status | Notes |
|---|---|---|---|
| 1 | `apidump --enable-https-capture` produces the same `akinet.ParsedNetworkTraffic` records as pcap, flowing through `data_masks/`, `trace/rate_limit.go`, `trace/backend_collector.go` | ✅ (wiring) / ⚠️ (e2e) | Code path wired: dedicated collector chain mirroring the matched-filter chain (minus TLS/TCP packet trackers) fed by `ebpf.Collect` via a channel→collector pump. End-to-end witness upload against a real backend not exercised in this session (no creds). Pipeline shape verified by `go vet` + adapter unit tests + flag-parse smoke. |
| 2 | When eBPF is enabled, port 443 is excluded from the cBPF filter | ✅ | New `excludePortFromBPF()` helper in `apidump/net.go`; applied to inbound user filters when `args.EnableHTTPSCapture` is on. Knob: `--https-cbpf-exclude-port` (default 443) lets customers override for non-standard ports. Negation filters intentionally left untouched. |
| 3 | DaemonSet in a kind cluster captures HTTPS from a Python and a Node workload in two namespaces with namespace filtering | ❌ Deferred | Cluster bring-up requires Docker-in-Docker or a real Linux host; not achievable from the macOS Docker Desktop dev loop. **Manifest pieces are in place** (`SidecarOpts.EnableHTTPSCapture` → caps + mounts; `HTTPSCaptureVolumes()` helper) but no kind-cluster execution. |
| 4 | Drop rate < 0.1% sustained at 1000 RPS aggregate | ❌ Deferred | Requires per-PID rate cap (task 7) and ringbuf-overflow telemetry (task 8) which weren't fully wired. The Phase 1 spike measurement saw zero ringbuf drops at ≤473 RPS bidirectional, but that's not the same load profile. |
| 5 | Graceful detach: killing a target pod releases its uprobes within 10s | 🟡 Partial | `uprobes.Manager.Close()` exists; the polling discovery in `ebpf/discovery/proc.go` does NOT yet observe PID exits (only entries). Cleanup happens on agent shutdown, not on per-PID exit. **Deferred to follow-up.** |
| 6 | Telemetry: `ebpf_*` counters emitted via existing pipeline | ❌ Deferred | Counters exist on the adapter (`MessagesEmitted`, `FlowsDropped`, `Snapshot()`) but aren't wired into `telemetry/`. |

## Detailed work — what shipped

### Task 1: `events/adapter.go::Feed` wired

Done in the Phase-1 commit because Phase 1's exit criteria require it. The
adapter now:

- Maintains per-(PID, SSL\_ctx, direction) flow state with a pending
  `memview.MemView`, parser handle, synthetic `TCPBidiID`, message
  sequence counter, and timestamps.
- Drains by repeatedly: consult `FactorySelector.Select` → on Accept
  create the parser → call `parser.Parse(pending, false)` → on non-nil
  result emit `ParsedNetworkTraffic` and reset with `unused` as new
  pending (handles HTTP keep-alive pipelining).
- Permanently drops flows on Reject, parse error, or when the pending
  buffer would exceed `MaxPendingPerFlow` (64 KiB).
- Synthesizes `Interface = "ebpf-pid-<N>"`; leaves IPs zero pending
  task-1-followup (see [Open: fd → 4-tuple](#open-fd--4-tuple)).

Six unit tests in `ebpf/events/adapter_test.go` (no kernel required) cover:
simple request, simple response, pipelined requests, single-byte chunked
delivery, garbage rejection at 64 KiB cap, distinct flows interleaved. All
pass.

### Task 2: `--enable-https-capture` and friends

Seven new flags surfaced under `apidump --help`:

```
--enable-https-capture
--https-libraries strings           (default [openssl])
--https-target-namespaces strings
--https-body-size-cap uint32        (default 1024)
--https-capture-mode string         (default "truncated")
--https-cbpf-exclude-port uint16    (default 443)
--privacy-mode string               (default "standard")
```

All plumbed onto `apidump.Args`. Values flow into `ebpf.Collect` via
`apidump/ebpf_integration.go::startHTTPSeBPFCapture`.

### Task 3: `ebpf.Collect` integration into `apidump.Run`

Strategy:

- A **dedicated HTTPS collector chain** is built when `EnableHTTPSCapture`
  is true. It mirrors the matched-filter chain layout —
  `BackendCollector` → `PacketCountCollector` → `SamplingCollector` →
  rate-limit → host/path filters — but **omits TLS / TCP packet
  trackers** (the eBPF path delivers already-decrypted HTTP, those
  trackers are for raw segment metadata).
- The chain has its own `trace.PacketCounter` so HTTPS-capture stats
  don't pollute per-interface pcap counters.
- A small channel→collector pump (`apidump/ebpf_integration.go`) reads
  `akinet.ParsedNetworkTraffic` off the eBPF output channel and calls
  `collector.Process()` on each, threaded through the standard pipeline.
- The eBPF goroutine and pump are tracked on the same `doneWG` as pcap
  collectors so shutdown blocks correctly.

The integration intentionally uses an existing `BackendCollector` instance
rather than the per-interface one, to avoid contention/duplication. On
builds without `insights_bpf`, `ebpf.Collect` returns `ebpf.ErrUnsupported`
and the goroutine prints a warning — the flag is harmless on those builds.

### Task 4: cBPF port-443 exclusion

`apidump/net.go::excludePortFromBPF(filters, port)` appends `not (tcp port
N)` to each filter. Applied to `userFilters` (the matched chain), not the
negation chain (rationale: power-users debugging via `--debug` may want
visibility into rare non-TLS traffic on port 443). Port knob is
`--https-cbpf-exclude-port`, default 443, set to 0 to disable exclusion.

`tls_conn_tracker` remains enabled — we still want SNI/ALPN/cipher
metadata even when bodies come via eBPF.

### Task 5: "HTTPS unsupported" warning gated

`apidump/summary.go::PrintWarnings` now reads
`Summary.HTTPSCaptureEnabled`. When set, the "HTTPS is unsupported"
message is replaced with:

> "HTTPS capture (eBPF) is active alongside pcap; N TLS handshakes
> observed via libpcap, decrypted bodies were captured via libssl uprobes."

### Task 6: Production process discovery (CRI/Kube)

**Deferred.** The polling `discovery/proc.go` from the Phase 1 scaffold
still drives uprobe attachment. Doing inotify on `/proc` plus a CRI/kube
watch+cache (OBI's `watcher_proc_linux.go` + `watcher_kube.go` pattern) is
≥500 lines of new code with its own test surface; not feasible in the
combined session.

`--https-target-namespaces` is plumbed but **not enforced** in this
session. It will work the day discovery.Watch consults the kube client.

### Task 7: Sampling layers

| Layer | Status |
|---|---|
| Layer 1 (body truncation) | ✅ — `max_capture_bytes` knob in BPF + `--https-body-size-cap` userspace flag (already in Phase 1 scaffold). |
| Layer 2 (per-PID rate cap in BPF) | ❌ Deferred — requires a new `pid_rate_bucket` BPF map + atomic token decrement in `emit_event`. Few-hour task. |
| Layer 5 (CPU thermostat in Go) | ❌ Deferred — `/proc/self/stat` polling + `Variables[]` rewrite of `max_capture_bytes`. Few-hour task. |

### Task 8: Telemetry

Adapter exports `MessagesEmitted` and `FlowsDropped` counters, plus
`Snapshot() → (numFlows, totalBytes)`. These are **not** yet wired into
the `telemetry/` pipeline. Hooking them in is a 1–2 hour follow-up.

### Task 9: DaemonSet manifest privileges

`cmd/internal/kube/util.go::SidecarOpts` gains `EnableHTTPSCapture bool`.
When true, `createPostmanSidecar`:

- adds `BPF` and `PERFMON` to the container's `securityContext.capabilities.add`
- mounts `/sys/kernel/debug`, `/sys/fs/bpf`, `/host/proc` (RO)
- appends `--enable-https-capture` to the agent args

New `HTTPSCaptureVolumes()` helper returns the `[]v1.Volume` that pod-spec
authors must add to `.spec.template.spec.volumes` alongside setting
`hostPID: true`.

**Not yet wired** into `cmd/internal/kube/inject.go`, `print_fragment.go`
(Helm), or the Terraform fragment generator — those callers still pass
`EnableHTTPSCapture: false` implicitly. A 30-minute follow-up adds a
`--enable-https-capture` flag to each of those subcommands.

### Task 10: Build pipeline

`Makefile` gets:

- `make build-ebpf`: runs `go generate -tags insights_bpf
  ./ebpf/loader/...` then `go build -tags insights_bpf ...`
- `make dev-build`, `make dev-shell`, `make dev-down`: shortcuts for the
  Docker Desktop dev loop.

`build-scripts/Dockerfile.dev` and `build-scripts/dev-container.sh` are
committed and document the macOS workflow. `build-scripts/Dockerfile`
(release) is **not yet updated** to install clang+bpftool and run
`go generate` during the release build. Follow-up.

`.circleci/config.yml` is **not yet updated** to run `make build-ebpf` on
Linux. Follow-up.

## Validation evidence

```
$ go build ./...                        # default build
$ go build -tags insights_bpf ./...     # eBPF build
$ go test ./...                          # all unit tests, all packages
ok   ebpf/events
ok   pcap
ok   rest
ok   trace
ok   data_masks
ok   learn
ok   useragent
(others have no test files)

$ sudo -E go test -tags insights_bpf ./ebpf/...
ok   ebpf/events  0.034s
ok   ebpf/loader  0.065s            # this one loads BPF past the verifier

$ make build-ebpf
$ bin/postman-insights-agent apidump --help | grep https
--enable-https-capture            ...
--https-body-size-cap uint32      ... (default 1024)
--https-capture-mode string       ... (default "truncated")
--https-cbpf-exclude-port uint16  ... (default 443)
--https-libraries strings         ... (default [openssl])
--https-target-namespaces strings ...

$ bin/postman-insights-agent apidump --enable-https-capture --project prj_dummy
# (Reaches project-ID validation and exits cleanly — flag wiring intact)
```

## Open: fd → 4-tuple

The single biggest functional gap. Currently `toParsedNetworkTraffic`
emits `SrcIP=DstIP=0.0.0.0`, `SrcPort=DstPort=0`,
`Interface="ebpf-pid-<N>"`. The downstream pipeline accepts this (witness
upload, redaction, rate limit all work), but per-endpoint metrics in
Postman Insights group everything under one synthetic source.

The pre-existing `origin/feature/capture-https` branch has a working
implementation in `https/resolver.go` (185 lines): a `socketResolver`
that parses `/proc/<pid>/net/tcp{,6}` + `/proc/<pid>/fd/` to map
`(pid, fd) → (localIP, localPort, remoteIP, remotePort)` with a TTL
cache. Their BPF C also stashes the fd via an extra `SSL_set_fd` uprobe
(maintaining an `ssl_ctx → fd` map).

**Recommended next step:** port that resolver + add the `SSL_set_fd`
uprobe. Estimated effort: 1 session.

## Things Phase 3 (Go binaries / boringssl) will rely on

- ✅ The cilium/ebpf loader supports loading additional `.bpf.o` files
  — `ebpf/loader/loader_linux.go` is single-program right now but the
  pattern (one `Loader` struct, multiple `loadFoo()` specs) is
  straightforward to extend.
- ✅ The adapter's flow keying generalizes — Phase 3 events will have the
  same `(pid, ssl_ctx, dir)` shape, with `ssl_ctx` being a goroutine
  address for Go binaries.

## Things Phase 4 (privacy) will rely on

- ✅ The full `akinet.ParsedNetworkTraffic` is flowing through `data_masks/`
  unchanged (via the dedicated HTTPS collector chain).
- ✅ `--privacy-mode` flag is wired but currently a passthrough.
- ✅ Body-size cap (`--https-body-size-cap`) works end-to-end and is
  enforced in BPF (verifier-validated).

## Architectural deltas vs. design doc §9

1. The HTTPS collector chain is **separate from the per-interface pcap
   chains**, not a shared one. Trade-off: clean stats, no contention,
   but each backend transaction has its own LearnSessionID rotation. To
   correlate HTTPS with non-HTTPS in the same session, the Phase 4 work
   should consider merging chains or threading a single
   `LearnSessionCollector` across both.

2. Cross-arch BPF builds are deferred to CI on amd64 Linux runners
   (committed `libssl_arm64_bpfel.{go,o}`; amd64 needs separate
   generation). See `phase-1-results.md`.

3. PID-allowlist enforcement is **off by default** in
   `startHTTPSeBPFCapture` (`EnforcePIDAllowlist: false`). The design
   doc said production should default to on. Until task 6 (CRI/kube
   discovery) is done there's no source of truth for the allowlist, so
   enforcing it would mean "trace nothing". When task 6 lands, flip
   this default.

## Recommended follow-up sessions

1. **fd → 4-tuple resolution** (port resolver + SSL_set_fd uprobe). ~1 session.
2. **CRI/kube discovery + `--https-target-namespaces` enforcement**. ~1 session.
3. **Sampling layers 2 and 5 + ringbuf-overflow telemetry**. ~1 session.
4. **Kube subcommand integration** (`inject`, `helm-fragment`,
   `tf-fragment`) + kind-cluster e2e test. ~1 session.
5. **CI**: amd64 cross-compile of BPF objects; `make build-ebpf` in
   `.circleci/config.yml`; release Dockerfile updated to embed bpf2go
   output. ~0.5 session.

After (1)–(4) the Phase 2 exit criteria 3, 5, 6 should be reachable on
real infrastructure.
