# Phase 2 — Production integration into `apidump`

**Starting branch:** `feat/https-capture-ebpf` after Phase 1 has merged.

**Working branch:** `feat/https-capture-ebpf-phase2`.

**Requires:** Linux dev host (same as Phase 1) plus access to a real or kind/minikube Kubernetes cluster for DaemonSet validation.

---

## Goal

`postman-insights-agent apidump --enable-https-capture` captures HTTPS traffic from real workloads, integrates with existing CRI/Kube discovery, ships per-namespace controls, and runs as a properly-permissioned DaemonSet on a real cluster.

## Hard exit criteria

1. The `--enable-https-capture` flag on `apidump` works against the production codepath (not the spike command). Capturing HTTPS produces the same `akinet.ParsedNetworkTraffic` records that pcap produces, flowing through `data_masks/`, `trace/rate_limit.go`, and `trace/backend_collector.go` unchanged.
2. When eBPF is enabled, port 443 is **excluded** from the cBPF filter to avoid double-counting handshakes via the existing `tls_conn_tracker/`.
3. A DaemonSet deployed in a kind cluster captures HTTPS from two test workloads (one Python, one Node.js) in two different namespaces, with namespace filtering verified.
4. Drop rate < 0.1% sustained at 1000 RPS aggregate across captured workloads.
5. Graceful detach: killing a target pod releases its uprobes within 10s and does not leak ringbuf entries or map memory.
6. Telemetry: agent emits `ebpf_probes_attached`, `ebpf_events_received`, `ebpf_events_dropped`, `ebpf_bytes_captured`, `ebpf_cpu_percent` counters via the existing telemetry pipeline.

## Prerequisites — read these first

In the agent repo:
- `docs/phases/phase-1-results.md` — actual numbers from Phase 1
- `apidump/apidump.go` lines 700–1030 — current `pcap.Collect` integration point
- `apidump/net.go::createBPFFilters` — port-443 exclusion site
- `apidump/summary.go` — the "HTTPS unsupported" message at line 298 (remove when eBPF active)
- `cmd/internal/apidump/apidump.go` — flag declarations
- `cmd/internal/apidump/common_flags.go` — shared flag patterns
- `integrations/cri_apis/`, `integrations/kube_apis/` — existing process discovery
- `cmd/internal/kube/daemonset/` — current DaemonSet manifest template
- `cmd/internal/kube/run.go` — daemonset launch

In OBI (`../insights-ebpf-research/obi/`):
- `pkg/appolly/discover/watcher_proc_linux.go` — production-quality process watcher with inotify
- `pkg/appolly/discover/watcher_kube.go` — Kubernetes-aware discovery
- `pkg/internal/ebpf/generictracer/generictracer_linux.go::Run` — full event-loop pattern
- `bpf/common/large_buffers.h` — buffer-cap config knobs (we mirror these)

Reference for sampling:
- `docs/https-capture-design.md` §6.2 — the four-layer sampling stack

## Tasks (in order)

### 1. Wire `events/adapter.go::Feed` properly

This is the `TODO(phase2)` site. Replace the placeholder with real parser invocation. Pseudocode shape (refine against actual akinet types):

```go
func (a *Adapter) Feed(ev *SSLEvent, monoEpoch time.Time) {
    a.mu.Lock(); defer a.mu.Unlock()
    key := ev.Key()
    st := a.flows[key]
    if st == nil {
        st = &flowState{firstSeen: ev.Time(monoEpoch)}
        a.flows[key] = st
    }
    st.lastSeen = ev.Time(monoEpoch)
    st.totalBytes += int(ev.LenCaptured)

    payload := ev.Bytes()

    // Lazy-construct parser on first non-empty payload.
    if st.parser == nil {
        bidiID := syntheticBidiID(key)
        factory := a.FactorySelector.Select(payload, false)
        if factory == nil {
            // Not enough bytes to decide protocol; buffer and return.
            st.pendingBuf.Append(payload)
            return
        }
        st.parser = factory.CreateParser(bidiID, 0, 0)
        payload = append(st.pendingBuf.Bytes(), payload...)
        st.pendingBuf.Reset()
    }

    pnc, unused, _, err := st.parser.Parse(memview.New(payload), false)
    if err != nil { delete(a.flows, key); return }
    if pnc != nil {
        a.Out <- a.toParsedNetworkTraffic(key, st, pnc, ev.Time(monoEpoch))
        st.parser = nil
        if unused.Len() > 0 {
            // Pipelined: next message starts immediately.
            st.pendingBuf.Append(unused.Bytes())
        }
    }
}
```

You need to figure out:
- The real `akinet.TCPBidiID` constructor (check `pcap/stream.go::newTCPFlow` for the pattern)
- A `memview` builder for byte slices (look at how `pcap/net_parse.go` does it)
- `toParsedNetworkTraffic`: fill in `SrcIP`/`DstIP`/`SrcPort`/`DstPort`. **For Phase 2, synthesize plausible values by reading `/proc/<pid>/net/tcp` for the (pid, ssl_ctx→fd→sock) tuple.** See OBI `bpf/generictracer/get_conn_info_from_fd` for the kernel-side approach (more work but cleaner), or do it in userspace for Phase 2 (simpler).

Write a unit test in `ebpf/events/adapter_test.go` (no eBPF needed — just feed pre-recorded byte sequences and assert `akinet.HTTPRequest` is emitted).

### 2. Add the `--enable-https-capture` flag set to `apidump`

In `cmd/internal/apidump/apidump.go`, add (mirror the design doc §5.5 table):

```go
enableHTTPSCapture       bool
httpsLibraries           []string
httpsTargetNamespaces    []string
httpsBodySizeCap         uint32
httpsCaptureMode         string  // headers | truncated | full
privacyMode              string  // standard | strict | dry-run
```

Plumb into `apidump.Args`. The apidump.go flag-binding section is around line 200-300.

### 3. Integrate `ebpf.Collect` into `apidump/apidump.go`

After the existing `pcap.Collect` goroutine spawn (around line 991), conditionally start eBPF:

```go
if args.EnableHTTPSCapture {
    doneWG.Add(1)
    go func() {
        defer doneWG.Done()
        ebpfArgs := ebpf.Defaults()
        ebpfArgs.MaxCaptureBytes     = args.HTTPSBodySizeCap
        ebpfArgs.EnforcePIDAllowlist = true   // production: strict
        ebpfArgs.FactorySelector     = facts  // same factories pcap uses
        ebpfArgs.Out                 = parsedOutChan  // SAME channel pcap writes to
        if err := ebpf.Collect(ctx, ebpfArgs); err != nil {
            errChan <- interfaceError{interfaceName: "ebpf", err: err}
        }
    }()
}
```

Key point: the **same** `parsedOutChan` and `trace.Collector` chain. No changes downstream.

### 4. Exclude port 443 from cBPF filter when eBPF is active

In `apidump/net.go::createBPFFilters`, append a negation clause `and not (tcp port 443)` to each inbound filter when `args.EnableHTTPSCapture` is set. Keep this behind a knob (`--https-cbpf-exclude-port=443` defaulting to 443) so customers using non-standard HTTPS ports can override.

Update `tls_conn_tracker/` to remain *enabled* — we still want handshake metadata for ALPN/SNI/cipher even when bodies come from eBPF.

### 5. Remove the "HTTPS unsupported" warning when eBPF is active

In `apidump/summary.go` line 298, gate the message:

```go
} else if totalCount.TLSHello > 0 && !args.EnableHTTPSCapture {
    // existing message
}
```

When `EnableHTTPSCapture` is true, replace with a coverage report:
> "HTTPS capture active: attached N libssl probes, captured M HTTPS requests from K processes."

### 6. Production process discovery — CRI integration

Replace `ebpf/discovery/proc.go`'s polling Watch() with a real watcher:

- Inotify on `/proc` (look at OBI `pkg/appolly/discover/watcher_proc_linux.go`).
- Filter by Kubernetes namespace using `integrations/kube_apis/`.
- Filter by container metadata using `integrations/cri_apis/`.

Surface `--https-target-namespaces` as a comma-separated allowlist. When empty, fall back to the existing `apidump` discovery behaviour (all namespaces in scope).

Add new file `ebpf/discovery/kube.go` (build-tag-gated) that wraps the existing kube/CRI helpers.

### 7. Sampling layers 1, 2, 5

From design doc §6.2:

**Layer 1 (body truncation):** already done — `max_capture_bytes` knob in BPF. Verify the userspace cap matches what was loaded.

**Layer 2 (per-PID rate cap):** add a new BPF map `pid_rate_bucket` keyed by `tgid`, value `{tokens uint32, last_refill_ns uint64}`. In `emit_event()` in `libssl.bpf.c`, decrement tokens; if zero, return without copying. Userspace refills via a periodic `BPF_MAP_UPDATE_ELEM`.

**Layer 5 (CPU thermostat):** read `/proc/self/stat` once per second from a goroutine, compute %CPU. If > 5% sustained for 10s, halve the `max_capture_bytes` knob (via `Variables[]` rewrite). When CPU drops back below 3% for 30s, raise it back. Log every transition.

### 8. Telemetry

In `apidump/apidump.go` or `ebpf/collect_linux.go`, every 30s emit:
- `ebpf_probes_attached` (gauge, per-library)
- `ebpf_events_received_total` (counter)
- `ebpf_events_dropped_total` (counter, from ringbuf overflow query)
- `ebpf_bytes_captured_total` (counter)
- `ebpf_flows_active` (gauge, from `adapter.Snapshot()`)
- `ebpf_cpu_percent` (gauge)

Wire into the existing telemetry pipeline (`telemetry/`). Look at how `apidump/apidumpTelemetry` works today.

### 9. DaemonSet manifest

Update `cmd/internal/kube/daemonset/` templates and `cmd/internal/kube/run.go` to add the privileges from design doc §8.1:

```yaml
hostPID: true
securityContext:
  capabilities:
    add: [BPF, PERFMON, NET_ADMIN]
volumeMounts:
- { name: sys-kernel-debug, mountPath: /sys/kernel/debug }
- { name: sys-fs-bpf,       mountPath: /sys/fs/bpf }
- { name: host-proc,        mountPath: /host/proc, readOnly: true }
volumes:
- { name: sys-kernel-debug, hostPath: { path: /sys/kernel/debug } }
- { name: sys-fs-bpf,       hostPath: { path: /sys/fs/bpf } }
- { name: host-proc,        hostPath: { path: /proc } }
```

Gate the privilege add behind a `--enable-https-capture` flag on `kube run` and the helm fragment generator. Customers who don't want HTTPS capture continue running with current minimal privileges.

### 10. Build pipeline

Update `Makefile`:
```makefile
build-ebpf: clean
	go generate ./ebpf/loader/...
	go build -tags insights_bpf -o bin/postman-insights-agent .
```

Update `build-scripts/Dockerfile` to install `clang`, `llvm`, `libbpf-dev`, `bpftool`, generate `vmlinux.h`, run `go generate`, then build with `-tags insights_bpf`.

Update `.circleci/config.yml` to run both `make build` (no eBPF, current behaviour) and `make build-ebpf` (Linux only).

## Common failure modes

1. **Double-counting:** pcap captures port 443 packets *and* eBPF captures the same bytes' plaintext. Always exclude 443 from cBPF when eBPF active. Verify with `tcpdump` running alongside.

2. **Adapter buffer unbounded growth:** if a flow never produces a complete HTTP message (malformed stream, partial download abandoned), `pendingBuf` grows forever. Cap at 64 KiB per flow; on overflow, drop the flow.

3. **TCPBidiID collisions:** if `syntheticBidiID(key)` accidentally collides with a real pcap-side bidi ID, downstream dedup will be wrong. Use the high bit or a synthetic interface name to namespace them.

4. **Kube apiserver throttling:** discovery that lists pods on every refresh will get rate-limited. Use a watch + cache (OBI does this in `pkg/appolly/discover/watcher_kube.go`).

5. **Privileges insufficient at runtime but verifier passes:** `securityContext` is for the pod, but the **container runtime** also needs to honor `CAP_BPF`. Some hardened K8s setups strip caps via PSPs/PSAs. Test on the most-restrictive customer cluster type before claiming done.

6. **DaemonSet restart loop on kernel mismatch:** if `vmlinux.h` was generated on a different kernel than the host runs, BPF load fails. Mitigation: use libbpf CO-RE (already in place) and ship pre-compiled `.o` files for amd64+arm64. The host kernel's BTF (`/sys/kernel/btf/vmlinux`) is read at runtime for relocation.

## Validation

```sh
# 1. Default build unchanged.
go build ./... && go vet ./...

# 2. eBPF build clean.
make build-ebpf

# 3. All tests pass.
make mock && go test ./...
sudo -E go test -tags insights_bpf ./ebpf/...

# 4. End-to-end on a kind cluster.
kind create cluster
kubectl apply -f cmd/internal/kube/daemonset/testdata/https-capture.yaml
# Deploy two test workloads in two namespaces
kubectl apply -f docs/phases/phase-2-test-workloads.yaml
# Generate HTTPS traffic
kubectl exec -n test-py -- python -c 'import requests; [requests.get("https://example.com") for _ in range(100)]'
kubectl exec -n test-node -- node -e '...'
# Verify the agent received both
kubectl logs -n postman-insights ds/postman-insights-agent | grep "ebpf: received"

# 5. Namespace filtering: enable only test-py, verify test-node traffic is NOT captured.

# 6. Drop & latency budget at sustained load.
```

## Handoff to Phase 3 / Phase 4

Update:
- `ebpf/README.md` — mark Phase 2 components ✅
- `docs/https-capture-design.md` §9 — note any architectural deltas
- `docs/phases/phase-2-results.md` — kernel versions tested, throughput observed, drop rates, CPU%

Things Phase 3 (Go) will rely on:
- The cilium/ebpf loader supports loading additional .bpf.o files alongside libssl
- `discovery/` can be extended to detect Go binaries (look for `.gopclntab` section)
- The adapter's flow keying generalizes — Phase 3 events will have the same `(pid, ssl_ctx, dir)` shape but `ssl_ctx` will be a goroutine address instead

Things Phase 4 (Privacy) will rely on:
- The full `akinet.ParsedNetworkTraffic` is flowing through `data_masks/` unchanged
- `--privacy-mode` flag is wired but currently a passthrough
- Body-size cap works end-to-end
