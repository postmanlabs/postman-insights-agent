# `ebpf/` — HTTPS capture subsystem

This package adds **HTTPS traffic capture** to the Postman Insights Agent via eBPF uprobes on userspace TLS libraries. The full design lives in [`docs/https-capture-design.md`](../docs/https-capture-design.md).

## Current status (after Phases 1 + 2)

The libssl uprobe → ringbuf → adapter → akinet pipeline is end-to-end
functional on Linux 5.8+. The `apidump --enable-https-capture` flag turns
it on in production.

| Component | Status |
|---|---|
| BPF C source (`programs/libssl.bpf.c`) | ✅ Compiles, loads past verifier on kernel 6.12 first try |
| Go loader (`loader/`) | ✅ bpf2go bindings generated and committed (arm64; amd64 deferred to CI runner) |
| Ringbuf reader (`events/reader_linux.go`) | ✅ |
| Decoder (`events/decode.go`) | ✅ |
| Adapter to akinet (`events/adapter.go`) | ✅ Real `Parse()` loop with pipelining, chunked delivery, 64 KiB cap, 6 unit tests |
| Process discovery (`discovery/`) | 🟡 Polling `/proc` works; CRI/Kube integration deferred to follow-up |
| Uprobe attachment (`uprobes/`) | ✅ Dynamic libssl (OpenSSL 1.1 & 3.x); static BoringSSL in `node` exe (official Node 20+) |
| Top-level `Collect()` | ✅ |
| Spike command (`cmd/internal/apidump-ebpf/`) | ✅ Validated against curl, Python `requests`, Node `https.get` |
| `apidump --enable-https-capture` integration | ✅ Wired into the production `apidump` command (dedicated collector chain reusing data_masks / rate_limit / backend_collector) |
| cBPF port-443 exclusion | ✅ `--https-cbpf-exclude-port` (default 443) |
| DaemonSet privileges | 🟡 Helper code present (`SidecarOpts.EnableHTTPSCapture`, `HTTPSCaptureVolumes`); not yet wired into `kube inject` / `helm-fragment` / `tf-fragment` |
| Sampling layer 1 (body truncation) | ✅ |
| Sampling layers 2 & 5 (rate cap, CPU thermostat) | ❌ Deferred |
| Telemetry counters | 🟡 Counters exist on adapter; not yet wired into `telemetry/` |
| fd → 4-tuple resolution | ❌ Deferred — IPs zero, PID in Interface field |
| End-to-end on a kind cluster | ❌ Deferred (requires Docker-in-Docker or real Linux host) |

See `docs/phases/phase-1-results.md` and `docs/phases/phase-2-results.md` for
actual measurement numbers, deviations from the design doc, and the
recommended follow-up sequence.

## Build tags

The eBPF code paths are gated behind two conditions:

- `linux` — eBPF is a Linux kernel facility.
- `insights_bpf` — opt-in build tag that requires `bpf2go` to have run.

| Tag combination | Behaviour |
|---|---|
| Default (`go build .`) | Stubs compile everywhere. `apidump-ebpf` prints "not compiled in". |
| `-tags insights_bpf` on Linux | Real eBPF code. Requires `bpf2go` artifacts to be present. |
| `-tags insights_bpf` on macOS | Build fails (loader_linux.go won't match). Use Linux dev VM or container. |

## How to actually build & run

### On macOS (Apple Silicon or Intel) via Docker Desktop

```bash
make dev-build          # one-time: build the dev container image
make dev-shell          # open a shell inside it (repo bind-mounted, --pid=host)

# Inside the shell:
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/programs/vmlinux.h
make build-ebpf         # generates bpf2go bindings + builds insights_bpf binary
./bin/postman-insights-agent apidump-ebpf --duration 60s          # spike
# or for the production path:
./bin/postman-insights-agent apidump --enable-https-capture --project ...
```

### On a Linux host with `clang ≥ 14`, `llvm-strip`, `bpftool`, `libbpf-dev`

```bash
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/programs/vmlinux.h
make build-ebpf
sudo ./bin/postman-insights-agent apidump-ebpf --duration 60s
```

In another terminal, generate HTTPS traffic:

```bash
curl -sv https://example.com/ > /dev/null
```

Expected output in the spike: `REQ method=GET url=...` and `RESP status=200`.

## Package layout

```
ebpf/
├── README.md                    you are here
├── collect.go                   exported ErrUnsupported (all builds)
├── collect_linux.go             Collect() — top-level pipeline (linux+insights_bpf)
├── collect_stub.go              Collect() — no-op (other builds)
├── clock_linux.go               CLOCK_BOOTTIME helper for event timestamps
│
├── programs/                    BPF C sources, compiled to .o by bpf2go
│   ├── README.md
│   ├── event.h                  shared struct ssl_event {…}
│   └── libssl.bpf.c             uprobes for SSL_read/SSL_write/*_ex
│
├── loader/                      cilium/ebpf loader + bpf2go invocation
│   ├── loader.go                package doc
│   ├── loader_linux.go          real Loader (linux+insights_bpf)
│   ├── loader_stub.go           no-op Loader (other builds)
│   └── config.go                load-time knobs
│
├── events/                      ringbuf reader + Go event types + adapter
│   ├── event.go                 SSLEvent + FlowKey
│   ├── decode.go                ringbuf-bytes → SSLEvent
│   ├── reader_linux.go          ringbuf.Reader wrapper (linux+insights_bpf)
│   ├── reader_stub.go           no-op (other builds)
│   └── adapter.go               feeds bytes into akinet parsers (PHASE 2 wiring)
│
├── uprobes/                     symbol resolution + uprobe attach
│   ├── openssl.go               /proc/<pid>/maps walker (all builds)
│   ├── attach_linux.go          Manager.AttachLibSSL (linux+insights_bpf)
│   └── attach_stub.go           no-op (other builds)
│
└── discovery/                   target-PID enumeration
    └── proc.go                  scan + watch /proc; Phase 2 adds CRI integration
```

## What's left after Phases 1 + 2

1. **fd → 4-tuple resolution.** Largest functional gap; the
   `origin/feature/capture-https` branch has a working
   `socketResolver` worth porting.
2. **CRI/Kube discovery.** Replace `/proc` polling with inotify + a kube
   watch+cache.
3. **Sampling layers 2 & 5.** Per-PID rate-cap in BPF; CPU thermostat in Go.
4. **Telemetry wiring.** Counters exist on the adapter; need a 30-second
   emit loop hooked into the existing `telemetry/` pipeline.
5. **Kube subcommand integration.** `--enable-https-capture` on
   `kube inject`, `helm-fragment`, `tf-fragment`.
6. **CI.** amd64 cross-compile of BPF objects; `make build-ebpf` in
   `.circleci/config.yml`; release `Dockerfile` updated to embed bpf2go
   output.
7. **End-to-end kind-cluster test.** Once (1)–(5) land, walk a kind
   cluster through the namespace-filtering exit criterion.
