# `ebpf/` — HTTPS capture subsystem

This package adds **HTTPS traffic capture** to the Postman Insights Agent via eBPF uprobes on userspace TLS libraries. The full design lives in [`docs/https-capture-design.md`](../docs/https-capture-design.md).

## Current status (Phase 1 scaffold)

This is **Phase 1 scaffolding** committed on branch `feat/https-capture-ebpf`. The code structurally implements end-to-end libssl uprobe → ringbuf → adapter → akinet pipeline, but:

| Component | Status |
|---|---|
| BPF C source (`programs/libssl.bpf.c`) | ✅ Written |
| Go loader (`loader/`) | ✅ Written; requires bpf2go-generated bindings |
| Ringbuf reader (`events/reader_linux.go`) | ✅ Written |
| Decoder (`events/decode.go`) | ✅ Written |
| Adapter to akinet (`events/adapter.go`) | 🟡 Scaffold — Phase 2 wires the `Parse()` call |
| Process discovery (`discovery/`) | 🟡 Polling /proc, Phase 2 adds CRI/Kube |
| Uprobe attachment (`uprobes/`) | ✅ Written (dynamic libssl); static libssl deferred |
| Top-level `Collect()` | ✅ Written |
| Spike command (`cmd/internal/apidump-ebpf/`) | ✅ Written |
| `bpf2go` integration | ⏳ Not run yet (requires clang + vmlinux.h on host) |
| End-to-end test | ⏳ Phase 1 exit criterion |

## Build tags

The eBPF code paths are gated behind two conditions:

- `linux` — eBPF is a Linux kernel facility.
- `insights_bpf` — opt-in build tag that requires `bpf2go` to have run.

| Tag combination | Behaviour |
|---|---|
| Default (`go build .`) | Stubs compile everywhere. `apidump-ebpf` prints "not compiled in". |
| `-tags insights_bpf` on Linux | Real eBPF code. Requires `bpf2go` artifacts to be present. |
| `-tags insights_bpf` on macOS | Build fails (loader_linux.go won't match). Use Linux dev VM or container. |

## How to actually build & run the spike

On a Linux 5.8+ host (or VM) with `clang ≥ 14`, `llvm-strip`, `bpftool`:

```bash
# 1. Generate vmlinux.h from the running kernel's BTF.
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/programs/vmlinux.h

# 2. Generate Go bindings from the BPF C sources.
go install github.com/cilium/ebpf/cmd/bpf2go@latest
cd ebpf/loader && go generate ./... && cd ../..

# 3. Build the spike binary with the insights_bpf tag.
go build -tags insights_bpf -o bin/postman-insights-agent .

# 4. Run as root (or with CAP_BPF + CAP_PERFMON).
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

## What Phase 2 will add to this package

See `docs/https-capture-design.md §9 (Phase 2)`. In summary:

1. Wire `events/adapter.go` to call `parser.Parse()` with proper memview / TCPBidiID.
2. Replace `discovery/proc.go` polling with inotify + CRI events.
3. Integrate `ebpf.Collect` into the main `apidump` command behind `--enable-https-capture`.
4. Exclude port 443 from the cBPF filter when eBPF is active.
5. Add CLI flags, telemetry, K8s manifest updates.
6. Sampling layers 1, 2, 5 (truncation, per-PID rate cap, CPU thermostat).
