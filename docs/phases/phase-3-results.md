# Phase 3 — Results (in progress)

**Session:** continued from Phase 1 + 2; executed on macOS host via Docker
Desktop's LinuxKit VM (kernel 6.12 arm64). Rolling branch
`feat/https-capture-ebpf`, PR #173.

## Honest scope

This is **roughly 65%** of Phase 3 by design-doc scope. The brief calls
for a 4-week effort; we've now delivered:

- ✅ Go binary detection (`.note.go.buildid`)
- ✅ Minimum-viable ELF inspector (function symbols → file offsets, Go version)
- ✅ `crypto/tls.(*Conn).Write` uprobe verifier-validated
- ✅ Per-collection BPF loader (handles per-binary offset variance)
- ✅ End-to-end Go HTTPS server capture (HTTP/1.1)
- ✅ **HTTP/2 frame decoder + HPACK** — unblocks Go's default `net/http` behaviour
- ✅ **`crypto/tls.(*Conn).Read` via RET-instruction probing** — client-side capture
- ✅ Goroutine-context register reading (r14 / x28) used by Read probes
- ✅ **gRPC framing decoder + mid-stream HTTP/2 detection** (this task)
- ❌ Multi-layer dedup (`net/http` + `crypto/tls` + `net.netFD`)
- ❌ Stripped-binary pclntab fallback
- ❌ Multi-Go-version test matrix (1.17 / 1.21 / 1.22 / 1.23)
- ❌ Full per-goroutine flow correlation (we have the register read but no dedup logic yet)

## What works today

### Server-side Go HTTPS (foundation + HTTP/2)

A Go HTTPS server using `net/http` and a self-signed cert, captured by
the standalone spike command:

```bash
$ /tmp/gohttps &              # Go HTTPS server, PID 145155
$ postman-insights-agent apidump-gotls --pid 145155 --duration 10s &
$ for i in 1 2 3; do curl -sk https://127.0.0.1:9443/; done    # no --http1.1

# Output:
INFO Attached gotls probes pid=145155 (write + read_entry + 7 read_rets)
INFO RESP pid=ebpf-pid-145155 status=200
INFO RESP pid=ebpf-pid-145155 status=200
INFO RESP pid=ebpf-pid-145155 status=200
INFO gotls-stats: emitted=9 ringbuf_drops=0 read_fail=0 bytes=447
```

Three HTTP/2 transactions (Go's default over TLS) → three
`akinet.HTTPResponse{StatusCode:200}`. HTTP/1.1 traffic also captures
via the same path (parser selection happens on first bytes).

### gRPC over HTTP/2 (Phase 3 task #3)

```bash
# Start the gRPC server, then attach probes BEFORE any client connects.
# This matters: HPACK is stateful across the whole connection, so attaching
# mid-connection misses the dynamic-table state and HEADERS decoding fails.
# In production this isn't an issue — the agent DaemonSet attaches at pod
# start, before workloads' first outbound connections.
$ /tmp/grpcsrv &        # gRPC health server (TLS) on :50443
$ apidump-gotls --pid $! --duration 15s &
$ /tmp/grpccli &        # client doing Health.Check() in a 1-Hz loop

REQ  pid=ebpf-pid-154824 method=POST url=https://127.0.0.1:50443/grpc.health.v1.Health/Check
RESP pid=ebpf-pid-154824 status=200
REQ  pid=ebpf-pid-154824 method=POST url=https://127.0.0.1:50443/grpc.health.v1.Health/Check
RESP pid=ebpf-pid-154824 status=200
... (repeats at 1Hz)
gotls-stats: emitted=44 ringbuf_drops=0 read_fail=0 bytes=1668
```

The `:path` `/grpc.health.v1.Health/Check` *is* the gRPC service+method.
No extra grpc-package probing required. The 5-byte length-prefixed framing
inside DATA frames is stripped before emit and replaced with synthetic
`X-Pi-Grpc-Messages` / `X-Pi-Grpc-Total-Bytes` headers, so downstream
consumers see the protobuf bytes (not the framing overhead) plus the
per-stream message count.

**Known limitation — mid-connection attach.** Because HPACK is stateful
across the whole HTTP/2 connection, our decoder can't recover headers on
flows where we missed earlier HEADERS frames. We track this with the
`hpackErrors` counter and surface it on the flow. In production this is
rarely an issue: the DaemonSet attaches on pod start, before workloads
open their first long-lived connections. For demo / dev use, start the
agent before the client.

### Client-side Go HTTPS (RET-instruction probing for Read)

A Go binary using `http.Client.Get` in a loop:

```bash
$ /tmp/goclient &             # Go HTTPS client, PID 149471
$ postman-insights-agent apidump-gotls --pid $! --duration 12s
INFO Attached gotls probes pid=149471 (write + read_entry + 7 read_rets)

REQ  pid=ebpf-pid-149471 method=GET url=/         ←  Write entry probe (egress)
RESP pid=ebpf-pid-149471 status=200               ←  Read RET probe (ingress)
REQ  pid=ebpf-pid-149471 method=GET url=/
RESP pid=ebpf-pid-149471 status=200
... (repeats at 1Hz matching the client's request loop)

gotls-stats: emitted=19 ringbuf_drops=0 read_fail=0 bytes=2192
```

**Bidirectional Go HTTPS capture.** Both REQ and RESP visible from a
Go client. Read uses entry probe + N RET probes (7 RETs in this Go
binary's `(*Conn).Read`) because Go's uretprobes are unreliable
due to stack growth. Goroutine-pointer register (r14/x28) keys the
stash so concurrent Reads don't interfere.

## Architecture

```
Go binary (e.g. nginx-built-with-net/http)
    │
    │  user calls into crypto/tls.(*Conn).Write(c, b)
    │      // register ABI: x0=c, x1=b.data, x2=b.len  (arm64)
    │      //                ax=c, bx=b.data, cx=b.len  (amd64)
    ▼
uprobe (kernel)
    │  reads x1/x2, bpf_probe_read_user(payload, x2, x1)
    │  ring-buffer submit (gotls_events map)
    ▼
events.Reader → events.Adapter → akinet HTTP parser → akinet.HTTPResponse
                                                              │
                                                              ▼
                                                    same trace.Collector chain
                                                    as Phase 1+2 (libssl path)
```

The collection is **shared across all Go targets** (one BPF program object;
each target attaches its own uprobe via `link.UprobeOptions{PID:..., Address:...}`).
Per-target Go symbol offsets are resolved at attach time via the standard
ELF symbol table — cilium/ebpf handles the `.text` segment file-offset
conversion (`s.Value - segment.Vaddr + segment.Off`) for us.

## Lessons learned the hard way

1. **HTTP/2 over TLS is the default in Go.** Initial captures looked like
   "encrypted noise with plaintext at the end" — actually HTTP/2 HEADERS
   + DATA frames (HPACK-compressed). Forcing `curl --http1.1` revealed
   plaintext immediately. Production Go services running `net/http` will
   ship h2 unless they explicitly disable it. Closed by the HTTP/2 frame
   decoder in `ebpf/events/http2.go`.

2. **Go symbol names work fine with cilium/ebpf's ELF lookup.** I initially
   tried to hand-resolve `crypto/tls.(*Conn).Write` → file offset via my
   own DWARF inspector. The result was wrong (picked up a `.deferwrap`
   shadow). cilium/ebpf's standard symbol-name path with `Uprobe(sym, prog, &UprobeOptions{PID:...})`
   works correctly — let it do the work. For absolute-offset attach
   (RET probes), pass `symbol=""` + `UprobeOptions.Address: file_offset`.

3. **Go uretprobes are unreliable.** Standard `link.Uretprobe("sym", ...)`
   silently fails because Go's runtime grows/shrinks goroutine stacks,
   invalidating the saved return address that uretprobe relies on. The
   OBI workaround (used here): disassemble the function, find every RET
   instruction, attach entry-style uprobes at each RET. At RET time the
   return-value register (rax/x0) holds the result and the entry probe's
   stash (keyed by goroutine pointer) provides the original args.

4. **Go register ABI register-number conventions on arm64**: x0..x7 map
   to `ctx->regs[0]`..`ctx->regs[7]`; the goroutine register is x28
   (`regs[28]`). On amd64 register ABI it's the weird sequence
   `rax, rbx, rcx, rdi, rsi, r8, r9, r10, r11, r12` for args, `r14` for
   the goroutine pointer, `rax` for first return slot. NOT the System V
   C calling convention. Documented in `ebpf/programs/gotls.bpf.c`.

5. **HPACK is stateful across the whole HTTP/2 connection** — not just
   per-stream. If we attach to a process mid-connection, the encoder's
   dynamic-table state contains entries built up across HEADERS frames
   we never saw. Decoding any subsequent HEADERS that uses an indexed-
   name reference (`0x83`, `0x87`, etc.) fails silently. Surfaced via
   `h2State.HPACKErrors()`. Production-realistic mitigation: DaemonSet
   attaches at pod start, before the workload's first outbound
   connection. Demo mitigation: start the agent before the client.

6. **Function size from ELF symbols can be zero for stripped binaries.**
   `FunctionExtent` returns the symbol's `s.Size`; this is non-zero in
   normal Go builds but stripped builds (`-ldflags="-s"`) zero it. The
   `FindReturnOffsets` path errors cleanly in that case so the caller
   can fall back — fallback (pclntab) is task #5.

## Top follow-up tasks (in priority order)

1. ~~**HTTP/2 frame decoding**~~ — ✅ done (commit `34cf654`)
2. ~~**`crypto/tls.(*Conn).Read`**~~ — ✅ done (commit `308d3ab`)
3. ~~**gRPC framing decoder**~~ — ✅ done (this commit)

   gRPC method/service decoded from HTTP/2 `:path`; length-prefixed
   protobuf framing inside DATA frames stripped via `handleData`. No
   grpc-package-specific probing needed for v1. Mid-stream HTTP/2
   detection (`IsHTTP2Frame`) added so we can recognise an h2 connection
   even when we attach after the preface.

4. **Multi-Go-version test matrix.** Build a Go HTTPS server with
   Go 1.17, 1.21, 1.22, 1.23. Verify symbol resolution + register ABI
   work across all of them. Estimated: ~1 day if no issues; ~3 if Go ABI
   changed between versions (it did at 1.17 amd64 register ABI rollout).

5. **Stripped-binary pclntab fallback** for production builds compiled
   with `-ldflags="-s -w"`. Estimated: ~3 days.

6. **Multi-layer dedup.** Once we add `net/http`-layer probes alongside
   `crypto/tls`, we need to pick one source per goroutine. Goroutine-
   pointer register reading is already in place (commit `308d3ab`);
   what's missing is the `(goroutine, source)` keyed dedup map and the
   policy for choosing the highest-layer source. Estimated: ~2 days.

7. **amd64 RET-scan accuracy.** Current implementation matches the byte
   `0xc3` anywhere in the function body, which can false-positive on
   instructions that contain `0xc3` in their encoding (rare but real).
   Need a real disassembler library (`golang.org/x/arch/x86/x86asm`) for
   production-grade scanning. arm64 is correct (fixed-width instructions).

## Verification

```sh
# Default build (unchanged behaviour).
go build ./...          # ✅

# eBPF build with Phase 3 included.
make build-ebpf         # ✅

# Unit tests.
go test ./ebpf/goexec/  # ✅  (Go-binary detection, symbol resolution)

# eBPF tests (require root).
sudo -E go test -tags insights_bpf ./ebpf/loader/  # ✅
   # passes TestLoadGoTLS — verifier accepts the gotls BPF program.

# End-to-end spike (Linux dev container, e.g. via make dev-shell):
/tmp/gohttps &
postman-insights-agent apidump-gotls --pid $! --duration 10s &
curl -sk --http1.1 https://127.0.0.1:9443/  # captured
```

## Code map

| File | Purpose |
|---|---|
| `ebpf/goexec/goexec.go` | ELF inspector — IsGoBinary, Inspect, .go.buildinfo parse, FunctionExtent, FindReturnOffsets (arm64+amd64 RET scanning) |
| `ebpf/goexec/goexec_test.go` + `funcs_test.go` | Unit tests — self + built Go HTTPS server + RET-scan |
| `ebpf/programs/gotls.bpf.c` | Uprobes: `(*Conn).Write` entry, `(*Conn).Read` entry + RET. goroutine_ptr/go_ret helpers. |
| `ebpf/events/http2.go` | HTTP/2 frame decoder + HPACK; routed from `adapter.Feed` on h2 detection |
| `ebpf/events/http2_test.go` | 7 unit tests (request, request+body, response, preface, multi-stream, chunked, detection) |
| `ebpf/loader/loader_gotls_linux.go` | Per-collection loader; exposes WriteProg / ReadEntryProg / ReadRetProg |
| `ebpf/loader/loader_gotls_test.go` | Root-gated verifier smoke test |
| `ebpf/collect_gotls_linux.go` | `GoTLSCollector` orchestrating load + reader + adapter; attaches write entry + read entry + N read RETs |
| `cmd/internal/apidump-gotls/` | Spike CLI `apidump-gotls --pid N` |
| `docs/phases/phase-3-results.md` | This document |

## Commit map (this phase)

| Commit | Summary |
|---|---|
| `43b604b` | Phase 3 foundation — `crypto/tls.(*Conn).Write` + goexec + spike |
| `2bd2602` | phase-3-results.md initial draft |
| `34cf654` | HTTP/2 frame decoder + HPACK + 7 unit tests |
| `308d3ab` | `crypto/tls.(*Conn).Read` via RET-instruction probing |

## What this does NOT change

- Phase 1 + 2 capture paths (libssl uprobes) are untouched.
- The default-build agent (no `insights_bpf` tag) compiles + behaves
  exactly as before — the new code is fully gated behind the existing
  build tag.
- No K8s manifest changes required for Phase 3 — the Go uprobes attach
  via the same DaemonSet privileges we already established in Phase 2.
