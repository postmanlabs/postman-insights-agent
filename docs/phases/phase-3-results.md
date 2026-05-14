# Phase 3 — Foundation Results

**Session:** continued from Phase 1 + 2; executed on macOS host via Docker
Desktop's LinuxKit VM (kernel 6.12 arm64). Rolling branch
`feat/https-capture-ebpf`, PR #173.

## Honest scope

This is **roughly 25%** of Phase 3 by design-doc scope. The brief calls
for a 4-week effort; this session delivers the foundation that makes
session-by-session expansion possible:

- ✅ Go binary detection (`.note.go.buildid`)
- ✅ Minimum-viable ELF inspector (function symbols → file offsets, Go version)
- ✅ One BPF uprobe (`crypto/tls.(*Conn).Write`) verifier-validated
- ✅ Per-collection BPF loader (handles per-binary offset variance)
- ✅ End-to-end demo: Go HTTPS server → captured `HTTP/1.1 200 OK` plaintext
- ❌ HTTP/2 frame decoding (Go's `net/http` defaults to h2 over TLS)
- ❌ `crypto/tls.(*Conn).Read` (needs RET-instruction probing for Go's
  unreliable uretprobes)
- ❌ Multi-layer dedup (`net/http` + `crypto/tls` + `net.netFD`)
- ❌ gRPC probes
- ❌ Stripped-binary pclntab fallback
- ❌ Multi-Go-version test matrix (1.17 / 1.21 / 1.22 / 1.23)
- ❌ Goroutine-context tracking via register `r14`

## What works today

A Go HTTPS server using `net/http` and a self-signed cert, captured by
the standalone spike command:

```bash
$ /tmp/gohttps &              # the Go HTTPS server, PID 141438
$ postman-insights-agent apidump-gotls --pid 141438 --duration 10s &
$ curl -sk --http1.1 https://127.0.0.1:9443/ ×3

# Output:
INFO Attached gotls write uprobe to pid=141438 binary=/proc/141438/exe
INFO gotls-raw: pid=141438 ssl_ctx=0x4000096008 len=138 dir=0
     "HTTP/1.1 200 OK\r\nDate: Thu, 14 May 2026 15:56:33 GMT\r\n
      Content-Length: 21\r\nConten"...
INFO RESP pid=ebpf-pid-141438 status=200
INFO RESP pid=ebpf-pid-141438 status=200
INFO RESP pid=ebpf-pid-141438 status=200
INFO gotls-stats: emitted=3 ringbuf_drops=0 read_fail=0 bytes=414
```

3 curls × 1 response/curl → 3 emitted BPF events → 3 parsed
`akinet.HTTPResponse{StatusCode:200}`.

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
   ship h2 unless they explicitly disable it. **This is the most important
   gap to close next.**

2. **Go symbol names work fine with cilium/ebpf's ELF lookup.** I initially
   tried to hand-resolve `crypto/tls.(*Conn).Write` → file offset via my
   own DWARF inspector. The result was wrong (picked up a `.deferwrap`
   shadow). cilium/ebpf's standard symbol-name path with `Uprobe(sym, prog, &UprobeOptions{PID:...})`
   works correctly — let it do the work.

3. **`UprobeOptions.Address` is "absolute address minus addressOffset"**,
   not "raw file offset". Documentation is inconsistent. Recommend always
   passing the symbol name when possible; Address is reserved for cases
   where symbol resolution genuinely fails (e.g., stripped binaries).

4. **Go register ABI register-number conventions on arm64**: x0..x7 map
   to `ctx->regs[0]`..`ctx->regs[7]`. On amd64 register ABI it's the
   weird sequence `rax, rbx, rcx, rdi, rsi, r8, r9, r10, r11, r12` (NOT
   the System V C calling convention). Documented in
   `ebpf/programs/gotls.bpf.c::go_arg`.

## Top follow-up tasks (in priority order)

1. **HTTP/2 frame decoding** in akinet or a new userspace decoder. Without
   this, Go HTTPS capture only works when clients force HTTP/1.1, which
   is unrealistic for production. Estimated: ~3 days. Major work because
   HPACK is a stateful encoder/decoder.

2. **`crypto/tls.(*Conn).Read`**. Needed to capture HTTPS *requests* (the
   spike captures server-side responses; clients are uncovered). Requires
   the RET-instruction probing pattern from OBI's
   `pkg/internal/goexec/funcs.go`. Estimated: ~2 days.

3. **gRPC probes** on `google.golang.org/grpc.(*ServerStream)` etc.
   Probably the highest customer-impact addition. Estimated: ~5 days.

4. **Multi-Go-version test matrix.** Build the spike Go-HTTPS-server with
   Go 1.17, 1.21, 1.22, 1.23. Verify symbol resolution + register ABI
   work across all of them. Estimated: ~1 day if no issues; ~3 if Go ABI
   changed between versions (it did at 1.17 amd64 register ABI rollout).

5. **Stripped-binary pclntab fallback** for production builds compiled
   with `-ldflags="-s -w"`. Estimated: ~3 days.

6. **Multi-layer dedup.** Once we have `net/http` AND `crypto/tls` probes
   firing on the same byte stream, we need to pick one source per
   goroutine. Goroutine-address correlation (read `r14` register) plus a
   `(goroutine, source)` keyed dedup map. Estimated: ~2 days.

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
| `ebpf/goexec/goexec.go` | ELF inspector — IsGoBinary, Inspect, .go.buildinfo parse |
| `ebpf/goexec/goexec_test.go` | Unit tests (self + tiny built Go HTTPS server) |
| `ebpf/programs/gotls.bpf.c` | Uprobe on `crypto/tls.(*Conn).Write` |
| `ebpf/loader/loader_gotls_linux.go` | Per-collection loader for the gotls BPF object |
| `ebpf/loader/loader_gotls_test.go` | Root-gated verifier smoke test |
| `ebpf/collect_gotls_linux.go` | `GoTLSCollector` orchestrating load + reader + adapter |
| `cmd/internal/apidump-gotls/` | Spike CLI `apidump-gotls --pid N` |
| `docs/phases/phase-3-results.md` | This document |

## What this does NOT change

- Phase 1 + 2 capture paths (libssl uprobes) are untouched.
- The default-build agent (no `insights_bpf` tag) compiles + behaves
  exactly as before — the new code is fully gated behind the existing
  build tag.
- No K8s manifest changes required for Phase 3 — the Go uprobes attach
  via the same DaemonSet privileges we already established in Phase 2.
