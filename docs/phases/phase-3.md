# Phase 3 — Go support via DWARF-driven uprobes

**Starting branch:** `feat/https-capture-ebpf` after Phase 2 has merged.

**Working branch:** `feat/https-capture-ebpf-phase3`.

**Requires:** Linux dev host. Familiarity with Go internals (interfaces, slices, goroutine struct layout). Patience.

**Effort:** 4 weeks. Easily the hardest of the five phases. Budget conservatively.

---

## Goal

The agent captures HTTPS traffic from Go services that use pure-Go `crypto/tls` (i.e. don't link OpenSSL). Coverage spans Go 1.17 through current Go release. Both `net/http` and `google.golang.org/grpc` over TLS are supported.

## Hard exit criteria

1. A Go HTTPS server using `net/http` and a self-signed cert is fully captured: requests, responses, status codes, paths, headers up to the configured cap.
2. A Go HTTPS client (`http.Get("https://...")`) is captured.
3. A gRPC client and server (`google.golang.org/grpc` with `credentials.NewTLS`) are captured.
4. Works across Go 1.17, 1.21, 1.22, and current release. Test against binaries compiled with each.
5. CPU overhead ≤ 7% at 1000 RPS (slightly higher budget than Phase 1 because of multi-layer probe dedup).
6. Stripped binaries (compiled with `-ldflags="-s -w"`) work — the DWARF inspector must handle the strip-friendly fallback (Go's `pclntab` symbol table is preserved even when DWARF is stripped).

## Prerequisites — read these first

In the agent repo:
- `docs/phases/phase-2-results.md` and the full Phase 2 changeset
- `ebpf/uprobes/openssl.go` — pattern this work mirrors but on `/proc/<pid>/exe` instead of `libssl.so`
- `ebpf/discovery/` — extend to detect Go binaries

In OBI (`../insights-ebpf-research/obi/`):
- `bpf/gotracer/go_offsets.h` — full list of struct field offsets we'll need
- `bpf/gotracer/go_common.h` — `GO_PARAM1`/`GO_PARAM2` macros, goroutine address extraction
- `bpf/gotracer/go_nethttp.c` — net/http probes (lines 1–600 are the core)
- `bpf/gotracer/go_net_tls.c` — crypto/tls probes
- `bpf/gotracer/go_net.c` — netFD socket-level probes (the lowest layer)
- `bpf/gotracer/go_grpc.c` — gRPC stream probes
- `pkg/internal/goexec/structmembers.go` — **the DWARF inspector. Read this whole file.**
- `pkg/internal/goexec/offsets.go` — Offsets struct + InspectOffsets entry point
- `configs/offsets/tracker_input.json` — declarative list of struct fields needed
- `configs/offsets/std_inspect.go` — DWARF walker for the Go stdlib

In Datadog (`../insights-ebpf-research/datadog-agent/`):
- `pkg/network/go/bininspect/dwarf.go` — alternate DWARF inspector (often more polished)
- `pkg/network/go/bininspect/symbols.go` — handling stripped binaries via pclntab
- `pkg/network/go/bininspect/pclntab.go` — pure pclntab parsing (no DWARF needed)

Read this Go internals doc before starting:
- https://github.com/golang/go/blob/master/src/runtime/HACKING.md (sections on goroutines and stack layout)
- The Go ABI doc for whichever Go versions you're targeting (ABI changed slightly at 1.17 → register-based calling)

## Tasks (in order)

### 1. New BPF programs

Create the BPF C sources under `ebpf/programs/`. Adapt from OBI's `bpf/gotracer/`:

| File | Lines (OBI) | What it does |
|---|---:|---|
| `ebpf/programs/go_common.h` | ~150 | `GO_PARAM*`, `GOROUTINE_PTR`, common types |
| `ebpf/programs/go_offsets.h` | ~150 | Offset enum, must match userspace |
| `ebpf/programs/go_nethttp.bpf.c` | ~1500 | net/http probes (subset for v1) |
| `ebpf/programs/go_net_tls.bpf.c` | ~250 | crypto/tls probes |
| `ebpf/programs/go_net.bpf.c` | ~250 | netFD socket probes (for non-TLS Go) |
| `ebpf/programs/go_grpc.bpf.c` | ~800 | gRPC probes |

**For v1, you do NOT need the entire OBI gotracer.** Trim to:
- `net/http`: `(*Transport).RoundTrip` entry/exit, `(*conn).serve` entry/exit, `readRequest`, `header.writeSubset`
- `crypto/tls`: `(*Conn).Read` entry/exit, `(*Conn).Write` entry/exit
- `net.netFD`: `Read`/`Write` (used to get FD → 4-tuple)
- `grpc`: `server_handleStream`, `ClientConn_Invoke`, `ClientConn_NewStream`

Skip: HTTP/2 server, gin-specific probes, jsonrpc, kafka, mongo, sql, redis. They're not relevant to HTTPS capture.

### 2. DWARF inspector — `ebpf/goexec/`

Port OBI's `pkg/internal/goexec/` into our codebase. New files:

- `ebpf/goexec/inspect.go` — `InspectOffsets(binaryPath) (*Offsets, error)`
- `ebpf/goexec/structmembers.go` — list of struct field offsets we need (mirror `tracker_input.json`)
- `ebpf/goexec/funcs.go` — find function start + return offsets (return offsets needed because uretprobes on Go are unreliable on register-ABI; instead we attach uprobes at each `RET` instruction we find in the body — this is OBI's trick)
- `ebpf/goexec/pclntab.go` — fallback path when DWARF is stripped

The minimum struct fields you'll need offsets for (from OBI tracker_input.json, subset for v1):

```
net/http.Request:       Method, URL, ContentLength, Header
net/url.URL:            Path, Host, Scheme
net/http.Response:      StatusCode, ContentLength
net.TCPAddr:            IP, Port
net.conn:               fd
net.netFD:              laddr, raddr
net/http.persistConn:   conn, tlsState
net/http.conn:          rwc, tlsState
runtime.moduledata:     pcHeader, pclntable, minpc, maxpc, text, etext
```

The `runtime.moduledata` entries are how you locate Go-internal functions in a stripped binary.

### 3. Loader extensions

`ebpf/loader/loader_linux.go`:
- Add a new `go:generate` directive for each Go .bpf.c source.
- Loader needs to set per-binary offsets via `volatile const` rewrite at load time (per-process load — different binaries have different offsets).
- This means **one BPF program collection per target Go binary**, not one collection for the whole agent. Refactor `Loader` to be multi-instance.

This is a real architecture change. Look at OBI `pkg/internal/ebpf/gotracer/gotracer_linux.go::Run` for the per-target instantiation pattern.

### 4. Discovery extension

`ebpf/discovery/`:
- Add `go.go`: detect Go binaries by scanning `/proc/<pid>/exe` for the Go build ID section (`.note.go.buildid`) or the `go.buildid` symbol.
- Emit `GoTarget{PID, BinaryPath, GoVersion, Offsets}` alongside `LibSSLTarget`.

### 5. Multi-layer dedup in `events/adapter.go`

Now we have events arriving from THREE layers for the same byte stream:
1. `crypto/tls.(*Conn).Write` — TLS layer (plaintext, encrypted soon)
2. `net/http.(*Transport).RoundTrip` — HTTP layer (already structured)
3. `net.(*netFD).Write` — socket layer (ciphertext, irrelevant for HTTPS)

Strategy from OBI: **prefer the highest layer that fired.** If we see an HTTP-layer event for this goroutine, ignore the TLS-layer event for the same bytes. Maintain a `(goroutine_addr) → seen_at_http_layer` map keyed by goroutine.

`FlowKey` evolves to add a `Source` field: `LayerHTTP | LayerTLS | LayerSocket`. The userspace adapter dedups based on goroutine + sequence.

### 6. Goroutine context tracking

For correlation we need goroutine IDs, not just PIDs. The goroutine address is in `r14` (Go 1.17+ register ABI, amd64) or via `runtime.g` ptr indirection on older versions.

OBI's `bpf/gotracer/go_common.h::GOROUTINE_PTR(ctx)` macro handles this. Port directly.

### 7. Validation workloads

Create `ebpf/testdata/go-https-server.go`, `go-https-client.go`, `grpc-server.go`, `grpc-client.go`. Build each with multiple Go versions:

```sh
for v in 1.17 1.21 1.22 1.23; do
    docker run --rm -v $(pwd):/src golang:$v go build -o /src/testdata/bin/https-server-$v /src/ebpf/testdata/go-https-server.go
done
```

Test against each binary. Also test against a `-ldflags="-s -w"` stripped variant.

### 8. CPU + memory budget

Run sustained-load test (`wrk` against each Go workload). Targets:
- CPU ≤ 7% per agent pod at 1000 RPS aggregate
- Resident memory ≤ 200 MiB per agent pod with 50 attached Go binaries
- BPF map memory: monitor via `bpftool map show` — should plateau, not grow

## Common failure modes

1. **Go ABI register changes.** Go 1.17 introduced register-based ABI on amd64. Earlier code used stack-based. OBI handles this via `go_offsets.h` ABI version. arm64 has a different register convention. Test on both architectures or document arm64 as deferred.

2. **Function inlining.** Go's compiler may inline small functions like `(*Conn).Read`. Uprobe attach fails silently with "no such function". Mitigation: probe the *caller* one level up if the target was inlined. The pclntab parser detects inlining via the inline tree.

3. **Goroutine migration across threads.** Go's scheduler moves goroutines between OS threads. Our `pid_tgid` keys are useless for correlation. **Use the goroutine address as the correlation key**, not `pid_tgid`. The kernel-side maps need to be keyed accordingly.

4. **Stack growth invalidates pointers.** Go grows goroutine stacks dynamically by copying. If we capture a buffer pointer at uprobe entry, by uretprobe time it may point to freed memory. Mitigation: copy the buffer immediately at entry (we already do this on libssl; same pattern). Don't dereference at exit.

5. **Stripped binaries with no DWARF.** Production binaries are often stripped. Pclntab is still present (Go requires it for stack traces). Implement pclntab-only fallback that finds function symbols but cannot read struct offsets — for stripped binaries we fall back to socket-layer probes and lose some fidelity. Document this trade-off.

6. **Static vs dynamic linking of TLS in cgo binaries.** A Go binary that uses cgo + OpenSSL has BOTH `crypto/tls` AND libssl symbols. We don't want to attach both — pick one. The simple rule: if the binary has libssl mapped, prefer libssl uprobes (already in Phase 1); otherwise use Go uprobes.

7. **Verifier complexity limits.** Go BPF programs are larger and the verifier may reject them on older kernels with low instruction limits (1M before 5.2, 1M still on some hardened kernels). OBI uses BPF tail calls to break programs apart. We may need to do the same.

## Validation

```sh
# 1. Default build clean.
go build ./...

# 2. eBPF build with new Go support clean.
make build-ebpf

# 3. DWARF inspector tests.
go test ./ebpf/goexec/...

# 4. End-to-end against each Go version's HTTPS server.
for v in 1.17 1.21 1.22 1.23; do
    ./scripts/test-go-https.sh $v
done

# 5. gRPC.
./scripts/test-grpc-tls.sh

# 6. Stripped binary.
./scripts/test-stripped-go.sh

# 7. CPU budget.
./scripts/measure-cpu.sh --workload go-https --rps 1000 --duration 60s
```

## Handoff to Phase 4 / Phase 5

Update:
- `ebpf/README.md` — Go support ✅
- `docs/https-capture-design.md` §4.3 — note any deltas
- `docs/phases/phase-3-results.md`

What Phase 4 will rely on:
- Multi-layer dedup is in place — Phase 4's redaction sees clean, deduped HTTP messages
- Go binary detection is reliable enough to gate `decrypt: false` per Go workload

What Phase 5 (Java) will rely on:
- The multi-source `Layer` enum in `FlowKey` accommodates `LayerJavaIoctl`
- Loader supports loading additional BPF programs at runtime (the Java ioctl kprobe is independent of all other programs)
