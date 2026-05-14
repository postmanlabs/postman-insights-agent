# Phase 3 — Multi-Go-Version Test Matrix

Phase 3 task #5 verification. Tested on arm64 in the
`pia-bpf-dev` dev container (LinuxKit kernel 6.12).

## Versions covered

| Go version | Release date | Notes |
|---|---|---|
| 1.21.13 | 2024-08-13 | Last 1.21 patch; predates loopvar semantics finalisation. |
| 1.22.10 | 2024-11-06 | Loopvar default, range-int. |
| 1.23.4  | 2024-12-03 | Iterators GA. |
| 1.24.13 | 2025-08-12 | Container's default. |

## Test workload

A trivial `http.ListenAndServeTLS` server on `:9443` built with each
toolchain × `{default, -ldflags="-s -w"}`. Three curl GETs per probe
invocation.

## Results

```
server_1.21.13                   attach=1 req=3 resp=3 err=0
server_1.21.13_stripped          attach=1 req=3 resp=3 err=0
server_1.22.10                   attach=1 req=3 resp=3 err=0
server_1.22.10_stripped          attach=1 req=3 resp=3 err=0
server_1.23.4                    attach=1 req=3 resp=3 err=0
server_1.23.4_stripped           attach=1 req=3 resp=3 err=0
server_1.24.13                   attach=1 req=3 resp=3 err=0
server_1.24.13_stripped          attach=1 req=3 resp=3 err=0
```

**Perfect 8/8 across the matrix.** Every Go version × stripped/unstripped
combination yields: uprobe attach success, 3/3 REQ captured, 3/3 RESP
captured, zero errors.

## What this confirms

1. **The Go register ABI is stable from 1.21 → 1.24.** Our BPF programs
   read goroutine pointer (`r14`/`x28`), return register (`rax`/`x0`),
   and argument registers (per-arch) via the same offsets. No Go release
   in this window broke them.

2. **Symbol names are stable.** `crypto/tls.(*Conn).Write` and
   `crypto/tls.(*Conn).Read` resolve cleanly in every version's .symtab
   AND in every version's .gopclntab.

3. **Pclntab format compatibility.** `debug/gosym.NewLineTable` auto-
   detects Go 1.18+ pclntab v2 format and parses it correctly for all
   four versions.

4. **Stripped-binary fallback path is robust.** `-ldflags="-s -w"`
   removes .symtab entirely; the pclntab fallback recovers the same
   (file offset, size) result. RET-site count matches between
   stripped and unstripped builds.

## What this does NOT cover

- Go 1.17 and 1.18 — these introduced the amd64 register ABI; in
  principle the same code should work but we haven't tested it. Likely
  fine; revisit if a customer reports issues.
- Go 1.25+ — not released to general availability at test time.
- amd64 architecture — the dev container is arm64. The amd64 path
  shares all source code and is exercised by the `disasm_x86_test.go`
  unit tests, but end-to-end attach verification on amd64 needs a
  Linux/amd64 CI runner (see TODO in `docs/progress.md`).
- Tip of Go HEAD — typically broken at any moment; not a target.

## How to reproduce

```bash
# Install older Go toolchains in the dev container.
docker exec pia-bpf-dev bash -c '
  for v in 1.21.13 1.22.10 1.23.4; do
    go install golang.org/dl/go${v}@latest
    /go/bin/go${v} download
  done
'

# Build the test workload with each toolchain.
docker exec pia-bpf-dev bash -c '
  for v in 1.21.13 1.22.10 1.23.4 1.24.13; do
    if [ "$v" = "1.24.13" ]; then GO=go; else GO=go${v}; fi
    $GO build -o /tmp/gomatrix/server_${v} ./server.go
    $GO build -ldflags="-s -w" -o /tmp/gomatrix/server_${v}_stripped ./server.go
  done
'

# Run the test harness.
docker exec pia-bpf-dev bash /tmp/matrix_test.sh
```

The harness script is committed at `test/gomatrix/matrix_test.sh`.
