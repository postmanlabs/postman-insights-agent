# eBPF programs for the Postman Insights Agent

This directory contains the BPF C source files that implement HTTPS capture.
They are compiled to ELF objects by `cilium/ebpf`'s `bpf2go` codegen, which
also emits Go bindings in the parent `ebpf/loader/` package.

## Files

| File | Purpose | Phase |
|---|---|---|
| `event.h` | ABI-stable event struct shared with Go. | 1 |
| `libssl.bpf.c` | Uprobes for `SSL_read`/`SSL_write`/`SSL_read_ex`/`SSL_write_ex`. | 1 |
| `go_tls.bpf.c` | Uprobes for `crypto/tls.(*Conn).Read`/`Write` and Go HTTP layer. | 3 (TODO) |

## Build prerequisites

The BPF C files are NOT compiled by `go build`. They are compiled by
`bpf2go`, which is run by `go generate` against `ebpf/loader/loader.go`.

Required on the build host:

- `clang` ≥ 14 (we use `-target bpf`)
- `llvm-strip`
- Kernel headers / `vmlinux.h`. This is **generated at build time** from the
  build host's kernel BTF and is **not committed** (per-arch and large):
  ```sh
  bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/programs/vmlinux.h
  ```
  The eBPF Dockerfiles and the `make` build target do this automatically. Two
  constraints follow: the build host's kernel must expose
  `/sys/kernel/btf/vmlinux`, and the build must be **native per-arch** (a
  cross-arch build would bake the wrong `pt_regs` layout — the release builds
  amd64 and arm64 on separate machines). CO-RE relocates the compiled programs
  against the *runtime* kernel, so the builder kernel version need not match the
  deployment kernel. If a build environment cannot expose kernel BTF, drop a
  pre-generated `vmlinux.h` into this directory and the build will use it; for a
  fully deterministic header, source one from [BTFHub](https://github.com/aquasecurity/btfhub).

### Generating bpf2go output locally (IDE / full eBPF build)

`go generate` emits `ebpf/loader/libssl_*_bpfel.go` and `*.o`. These are
**gitignored** — CI regenerates them at build time. Without them, VS Code
may show `undefined: libsslObjects` when gopls type-checks with
`-tags=insights_bpf` (see `.vscode/settings.json`).

**macOS (via Docker — no host bpftool required):**

```sh
make dev-build        # one-time: build the dev container image
make generate-ebpf    # writes vmlinux.h + libssl_*_bpfel.go into your tree
```

Requires Docker Desktop. Reload the editor / restart gopls after running.

**Linux (native toolchain):**

```sh
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/programs/vmlinux.h
cd ebpf/loader && go generate -tags insights_bpf ./...
```

- libbpf headers (`bpf/bpf_helpers.h`, `bpf/bpf_tracing.h`, `bpf/bpf_core_read.h`)
  Provided by the `libbpf-dev` package or vendored.

## How `bpf2go` is invoked

From `ebpf/loader/loader.go`:

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go \
//   -target native \
//   -cc clang \
//   -cflags "-O2 -g -Wall -Werror -fms-extensions -Wno-missing-declarations -Wno-microsoft-anon-tag" \
//   libssl ../programs/libssl.bpf.c -- -I../programs
```

We use `-target native` (not `-target amd64,arm64`): Debian bookworm ships
libbpf 1.1, which lacks the synthetic per-arch `pt_regs` structs needed for
cross-arch codegen, so we build each architecture natively (the release builds
amd64 and arm64 on separate machines). This produces `libssl_bpfel.go`
(little-endian) and `libssl_bpfel.o`, embedded into the Go binary via
`go:embed`. These generated files are git-ignored and regenerated in every
build environment.

## Why GPL license tag

`bpf_probe_read_user()` and several other BPF helpers require the loaded
program to be GPL-licensed (this is a Linux kernel ABI requirement, not a
project license decision). The `char LICENSE[] SEC("license") = "GPL"` in
each `.bpf.c` only affects the BPF object's runtime license metadata. The
source files themselves are Apache-2.0 (matching this repo and OBI upstream).

## Verifier hints (debugging)

When the BPF verifier rejects a program at load time, run:

```sh
postman-insights-agent apidump --enable-https-capture --debug --log-format=json 2>&1 | jq
```

The verifier log includes program PC, register types, and stack state. The
common failure modes are:

1. **Unbounded read** — `bpf_probe_read_user(buf, len, src)` where `len`
   isn't statically bounded. Fix: mask with `(MAX - 1)` for power-of-two MAX.
2. **Invalid map access** — using a pointer returned by `bpf_map_lookup_elem`
   without a NULL check.
3. **Unreachable code / dead instructions** — usually indicates a
   compile-time constant the verifier folded away.
