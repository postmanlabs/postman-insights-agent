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
| `java_tls.bpf.c` | Kprobe on `sys_ioctl` for Java agent bridge. | 5 (TODO) |

## Build prerequisites

The BPF C files are NOT compiled by `go build`. They are compiled by
`bpf2go`, which is run by `go generate` against `ebpf/loader/loader.go`.

Required on the build host:

- `clang` ≥ 14 (we use `-target bpf`)
- `llvm-strip`
- Kernel headers / vmlinux.h. We generate `vmlinux.h` from BTF:
  ```sh
  bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/programs/vmlinux.h
  ```
  This file is **not** checked into the repo (per-arch, large). The build
  scripts generate it during the container build.
- libbpf headers (`bpf/bpf_helpers.h`, `bpf/bpf_tracing.h`, `bpf/bpf_core_read.h`)
  Provided by the `libbpf-dev` package or vendored.

## How `bpf2go` is invoked

From `ebpf/loader/loader.go`:

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go \
//   -target amd64,arm64 \
//   -cc clang \
//   -cflags "-O2 -g -Wall -Werror" \
//   libssl ../programs/libssl.bpf.c -- -I../programs
```

This produces `libssl_bpfel.go` (little-endian) and `libssl_bpfel.o` for each
target architecture, embedded into the Go binary via `go:embed`.

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
