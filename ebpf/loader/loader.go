// Package loader handles compiling, loading, and attaching the eBPF programs
// used for HTTPS capture.
//
// BUILD TAGS
//
// The "real" loader (loader_linux.go) is gated behind `linux && insights_bpf`.
// Without the `insights_bpf` build tag, a no-op stub (loader_stub.go) is used
// instead. This lets `go build`, `go test`, and `go vet` succeed on any
// platform during development, without requiring clang/llvm/vmlinux.h or
// bpf2go-generated artifacts to be present.
//
// To build the real eBPF subsystem:
//
//  1. Install clang ≥ 14 and llvm-strip.
//  2. Generate vmlinux.h on the build host (see ../programs/README.md).
//  3. Run `go generate ./ebpf/loader/...` to compile the .bpf.c files and
//     emit bpf2go bindings.
//  4. Build with `go build -tags insights_bpf ./...`.
//
// See docs/https-capture-design.md §9 (phased delivery plan) for context.
package loader

// This file exists only to host the package-level documentation above. The
// actual implementations are in loader_linux.go (real) and loader_stub.go
// (no-op fallback).
