// SPDX-License-Identifier: Apache-2.0
//
// Package goexec inspects Go ELF binaries to extract the offsets that
// eBPF uprobes need to attach correctly: function entry addresses, struct
// field offsets for arguments, Go version, GOARCH.
//
// This is the Postman-Insights port of the technique used by both OBI
// (pkg/internal/goexec) and Datadog system-probe (pkg/network/go/bininspect).
// We intentionally implement a *minimum-viable* subset for Phase 3 of the
// HTTPS-capture program:
//
//   1. Detect "is this a Go binary?" via the .note.go.buildid section.
//   2. Read Go version from the .go.buildinfo section.
//   3. Find the file offset (not virtual addr) of named functions via
//      ELF symbol tables. uprobes attach by file offset, which the kernel
//      relocates to whatever virtual address the dynamic loader picked.
//
// Future phases extend with:
//   - DWARF-driven struct field offset extraction (currently we attach
//     uprobes by symbol name and read args from registers per the Go ABI).
//   - Pclntab fallback for stripped binaries (.debug_info absent).
//   - inline-aware function probing.

package goexec

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"strings"
)

// IsGoBinary returns true if the file at path is a Go-built ELF (looks for
// the .note.go.buildid section that the Go linker always emits).
func IsGoBinary(path string) (bool, error) {
	f, err := elf.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	return f.Section(".note.go.buildid") != nil, nil
}

// GoBinaryInfo holds the metadata we extract from a Go binary.
type GoBinaryInfo struct {
	Path     string
	GoVersion string  // e.g. "go1.22.5" — best-effort from .go.buildinfo
	Arch     string  // GOARCH guess based on ELF machine type
	Symbols  map[string]uint64 // symbol name → file offset for uprobe attach
}

// Inspect opens a Go binary and returns the minimum info eBPF uprobes need.
//
// `wantSymbols` is the list of symbol names whose file offsets we should
// resolve. For symbols not found, the returned map simply omits them — caller
// decides whether that's fatal. Pattern matches OBI's GoTracerOffsets shape.
func Inspect(path string, wantSymbols []string) (*GoBinaryInfo, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("goexec: open %s: %w", path, err)
	}
	defer f.Close()

	if f.Section(".note.go.buildid") == nil {
		return nil, errors.New("goexec: not a Go binary (no .note.go.buildid)")
	}

	info := &GoBinaryInfo{
		Path:    path,
		Symbols: map[string]uint64{},
	}

	switch f.Machine {
	case elf.EM_X86_64:
		info.Arch = "amd64"
	case elf.EM_AARCH64:
		info.Arch = "arm64"
	default:
		info.Arch = fmt.Sprintf("unknown(%d)", f.Machine)
	}

	if v, err := readGoBuildInfo(f); err == nil {
		info.GoVersion = v
	}

	// Resolve symbols: we need the *file offset* for uprobe attach. ELF
	// symbol table values are virtual addresses; we convert by finding the
	// segment that contains the address and applying its file-offset delta.
	want := make(map[string]struct{}, len(wantSymbols))
	for _, s := range wantSymbols {
		want[s] = struct{}{}
	}

	syms, err := f.Symbols()
	if err != nil && err != elf.ErrNoSymbols {
		return nil, fmt.Errorf("goexec: read symbols: %w", err)
	}
	// Fall back to dynamic symbols too — Go binaries usually keep .symtab
	// unless explicitly stripped with `-s`.
	dynsyms, _ := f.DynamicSymbols()
	allSyms := append(syms, dynsyms...)

	for _, sym := range allSyms {
		if _, ok := want[sym.Name]; !ok {
			continue
		}
		off, err := vaddrToFileOff(f, sym.Value)
		if err != nil {
			continue
		}
		info.Symbols[sym.Name] = off
	}

	if len(info.Symbols) == 0 && len(want) > 0 {
		return info, fmt.Errorf("goexec: none of the requested symbols (%v) were found; binary may be stripped (-s) \u2014 pclntab fallback not yet implemented", wantSymbols)
	}
	return info, nil
}

// vaddrToFileOff converts a virtual address into a file offset by walking the
// ELF program headers and finding the LOAD segment that covers the address.
func vaddrToFileOff(f *elf.File, vaddr uint64) (uint64, error) {
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD {
			continue
		}
		if vaddr >= p.Vaddr && vaddr < p.Vaddr+p.Memsz {
			return p.Off + (vaddr - p.Vaddr), nil
		}
	}
	return 0, fmt.Errorf("vaddr 0x%x not in any LOAD segment", vaddr)
}

// readGoBuildInfo extracts the Go runtime version from the .go.buildinfo
// section. The format is documented in $GOROOT/src/debug/buildinfo and
// starts with the magic `\xff Go buildinf:`.
//
// We do a minimum-viable parse — just enough to populate GoVersion. The
// stdlib has runtime/debug.BuildInfo but that requires actually running the
// binary; we're inspecting from outside.
func readGoBuildInfo(f *elf.File) (string, error) {
	sec := f.Section(".go.buildinfo")
	if sec == nil {
		return "", errors.New("no .go.buildinfo section")
	}
	r := sec.Open()
	hdr := make([]byte, 32)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return "", err
	}
	// Header: 14 bytes "\xff Go buildinf:", 1 byte ptrSize, 1 byte flags,
	// then either inline strings or pointers (depending on flags).
	if string(hdr[:14]) != "\xff Go buildinf:" {
		return "", errors.New("bad .go.buildinfo magic")
	}
	flags := hdr[15]
	// Flag bit 1 = "version & modinfo are stored inline as length-prefixed
	// strings, not via pointers". Newer Go versions (1.18+) use inline form.
	if flags&0x2 == 0 {
		// Pointer form (Go < 1.18). For our minimum-viable goal we accept
		// "go version unknown" rather than implement the full pointer
		// chasing.
		return "", errors.New("legacy pointer-form buildinfo not yet supported")
	}
	// Re-read from offset 32 — the inline strings start there.
	r2 := sec.Open()
	all, err := io.ReadAll(r2)
	if err != nil {
		return "", err
	}
	if len(all) < 33 {
		return "", errors.New("buildinfo too short")
	}
	// First length-prefixed string is the Go version.
	rest := all[32:]
	ver, _, err := readLenPrefixed(rest)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(ver), nil
}

// readLenPrefixed reads a varint-length-prefixed string from a byte slice.
// Format: uvarint(len) followed by `len` bytes of UTF-8.
func readLenPrefixed(b []byte) (string, []byte, error) {
	var x uint64
	var s uint
	for i, c := range b {
		if i >= 10 {
			return "", nil, errors.New("varint too long")
		}
		if c < 0x80 {
			x |= uint64(c) << s
			b = b[i+1:]
			if uint64(len(b)) < x {
				return "", nil, errors.New("string truncated")
			}
			return string(b[:x]), b[x:], nil
		}
		x |= uint64(c&0x7f) << s
		s += 7
	}
	return "", nil, errors.New("varint not terminated")
}
