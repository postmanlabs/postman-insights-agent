// SPDX-License-Identifier: Apache-2.0

package goexec

import (
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// TestPclntab_StrippedBinary verifies the .gopclntab fallback resolves
// crypto/tls.(*Conn).Write in a Go binary built with -ldflags="-s -w"
// (the production-stripped configuration where the ELF symbol table
// is gone entirely).
//
// Test strategy: build a tiny Go binary in a temp dir with stripped
// flags, then assert Inspect() / FunctionExtent() succeed.
func TestPclntab_StrippedBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("requires go build; skipped in -short mode")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	if runtime.GOOS != "linux" {
		// go build on non-Linux produces Mach-O / PE, not ELF — the
		// debug/elf package won't parse those. The implementation is
		// Linux-only anyway (uprobes don't exist elsewhere).
		t.Skip("pclntab fallback test requires Linux ELF output")
	}

	dir := t.TempDir()
	srcPath := filepath.Join(dir, "main.go")
	binPath := filepath.Join(dir, "stripped")

	// Tiny program that imports crypto/tls so the symbols we want are
	// linked in.
	src := `package main

import (
	"crypto/tls"
	"net"
)

func main() {
	var c net.Conn
	tc := tls.Client(c, &tls.Config{})
	// Reference Write/Read so the Go linker keeps them live (dead-code
	// elimination would otherwise drop them).
	_, _ = tc.Write([]byte{0})
	buf := make([]byte, 1)
	_, _ = tc.Read(buf)
}
`
	if err := os.WriteFile(srcPath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	// Build with -s -w to strip symbol + DWARF tables. This is exactly
	// what production Go binaries typically use.
	cmd := exec.Command("go", "build", "-ldflags=-s -w", "-o", binPath, srcPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	// Sanity check: the binary should have NO .symtab section.
	f, err := elf.Open(binPath)
	if err != nil {
		t.Fatal(err)
	}
	syms, _ := f.Symbols()
	dyn, _ := f.DynamicSymbols()
	if len(syms)+len(dyn) > 0 {
		t.Logf("note: stripped binary still has %d symtab + %d dynsym entries",
			len(syms), len(dyn))
	}
	if f.Section(".gopclntab") == nil {
		t.Fatal("stripped binary missing .gopclntab — Go runtime invariant violated, test cannot proceed")
	}
	f.Close()

	// Inspect should find the symbol via the pclntab fallback.
	info, err := Inspect(binPath, []string{"crypto/tls.(*Conn).Write"})
	if err != nil {
		t.Fatalf("Inspect on stripped binary: %v", err)
	}
	off, ok := info.Symbols["crypto/tls.(*Conn).Write"]
	if !ok {
		t.Fatal("crypto/tls.(*Conn).Write not resolved via pclntab fallback")
	}
	t.Logf("stripped binary: crypto/tls.(*Conn).Write resolved at file offset 0x%x", off)

	// FunctionExtent should also work; size must be non-zero.
	start, end, err := FunctionExtent(binPath, "crypto/tls.(*Conn).Write")
	if err != nil {
		t.Fatalf("FunctionExtent on stripped binary: %v", err)
	}
	if end <= start {
		t.Errorf("zero-size function extent: [0x%x, 0x%x)", start, end)
	}
	if start != off {
		t.Errorf("Inspect offset 0x%x != FunctionExtent start 0x%x", off, start)
	}
	t.Logf("stripped binary: crypto/tls.(*Conn).Write extent [0x%x, 0x%x) (%d bytes)",
		start, end, end-start)

	// FindReturnOffsets should also work since we now have a valid extent.
	rets, err := FindReturnOffsets(binPath, "crypto/tls.(*Conn).Write")
	if err != nil {
		t.Fatalf("FindReturnOffsets on stripped binary: %v", err)
	}
	if len(rets) == 0 {
		t.Errorf("expected at least one RET in crypto/tls.(*Conn).Write, got 0")
	}
	t.Logf("stripped binary: %d RET sites in crypto/tls.(*Conn).Write (arch=%s)",
		len(rets), runtime.GOARCH)
	for _, r := range rets {
		if r < start || r >= end {
			t.Errorf("RET 0x%x outside function extent [0x%x, 0x%x)", r, start, end)
		}
	}
}


