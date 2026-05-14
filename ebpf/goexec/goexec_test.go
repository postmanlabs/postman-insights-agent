// SPDX-License-Identifier: Apache-2.0

package goexec

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// TestInspectSelf inspects the current go-test binary, which is itself a
// Go-built ELF on Linux. Smoke-tests Go-binary detection and version
// extraction.
func TestInspectSelf(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("test relies on ELF; runtime is %s", runtime.GOOS)
	}
	selfExe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	ok, err := IsGoBinary(selfExe)
	if err != nil {
		t.Fatalf("IsGoBinary: %v", err)
	}
	if !ok {
		t.Fatalf("test binary not detected as Go")
	}
	info, err := Inspect(selfExe, nil)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if info.GoVersion == "" {
		t.Errorf("expected GoVersion, got empty")
	}
	if info.Arch == "" {
		t.Errorf("expected Arch, got empty")
	}
	t.Logf("self: GoVersion=%s Arch=%s", info.GoVersion, info.Arch)
}

// TestInspectSymbolResolution builds a tiny Go HTTPS server in a temp dir
// and verifies we can resolve crypto/tls.(*Conn).Write to a non-zero file
// offset.
func TestInspectSymbolResolution(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("test builds an ELF; runtime is %s", runtime.GOOS)
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go toolchain in test environment")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	bin := filepath.Join(dir, "srv")
	if err := os.WriteFile(src, []byte(`
package main
import (
	"crypto/tls"
	"net/http"
)
func main() {
	srv := &http.Server{Addr: ":0", TLSConfig: &tls.Config{}}
	srv.ListenAndServeTLS("", "")
}
`), 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}
	cmd := exec.Command("go", "build", "-o", bin, src)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	info, err := Inspect(bin, []string{
		"crypto/tls.(*Conn).Write",
		"crypto/tls.(*Conn).Read",
	})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(info.Symbols) == 0 {
		t.Fatalf("expected at least one symbol resolved, got 0")
	}
	for sym, off := range info.Symbols {
		if off == 0 {
			t.Errorf("%s resolved to offset 0 (suspicious)", sym)
		} else {
			t.Logf("%s -> file offset 0x%x", sym, off)
		}
	}
}
