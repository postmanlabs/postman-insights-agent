// SPDX-License-Identifier: Apache-2.0

package uprobes

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestHasStaticSSLSymbols(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ELF symbol tests require Linux")
	}

	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not on PATH")
	}
	// Debian/apt node links libssl dynamically; the node binary itself should
	// not be the TLS attach target.
	if hasStaticSSLSymbols(node) {
		t.Logf("note: %s exports SSL_* (unusual for dynamic-link builds)", node)
	}

	bin := os.Getenv("NODE_STATIC_BIN")
	if bin == "" {
		t.Skip("NODE_STATIC_BIN not set; skip official node binary test")
	}
	if !hasStaticSSLSymbols(bin) {
		t.Fatalf("%s missing required SSL_* symbols", bin)
	}
}

func TestFindStaticLibSSLAt_skipsNonNode(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux")
	}
	_, err := FindStaticLibSSLAt("/proc", uint32(os.Getpid()))
	if err != ErrNotFound {
		t.Fatalf("FindStaticLibSSLAt(self) = %v, want ErrNotFound", err)
	}
}

func TestFindLibSSLAnyAt_self(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux")
	}
	// The test runner may or may not have libssl mapped; either outcome is ok
	// as long as we do not error unexpectedly.
	_, err := FindLibSSLAnyAt("/proc", uint32(os.Getpid()))
	if err != nil && err != ErrNotFound {
		t.Fatalf("FindLibSSLAnyAt(self) unexpected error: %v", err)
	}
}

func TestIsStaticLibSSLCandidate_nodeComm(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux")
	}
	dir := t.TempDir()
	proc := filepath.Join(dir, "12345")
	if err := os.Mkdir(proc, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "comm"), []byte("node\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(proc, "exe")
	if err := os.Symlink("/usr/local/bin/node", exe); err != nil {
		t.Skip("cannot create test symlink:", err)
	}
	if !isStaticLibSSLCandidate(dir, 12345) {
		t.Fatal("expected node comm to be a static libssl candidate")
	}
}

func TestStaticExecutablePaths_attachVsELF(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux")
	}
	dir := t.TempDir()
	pid := uint32(99999)
	proc := filepath.Join(dir, fmt.Sprintf("%d", pid))
	rootDir := filepath.Join(proc, "root", "usr", "local", "bin")
	if err := os.MkdirAll(rootDir, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(rootDir, "node")
	if err := os.WriteFile(bin, []byte{0x7f, 'E', 'L', 'F'}, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/local/bin/node", filepath.Join(proc, "exe")); err != nil {
		t.Fatal(err)
	}
	if got := staticExecutableAttachPath(dir, pid); got != bin {
		t.Fatalf("attach path = %q, want %q", got, bin)
	}
}
