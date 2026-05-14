// SPDX-License-Identifier: Apache-2.0

package goexec

import (
	"os/exec"
	"runtime"
	"testing"
)

func TestFindReturnOffsets_Self(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ELF-only test")
	}
	// Find RETs in this test binary's own runtime.main — it's a Go binary,
	// runtime.main always exists, and has at least one return.
	exe, err := exec.LookPath("/proc/self/exe")
	if err != nil {
		t.Fatalf("lookpath: %v", err)
	}
	offsets, err := FindReturnOffsets(exe, "runtime.main")
	if err != nil {
		t.Fatalf("FindReturnOffsets: %v", err)
	}
	if len(offsets) == 0 {
		t.Fatal("expected at least one RET offset in runtime.main")
	}
	for _, o := range offsets {
		t.Logf("RET at file offset 0x%x", o)
	}
}

func TestFunctionExtent_Self(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ELF-only test")
	}
	start, end, err := FunctionExtent("/proc/self/exe", "runtime.main")
	if err != nil {
		t.Fatalf("FunctionExtent: %v", err)
	}
	if start == 0 || end <= start {
		t.Errorf("bad extent: start=0x%x end=0x%x", start, end)
	}
	t.Logf("runtime.main: 0x%x..0x%x (%d bytes)", start, end, end-start)
}
