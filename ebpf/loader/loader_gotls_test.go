// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package loader

import (
	"os"
	"testing"
)

// TestLoadGoTLS smoke-loads the Phase 3 gotls BPF collection. Verifies the
// program passes the verifier and all expected handles are present.
//
// Requires root (CAP_BPF + CAP_PERFMON).
func TestLoadGoTLS(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_BPF + CAP_PERFMON)")
	}
	l, err := LoadGoTLS(512)
	if err != nil {
		t.Fatalf("LoadGoTLS: %v", err)
	}
	defer l.Close()
	if l.EventsMap() == nil {
		t.Fatal("EventsMap is nil")
	}
	if l.WriteProg() == nil {
		t.Fatal("WriteProg is nil")
	}
	if _, err := l.ReadCounter(0); err != nil {
		t.Fatalf("ReadCounter: %v", err)
	}
}
