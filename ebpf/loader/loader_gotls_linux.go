// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package loader

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target native -cc clang -cflags "-O2 -g -Wall -Werror" gotls ../programs/gotls.bpf.c -- -I../programs

// GoTLSLoader owns a per-binary instance of the gotls.bpf.o program. Unlike
// the shared libssl Loader, Go binaries have different function-symbol file
// offsets, so each target binary gets its own program load with a
// load-time-rewritten max_capture_bytes constant.
//
// The events ringbuf is per-loader too — the userspace reader needs to
// multiplex across multiple Go targets.
type GoTLSLoader struct {
	gotls *gotlsObjects
}

// LoadGoTLS instantiates a gotls BPF collection. max_capture_bytes is
// rewritten at load time. Subsequent runtime updates aren't supported for
// this collection — the thermostat operates on the libssl collection only
// in Phase 3 MVP (gotls support extends in a follow-up).
func LoadGoTLS(maxCaptureBytes uint32) (*GoTLSLoader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("ebpf: remove memlock: %w", err)
	}
	spec, err := loadGotls()
	if err != nil {
		return nil, fmt.Errorf("ebpf: load gotls spec: %w", err)
	}
	if maxCaptureBytes == 0 {
		maxCaptureBytes = 1024
	}
	if err := spec.Variables["gotls_max_capture_bytes"].Set(maxCaptureBytes); err != nil {
		return nil, fmt.Errorf("ebpf: set gotls_max_capture_bytes: %w", err)
	}
	objs := &gotlsObjects{}
	if err := spec.LoadAndAssign(objs, &ebpf.CollectionOptions{}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("ebpf: gotls verifier rejected:\n%+v", ve)
		}
		return nil, fmt.Errorf("ebpf: gotls load: %w", err)
	}
	return &GoTLSLoader{gotls: objs}, nil
}

// Close releases all maps and programs owned by this loader.
func (l *GoTLSLoader) Close() error {
	if l.gotls != nil {
		return l.gotls.Close()
	}
	return nil
}

// EventsMap returns the per-collection ringbuf map.
func (l *GoTLSLoader) EventsMap() *ebpf.Map { return l.gotls.GotlsEvents }

// WriteProg returns the entry uprobe for crypto/tls.(*Conn).Write.
func (l *GoTLSLoader) WriteProg() *ebpf.Program { return l.gotls.UprobeGotlsWrite }

// ReadCounter sums per-CPU values for the gotls counters map.
func (l *GoTLSLoader) ReadCounter(idx uint32) (uint64, error) {
	var perCPU []uint64
	if err := l.gotls.GotlsCounters.Lookup(&idx, &perCPU); err != nil {
		return 0, err
	}
	var sum uint64
	for _, v := range perCPU {
		sum += v
	}
	return sum, nil
}

// OpenExecutable wraps link.OpenExecutable so callers don't import
// cilium/ebpf/link directly.
func (l *GoTLSLoader) OpenExecutable(path string) (*link.Executable, error) {
	return link.OpenExecutable(path)
}
