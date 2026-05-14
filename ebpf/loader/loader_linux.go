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

// bpf2go targets are intentionally limited to the *host* arch for the Phase 1
// spike: cross-arch compilation requires either libbpf >= 1.3 (which defines
// synthetic per-arch pt_regs structs) or per-arch vmlinux.h headers. Debian
// bookworm ships libbpf 1.1, so we cross-compile in CI on Linux/amd64 runners.
// On a developer machine, generate locally for whichever arch the host kernel
// exposes via /sys/kernel/btf/vmlinux.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target native -cc clang -cflags "-O2 -g -Wall -Werror" libssl ../programs/libssl.bpf.c -- -I../programs

// Loader owns the loaded BPF objects (maps + programs) for a single Insights
// Agent process. One Loader serves all target processes; per-process state
// (which PIDs to trace, which libssl path to probe) is communicated via maps
// and per-target link.Link handles owned by the uprobes package.
type Loader struct {
	libssl *libsslObjects
}

// Load reads the embedded BPF ELF, instantiates maps and programs, and returns
// a Loader ready for uprobe attachment.
func Load(cfg Config) (*Loader, error) {
	// RLIMIT_MEMLOCK matters on kernels < 5.11 where BPF objects are charged
	// against locked memory. No-op on newer kernels but harmless.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("ebpf: remove memlock: %w", err)
	}

	spec, err := loadLibssl()
	if err != nil {
		return nil, fmt.Errorf("ebpf: load libssl spec: %w", err)
	}

	// Override .rodata constants declared in libssl.bpf.c.
	if err := spec.Variables["enforce_pid_allowlist"].Set(cfg.bpfEnforce()); err != nil {
		return nil, fmt.Errorf("ebpf: set enforce_pid_allowlist: %w", err)
	}
	if err := spec.Variables["max_capture_bytes"].Set(cfg.bpfMaxCapture()); err != nil {
		return nil, fmt.Errorf("ebpf: set max_capture_bytes: %w", err)
	}

	objs := &libsslObjects{}
	if err := spec.LoadAndAssign(objs, &ebpf.CollectionOptions{}); err != nil {
		// Verifier errors deserve full output — they're the dominant failure mode.
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("ebpf: BPF verifier rejected program:\n%+v", ve)
		}
		return nil, fmt.Errorf("ebpf: load and assign: %w", err)
	}

	return &Loader{libssl: objs}, nil
}

// Close releases all maps and programs. Callers MUST close any link.Link
// handles for attached probes BEFORE calling Close on the loader.
func (l *Loader) Close() error {
	if l.libssl != nil {
		return l.libssl.Close()
	}
	return nil
}

func (l *Loader) EventsMap() *ebpf.Map     { return l.libssl.Events }
func (l *Loader) TargetPIDsMap() *ebpf.Map { return l.libssl.TargetPids }
func (l *Loader) CountersMap() *ebpf.Map   { return l.libssl.Counters }

// Counter indices — must match the BPF C source.
const (
	CounterEventsEmitted uint32 = 0
	CounterEventsDropped uint32 = 1
	CounterReadFailed    uint32 = 2
	CounterBytesCaptured uint32 = 3
)

// ReadCounter sums the per-CPU values for a counter index.
func (l *Loader) ReadCounter(idx uint32) (uint64, error) {
	var perCPU []uint64
	if err := l.libssl.Counters.Lookup(&idx, &perCPU); err != nil {
		return 0, fmt.Errorf("ebpf: read counter %d: %w", idx, err)
	}
	var sum uint64
	for _, v := range perCPU {
		sum += v
	}
	return sum, nil
}

func (l *Loader) SSLReadProgs() (entry, exit *ebpf.Program) {
	return l.libssl.UprobeSslRead, l.libssl.UretprobeSslRead
}
func (l *Loader) SSLReadExProgs() (entry, exit *ebpf.Program) {
	return l.libssl.UprobeSslReadEx, l.libssl.UretprobeSslReadEx
}
func (l *Loader) SSLWriteProgs() (entry, exit *ebpf.Program) {
	return l.libssl.UprobeSslWrite, l.libssl.UretprobeSslWrite
}
func (l *Loader) SSLWriteExProgs() (entry, exit *ebpf.Program) {
	return l.libssl.UprobeSslWriteEx, l.libssl.UretprobeSslWriteEx
}

// OpenExecutable is a thin wrapper around link.OpenExecutable so callers
// don't have to import cilium/ebpf/link directly.
func OpenExecutable(path string) (*link.Executable, error) {
	return link.OpenExecutable(path)
}
