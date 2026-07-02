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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target native -cc clang -cflags "-O2 -g -Wall -Werror" javatls ../programs/java_tls.bpf.c -- -I../programs

// JavaTLSLoader owns the kernel-side java_tls program. Unlike libssl (one
// shared Loader, many per-target uprobe links) and unlike gotls (one loader
// per Go binary), Java capture has exactly ONE attach point — a single
// `sys_ioctl` kprobe — shared across all JVMs on the host. The kprobe gates
// per-PID via the same allowlist map shape used by libssl.
//
// The kprobe fires on sys_ioctl; the Java agent (postman-java-agent.jar)
// drives the ioctl from the JVM side to pass decrypted TLS bytes to the kernel.
type JavaTLSLoader struct {
	javatls *javatlsObjects
}

// LoadJavaTLS instantiates the java_tls BPF collection. enforceAllowlist
// gates whether non-allowlisted PIDs trigger emission.
func LoadJavaTLS(maxCaptureBytes uint32, enforceAllowlist bool) (*JavaTLSLoader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("ebpf: remove memlock: %w", err)
	}
	spec, err := loadJavatls()
	if err != nil {
		return nil, fmt.Errorf("ebpf: load java_tls spec: %w", err)
	}
	if maxCaptureBytes == 0 {
		maxCaptureBytes = 1024
	}
	var enforce uint32
	if enforceAllowlist {
		enforce = 1
	}
	if err := spec.Variables["java_enforce_pid_allowlist"].Set(enforce); err != nil {
		return nil, fmt.Errorf("ebpf: set java_enforce_pid_allowlist: %w", err)
	}
	if err := spec.Variables["java_max_capture_bytes"].Set(maxCaptureBytes); err != nil {
		return nil, fmt.Errorf("ebpf: set java_max_capture_bytes: %w", err)
	}
	objs := &javatlsObjects{}
	if err := spec.LoadAndAssign(objs, &ebpf.CollectionOptions{}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("ebpf: java_tls verifier rejected:\n%+v", ve)
		}
		return nil, fmt.Errorf("ebpf: java_tls load: %w", err)
	}
	return &JavaTLSLoader{javatls: objs}, nil
}

// Close releases all maps and the kprobe program.
func (l *JavaTLSLoader) Close() error {
	if l.javatls != nil {
		return l.javatls.Close()
	}
	return nil
}

// EventsMap returns the ringbuf containing struct ssl_event records.
func (l *JavaTLSLoader) EventsMap() *ebpf.Map { return l.javatls.JavaEvents }

// IoctlProg returns the kprobe program attached to sys_ioctl.
func (l *JavaTLSLoader) IoctlProg() *ebpf.Program { return l.javatls.JavaKprobeSysIoctl }

// Attach attaches the program to the kernel's sys_ioctl symbol. The caller
// owns the returned link.Link and MUST close it (and then the loader) on
// shutdown.
func (l *JavaTLSLoader) Attach() (link.Link, error) {
	// cilium/ebpf's link.Kprobe resolves the right arch-prefixed symbol
	// (__x64_sys_ioctl / __arm64_sys_ioctl) automatically. The fallback
	// to the unprefixed name covers kernels < 4.17 / non-syscall-wrapper
	// builds.
	lnk, err := link.Kprobe("sys_ioctl", l.IoctlProg(), nil)
	if err != nil {
		return nil, fmt.Errorf("ebpf: java_tls attach kprobe sys_ioctl: %w", err)
	}
	return lnk, nil
}

// AddTargetPID adds a PID to the allowlist (only consulted when the
// enforce_pid_allowlist constant was set at load time).
func (l *JavaTLSLoader) AddTargetPID(pid uint32) error {
	var v uint8 = 1
	return l.javatls.JavaTargetPids.Update(&pid, &v, ebpf.UpdateAny)
}

// RemoveTargetPID deletes a PID from the allowlist.
func (l *JavaTLSLoader) RemoveTargetPID(pid uint32) error {
	return l.javatls.JavaTargetPids.Delete(&pid)
}

// ReadCounter sums per-CPU values. Indices match the BPF source:
//
//	0 = events emitted
//	1 = ringbuf-reserve failures
//	2 = probe_read_user failures
//	3 = bytes captured
//	4 = ioctl(fd=0, cmd≠magic) — diagnostic
//	5 = (reserved; not currently incremented)
func (l *JavaTLSLoader) ReadCounter(idx uint32) (uint64, error) {
	var perCPU []uint64
	if err := l.javatls.JavaCounters.Lookup(&idx, &perCPU); err != nil {
		return 0, err
	}
	var sum uint64
	for _, v := range perCPU {
		sum += v
	}
	return sum, nil
}
