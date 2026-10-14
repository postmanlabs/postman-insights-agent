// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package loader

import (
	"errors"
	"fmt"
	"math"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// The Java TLS programs are a separate object so that a failure to load or
// attach them disables only Java capture, never libssl. They share the libssl
// object's ring buffer and rate-cap buckets through MapReplacements (both
// objects define these maps in programs/common.h).
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target native -cc clang -cflags "-O2 -g -Wall -Werror -fms-extensions -Wno-missing-declarations -Wno-microsoft-anon-tag" javatls ../programs/java_tls.bpf.c -- -I../programs

type javaTLS struct {
	objs  javatlsObjects
	links []link.Link
}

func loadJavaTLS(cfg Config, shared *libsslObjects) (*javaTLS, error) {
	spec, err := loadJavatls()
	if err != nil {
		return nil, fmt.Errorf("ebpf: load java_tls spec: %w", err)
	}
	if err := spec.Variables["enforce_netns_allowlist"].Set(cfg.bpfEnforceJavaNetns()); err != nil {
		return nil, fmt.Errorf("ebpf: set enforce_netns_allowlist: %w", err)
	}
	if err := spec.Variables["max_capture_bytes"].Set(cfg.bpfMaxCapture()); err != nil {
		return nil, fmt.Errorf("ebpf: set java max_capture_bytes: %w", err)
	}

	j := &javaTLS{}
	opts := &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"events":           shared.Events,
			"pid_rate_buckets": shared.PidRateBuckets,
		},
	}
	if err := spec.LoadAndAssign(&j.objs, opts); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("ebpf: BPF verifier rejected java_tls program:\n%+v", ve)
		}
		return nil, fmt.Errorf("ebpf: load java_tls: %w", err)
	}

	// Syscall tracepoints need tracefs (/sys/kernel/tracing, or
	// /sys/kernel/debug/tracing, which the DaemonSet mounts).
	for _, tp := range []struct {
		name string
		prog *ebpf.Program
	}{
		{"sys_enter_pwrite64", j.objs.TpSysEnterPwrite64},
		{"sys_enter_pwritev2", j.objs.TpSysEnterPwritev2},
		{"sys_enter_pwritev", j.objs.TpSysEnterPwritev},
	} {
		lk, err := link.Tracepoint("syscalls", tp.name, tp.prog, nil)
		if err != nil {
			_ = j.close()
			return nil, fmt.Errorf("ebpf: attach tracepoint syscalls/%s: %w", tp.name, err)
		}
		j.links = append(j.links, lk)
	}
	return j, nil
}

var errJavaDisabled = errors.New("ebpf: Java TLS capture is not running")

// netnsKey converts a netns inode (as returned by stat) to the BPF map key.
// The kernel's ns.inum is 32 bits wide.
func netnsKey(netnsInode uint64) (uint32, error) {
	if netnsInode == 0 || netnsInode > math.MaxUint32 {
		return 0, fmt.Errorf("ebpf: invalid netns inode %d", netnsInode)
	}
	return uint32(netnsInode), nil
}

func (j *javaTLS) close() error {
	for _, lk := range j.links {
		_ = lk.Close()
	}
	j.links = nil
	return j.objs.Close()
}

// JavaEnabled reports whether the Java TLS programs are loaded and attached.
func (l *Loader) JavaEnabled() bool { return l.java != nil }

// JavaError returns why the Java TLS programs are not running when
// Config.EnableJava was set, or nil.
func (l *Loader) JavaError() error { return l.javaErr }

// AllowJavaNetns accepts Java frames from processes in the network namespace
// with inode netnsInode. Only meaningful with
// Config.EnforceJavaNetnsAllowlist.
func (l *Loader) AllowJavaNetns(netnsInode uint64) error {
	if l.java == nil {
		return errJavaDisabled
	}
	key, err := netnsKey(netnsInode)
	if err != nil {
		return err
	}
	var one uint8 = 1
	return l.java.objs.JavaNetns.Update(&key, &one, ebpf.UpdateAny)
}

// DisallowJavaNetns stops accepting Java frames from a network namespace.
func (l *Loader) DisallowJavaNetns(netnsInode uint64) error {
	if l.java == nil {
		return errJavaDisabled
	}
	key, err := netnsKey(netnsInode)
	if err != nil {
		return err
	}
	if err := l.java.objs.JavaNetns.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

// ReadJavaCounter sums the per-CPU values for a JavaCounter* index.
func (l *Loader) ReadJavaCounter(idx uint32) (uint64, error) {
	if l.java == nil {
		return 0, errJavaDisabled
	}
	var perCPU []uint64
	if err := l.java.objs.JavaCounters.Lookup(&idx, &perCPU); err != nil {
		return 0, fmt.Errorf("ebpf: read java counter %d: %w", idx, err)
	}
	var sum uint64
	for _, v := range perCPU {
		sum += v
	}
	return sum, nil
}
