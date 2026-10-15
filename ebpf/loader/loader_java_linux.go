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
// object's ring buffer through MapReplacements (both objects define it in
// programs/common.h).
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target native -cc clang -cflags "-O2 -g -Wall -Werror -fms-extensions -Wno-missing-declarations -Wno-microsoft-anon-tag" javatls ../programs/java_tls.bpf.c -- -I../programs

type javaTLS struct {
	objs javaTLSCore
	// readHook is the program that records socket reads (see "Connection
	// addresses" in java_tls.bpf.c), nil when neither fentry nor kprobe
	// could attach: then Java events carry no addresses.
	readHook *ebpf.Program
	// readHookKind is how readHook attached: "fentry" or "kprobe".
	readHookKind string
	// readHookErr is why readHook is nil.
	readHookErr error
	links       []link.Link
}

// javaTLSCore is the java_tls object without its tcp_recvmsg hook, which is
// loaded on its own: fentry needs BPF trampolines (x86_64 5.5+, arm64 6.0+),
// and a kernel without them must still run the rest.
type javaTLSCore struct {
	javatlsMaps
	javatlsVariables
	TpSysEnterPwrite64 *ebpf.Program `ebpf:"tp_sys_enter_pwrite64"`
	TpSysEnterPwritev  *ebpf.Program `ebpf:"tp_sys_enter_pwritev"`
	TpSysEnterPwritev2 *ebpf.Program `ebpf:"tp_sys_enter_pwritev2"`
}

func (c *javaTLSCore) Close() error {
	return _JavatlsClose(c.TpSysEnterPwrite64, c.TpSysEnterPwritev, c.TpSysEnterPwritev2, &c.javatlsMaps)
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
			"events": shared.Events,
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
	j.attachReadHook(spec, !cfg.javaReadHookKprobe)
	return j, nil
}

// attachReadHook attaches the tcp_recvmsg hook, with fentry if it can, else
// kprobe. Failing both only leaves Java events without addresses.
func (j *javaTLS) attachReadHook(spec *ebpf.CollectionSpec, tryFentry bool) {
	opts := &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"java_senders":      j.objs.JavaSenders,
			"java_thread_reads": j.objs.JavaThreadReads,
		},
	}
	var errs []error
	var fentry struct {
		Prog *ebpf.Program `ebpf:"fentry_tcp_recvmsg"`
	}
	if !tryFentry {
		errs = append(errs, errors.New("fentry: not tried"))
	} else if err := spec.LoadAndAssign(&fentry, opts); err != nil {
		errs = append(errs, fmt.Errorf("fentry: %w", err))
	} else if lk, err := link.AttachTracing(link.TracingOptions{Program: fentry.Prog}); err != nil {
		_ = fentry.Prog.Close()
		errs = append(errs, fmt.Errorf("fentry: %w", err))
	} else {
		j.readHook, j.readHookKind = fentry.Prog, "fentry"
		j.links = append(j.links, lk)
		return
	}
	var kprobe struct {
		Prog *ebpf.Program `ebpf:"kprobe_tcp_recvmsg"`
	}
	if err := spec.LoadAndAssign(&kprobe, opts); err != nil {
		errs = append(errs, fmt.Errorf("kprobe: %w", err))
	} else if lk, err := link.Kprobe("tcp_recvmsg", kprobe.Prog, nil); err != nil {
		_ = kprobe.Prog.Close()
		errs = append(errs, fmt.Errorf("kprobe: %w", err))
	} else {
		j.readHook, j.readHookKind = kprobe.Prog, "kprobe"
		j.links = append(j.links, lk)
		return
	}
	j.readHookErr = errors.Join(errs...)
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
	if j.readHook != nil {
		_ = j.readHook.Close()
	}
	return j.objs.Close()
}

// JavaConnAddresses reports how Java events get their connection's
// addresses: "fentry" or "kprobe" on tcp_recvmsg, or "" with the reason they
// carry none.
func (l *Loader) JavaConnAddresses() (string, error) {
	if l.java == nil {
		return "", errJavaDisabled
	}
	return l.java.readHookKind, l.java.readHookErr
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
