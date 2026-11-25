//go:build linux && insights_bpf

package loader

import (
	"errors"
	"fmt"
	"math"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// The Java TLS programs are a separate object so that a failure to load or
// attach them disables only Java capture, never libssl. They share the libssl
// object's ring buffer through MapReplacements (both objects define it in
// programs/common.h).
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target native -cc clang -cflags "-O2 -g -Wall -Werror -fms-extensions -Wno-missing-declarations -Wno-microsoft-anon-tag" javatls ../programs/java_tls.bpf.c -- -I../programs

type javaTLS struct {
	objs javaTLSCore
	// socketHooks are the programs that record socket reads and writes (see
	// "Connection addresses" in java_tls.bpf.c), the read hooks first; none
	// when neither fexit nor kprobe could attach: then Java events carry no
	// addresses.
	socketHooks []*ebpf.Program
	// socketHooksKind is how they attached: "fexit" or "kprobe".
	socketHooksKind string
	// socketHooksErr is why there are none.
	socketHooksErr error
	// socketHooksFallback is why they are kprobes rather than fexit and
	// fentry.
	socketHooksFallback error
	links               []link.Link
}

// javaTLSCore is the java_tls object without its tcp_recvmsg hook, which is
// loaded on its own: fexit needs BPF trampolines (x86_64 5.5+, arm64 6.0+),
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
	noAppendRejected := cfg.javaNoAppendRejected || pwritev2RejectsNoAppend()
	if err := spec.Variables["pwritev2_noappend_rejected"].Set(boolU32(noAppendRejected)); err != nil {
		return nil, fmt.Errorf("ebpf: set pwritev2_noappend_rejected: %w", err)
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
	j.attachSocketHooks(spec, !cfg.javaReadHookKprobe)
	return j, nil
}

// pwritev2RejectsNoAppend reports whether this kernel fails pwritev2 with
// RWF_NOAPPEND (added in Linux 6.9) as an unknown flag, which makes musl's
// pwrite() write every frame a second time with pwrite64. It writes one byte
// to /dev/null at offset 0, which no tracepoint program reads.
func pwritev2RejectsNoAppend() bool {
	f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	_, err = unix.Pwritev2(int(f.Fd()), [][]byte{{0}}, 0, unix.RWF_NOAPPEND)
	return errors.Is(err, unix.EOPNOTSUPP)
}

func boolU32(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

// kretprobeMaxActive is the kernel's maximum of concurrent kretprobe
// instances (KRETPROBE_MAXACTIVE_MAX).
const kretprobeMaxActive = 4096

// attachSocketHooks attaches the tcp_recvmsg and tcp_sendmsg hooks: fexit
// and fentry if it can, else kprobes (with a kretprobe for reads). Failing
// both only leaves Java events without addresses.
func (j *javaTLS) attachSocketHooks(spec *ebpf.CollectionSpec, tryTracing bool) {
	opts := &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"java_senders":      j.objs.JavaSenders,
			"java_thread_reads": j.objs.JavaThreadReads,
			"java_thread_sends": j.objs.JavaThreadSends,
			"java_conns":        j.objs.JavaConns,
			"java_counters":     j.objs.JavaCounters,
		},
	}
	var errs []error
	if !tryTracing {
		errs = append(errs, errors.New("fexit: not tried"))
	} else {
		readDone, err := loadFexitRead(spec, opts)
		if err == nil {
			var write struct {
				Prog *ebpf.Program `ebpf:"fentry_tcp_sendmsg"`
			}
			if err = spec.LoadAndAssign(&write, opts); err != nil {
				_ = readDone.Close()
			} else {
				tracing := func(p *ebpf.Program) (link.Link, error) {
					return link.AttachTracing(link.TracingOptions{Program: p})
				}
				err = j.attachAll("fexit", []*ebpf.Program{readDone, write.Prog},
					[]func(*ebpf.Program) (link.Link, error){tracing, tracing})
			}
		}
		if err == nil {
			return
		}
		errs = append(errs, fmt.Errorf("fexit: %w", err))
		j.socketHooksFallback = err
	}
	var progs struct {
		Read     *ebpf.Program `ebpf:"kprobe_tcp_recvmsg"`
		ReadDone *ebpf.Program `ebpf:"kretprobe_tcp_recvmsg"`
		Write    *ebpf.Program `ebpf:"kprobe_tcp_sendmsg"`
	}
	err := spec.LoadAndAssign(&progs, opts)
	if err == nil {
		err = j.attachAll("kprobe", []*ebpf.Program{progs.Read, progs.ReadDone, progs.Write},
			[]func(*ebpf.Program) (link.Link, error){
				func(p *ebpf.Program) (link.Link, error) { return link.Kprobe("tcp_recvmsg", p, nil) },
				func(p *ebpf.Program) (link.Link, error) {
					// A blocking tcp_recvmsg holds a kretprobe instance until
					// it returns, on every process of the node: with the
					// default limit (about two per CPU), blocked readers
					// elsewhere use them up and returns are missed. Use the
					// kernel's maximum; it needs tracefs, else the default.
					lk, err := link.Kretprobe("tcp_recvmsg", p, &link.KprobeOptions{RetprobeMaxActive: kretprobeMaxActive})
					if err != nil {
						lk, err = link.Kretprobe("tcp_recvmsg", p, nil)
					}
					return lk, err
				},
				func(p *ebpf.Program) (link.Link, error) { return link.Kprobe("tcp_sendmsg", p, nil) },
			})
	}
	if err == nil {
		return
	}
	errs = append(errs, fmt.Errorf("kprobe: %w", err))
	j.socketHooksErr = errors.Join(errs...)
}

// attachAll attaches each program with its attach function, keeping all of
// them or none.
func (j *javaTLS) attachAll(kind string, progs []*ebpf.Program, attach []func(*ebpf.Program) (link.Link, error)) error {
	var links []link.Link
	for i, p := range progs {
		lk, err := attach[i](p)
		if err != nil {
			for _, l := range links {
				_ = l.Close()
			}
			for _, p := range progs {
				_ = p.Close()
			}
			return err
		}
		links = append(links, lk)
	}
	j.links = append(j.links, links...)
	j.socketHooks, j.socketHooksKind = progs, kind
	return nil
}

// loadFexitRead loads the fexit program for the kernel's tcp_recvmsg: one
// per number of arguments, since fexit reads the return value after them.
func loadFexitRead(spec *ebpf.CollectionSpec, opts *ebpf.CollectionOptions) (*ebpf.Program, error) {
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, fmt.Errorf("kernel BTF: %w", err)
	}
	args, err := tcpRecvmsgArgs(kernel)
	if err != nil {
		return nil, err
	}
	switch args {
	case 4:
		var p struct {
			Prog *ebpf.Program `ebpf:"fexit_tcp_recvmsg4"`
		}
		err = spec.LoadAndAssign(&p, opts)
		return p.Prog, err
	case 5:
		var p struct {
			Prog *ebpf.Program `ebpf:"fexit_tcp_recvmsg5"`
		}
		err = spec.LoadAndAssign(&p, opts)
		return p.Prog, err
	default:
		var p struct {
			Prog *ebpf.Program `ebpf:"fexit_tcp_recvmsg6"`
		}
		err = spec.LoadAndAssign(&p, opts)
		return p.Prog, err
	}
}

// tcpRecvmsgArgs returns the number of arguments of the kernel's
// tcp_recvmsg, from its BTF rather than the kernel version, since
// distributions backport changes: 6 before Linux 5.19 (with nonblock), 5
// after (without), and 4 on later kernels (without addr_len too). Any other
// number is an error, and the loader falls back to kprobes, whose return
// value does not depend on the signature.
func tcpRecvmsgArgs(kernel *btf.Spec) (int, error) {
	var fn *btf.Func
	if err := kernel.TypeByName("tcp_recvmsg", &fn); err != nil {
		return 0, fmt.Errorf("tcp_recvmsg in the kernel's BTF: %w", err)
	}
	proto, ok := fn.Type.(*btf.FuncProto)
	if !ok {
		return 0, fmt.Errorf("tcp_recvmsg in the kernel's BTF is a %T, not a function prototype", fn.Type)
	}
	if n := len(proto.Params); n < 4 || n > 6 {
		return 0, fmt.Errorf("tcp_recvmsg has %d arguments in the kernel's BTF, want 4 to 6", n)
	}
	return len(proto.Params), nil
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
	for _, p := range j.socketHooks {
		_ = p.Close()
	}
	return j.objs.Close()
}

// JavaConnAddresses reports how Java events get their connection's
// addresses: "fexit" (fexit and fentry) or "kprobe" (kprobes, and a
// kretprobe for reads) on tcp_recvmsg and tcp_sendmsg; or "" with the reason
// they carry none.
func (l *Loader) JavaConnAddresses() (string, error) {
	if l.java == nil {
		return "", errJavaDisabled
	}
	return l.java.socketHooksKind, l.java.socketHooksErr
}

// JavaConnAddressesFallback returns why the socket hooks are attached by
// kprobe rather than fexit and fentry, or nil when they are not (or fexit was
// not tried).
func (l *Loader) JavaConnAddressesFallback() error {
	if l.java == nil || l.java.socketHooksKind != "kprobe" {
		return nil
	}
	return l.java.socketHooksFallback
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
