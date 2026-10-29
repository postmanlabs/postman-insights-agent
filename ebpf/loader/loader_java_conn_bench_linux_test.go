// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package loader

import (
	"io"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/postmanlabs/postman-insights-agent/ebpf/javatls"
)

// BenchmarkJavaReadHook measures what the tcp_recvmsg hook costs: TCP round
// trips over loopback without the Java programs, then with the hook attached
// by fexit and by kprobe with kretprobe, for a process that sends no frames (every other
// process on the node: one map lookup) and for one that does (a JVM with the
// agent: the read's addresses recorded). It reports the hook's own run time
// per call from the kernel's BPF statistics.
//
//	go test -tags insights_bpf -run - -bench JavaReadHook ./ebpf/loader/
func BenchmarkJavaReadHook(b *testing.B) {
	if os.Geteuid() != 0 {
		b.Skip("requires root (CAP_BPF + CAP_PERFMON)")
	}
	stats, err := ebpf.EnableStats(uint32(unix.BPF_STATS_RUN_TIME))
	if err != nil {
		b.Fatalf("enable BPF stats: %v", err)
	}
	defer stats.Close()

	b.Run("no-hook", func(b *testing.B) { benchRoundTrips(b, nil) })
	for _, kprobe := range []bool{false, true} {
		for _, sender := range []bool{false, true} {
			name := "fexit"
			if kprobe {
				name = "kprobe"
			}
			if sender {
				name += "/frame-sender"
			} else {
				name += "/other-process"
			}
			b.Run(name, func(b *testing.B) {
				l, err := Load(Config{EnableJava: true, EnforceJavaNetnsAllowlist: true, javaReadHookKprobe: kprobe})
				if err != nil {
					b.Fatal(err)
				}
				defer l.Close()
				if _, err := l.JavaConnAddresses(); err != nil {
					b.Fatal(err)
				}
				if sender {
					var st syscall.Stat_t
					if err := syscall.Stat("/proc/self/ns/net", &st); err != nil {
						b.Fatal(err)
					}
					if err := l.AllowJavaNetns(st.Ino); err != nil {
						b.Fatal(err)
					}
					devNull, err := os.OpenFile("/dev/null", os.O_WRONLY, 0)
					if err != nil {
						b.Fatal(err)
					}
					frame := javatls.Frame{Version: javatls.Version1, Op: javatls.OpHeartbeat}.Append(nil)
					if _, err := unix.Pwrite(int(devNull.Fd()), frame, int64(javatls.Magic)); err != nil {
						b.Fatal(err)
					}
					devNull.Close()
				}
				// The read hooks: a round trip has no write by a thread
				// with a pending connection.
				benchRoundTrips(b, readHooks(l.java))
			})
		}
	}
}

// benchRoundTrips runs b.N one-byte round trips over a loopback TCP
// connection, each with two tcp_recvmsg calls (the echo's and the
// client's), and reports the hooks' run time per tcp_recvmsg call.
func benchRoundTrips(b *testing.B, hooks []*ebpf.Program) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// Explicit reads and writes: io.Copy between TCP connections
		// splices, bypassing tcp_recvmsg.
		buf := make([]byte, 1)
		for {
			if _, err := c.Read(buf); err != nil {
				return
			}
			if _, err := c.Write(buf); err != nil {
				return
			}
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	defer c.Close()

	// The run time of all the hooks, and the calls of the first (each
	// tcp_recvmsg runs every hook once).
	runTime := func() (ns, calls uint64) {
		for i, hook := range hooks {
			info, err := hook.Info()
			if err != nil {
				b.Fatal(err)
			}
			rt, _ := info.Runtime()
			ns += uint64(rt)
			if i == 0 {
				calls, _ = info.RunCount()
			}
		}
		return ns, calls
	}
	ns0, calls0 := runTime()
	buf := []byte{'x'}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.Write(buf); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(c, buf); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	if ns1, calls1 := runTime(); calls1 > calls0 {
		b.ReportMetric(float64(ns1-ns0)/float64(calls1-calls0), "hook-ns/call")
	}
}

// readHooks returns the tcp_recvmsg programs of j.socketHooks.
func readHooks(j *javaTLS) []*ebpf.Program {
	if j.socketHooksKind == "fexit" {
		return j.socketHooks[:1]
	}
	return j.socketHooks[:2]
}
