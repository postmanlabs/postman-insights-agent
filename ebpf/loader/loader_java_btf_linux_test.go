//go:build linux && insights_bpf

package loader

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/cilium/ebpf/btf"
)

// btfWithFunc returns BTF holding one function, name, with params int
// arguments, as a kernel's BTF describes tcp_recvmsg.
func btfWithFunc(t *testing.T, name string, params int) *btf.Spec {
	t.Helper()
	intType := &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}
	proto := &btf.FuncProto{Return: intType}
	for i := 0; i < params; i++ {
		proto.Params = append(proto.Params, btf.FuncParam{Name: fmt.Sprintf("arg%d", i), Type: intType})
	}
	b, err := btf.NewBuilder([]btf.Type{&btf.Func{Name: name, Type: proto, Linkage: btf.GlobalFunc}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := b.Marshal(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := btf.LoadSpecFromReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

// TestTCPRecvmsgSignature: the fexit program is picked by the number of
// tcp_recvmsg's arguments in the kernel's BTF (6 before Linux 5.19, 5 after,
// 4 on later kernels), and any other number is refused, so the loader falls
// back to kprobes. Synthetic BTF, so every signature is checked on any
// kernel.
func TestTCPRecvmsgSignature(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fn      string
		params  int
		wantErr bool
	}{
		{"without nonblock and addr_len", "tcp_recvmsg", 4, false},
		{"Linux 5.19+, without nonblock", "tcp_recvmsg", 5, false},
		{"before Linux 5.19", "tcp_recvmsg", 6, false},
		{"too few arguments", "tcp_recvmsg", 3, true},
		{"too many arguments", "tcp_recvmsg", 7, true},
		{"no tcp_recvmsg", "udp_recvmsg", 5, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args, err := tcpRecvmsgArgs(btfWithFunc(t, tc.fn, tc.params))
			if tc.wantErr {
				if err == nil {
					t.Errorf("tcpRecvmsgArgs = %d, want an error", args)
				}
				return
			}
			if err != nil || args != tc.params {
				t.Errorf("tcpRecvmsgArgs = %d, %v; want %d", args, err, tc.params)
			}
		})
	}

	// This kernel's own BTF has one of them.
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		t.Skipf("no kernel BTF: %v", err)
	}
	args, err := tcpRecvmsgArgs(kernel)
	if err != nil {
		t.Fatalf("this kernel's tcp_recvmsg: %v", err)
	}
	t.Logf("this kernel's tcp_recvmsg has %d arguments", args)
}
