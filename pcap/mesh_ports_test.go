package pcap

import "testing"

func TestIsMeshProxyPort(t *testing.T) {
	for _, p := range []uint16{15000, 15001, 15006, 15090} {
		if !IsMeshProxyPort(p) {
			t.Fatalf("expected port %d to be a mesh proxy port", p)
		}
	}
	for _, p := range []uint16{22, 80, 443, 1337, 14999, 15091} {
		if IsMeshProxyPort(p) {
			t.Fatalf("port %d must not be treated as a mesh proxy port", p)
		}
	}
}
