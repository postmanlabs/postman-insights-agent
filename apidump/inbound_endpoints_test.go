package apidump

import (
	"net"
	"testing"
	"time"

	"github.com/akitasoftware/go-utils/optionals"
)

func TestParseListenPortFromProcNetTCPLine(t *testing.T) {
	// Port 1337 = 0x539
	line := "0: 00000000:0539 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1 1"
	port, ok := parseListenPortFromProcNetTCPLine(line)
	if !ok || port != 1337 {
		t.Fatalf("got port=%d ok=%v, want 1337 true", port, ok)
	}

	estab := "0: 0100007F:0539 0100007F:1F90 01 00000000:00000000 00:00000000 00000000 0 0 1 1"
	if _, ok := parseListenPortFromProcNetTCPLine(estab); ok {
		t.Fatal("established row should not parse as listen")
	}
}

func TestBuildInboundBPFFilterForEndpoints(t *testing.T) {
	ips := []net.IP{net.ParseIP("10.0.0.5").To4(), net.ParseIP("127.0.0.1").To4()}
	ports := []uint16{1337, 8080}
	expr := buildInboundBPFFilterForEndpoints(ips, ports)
	for _, want := range []string{
		"src host 10.0.0.5 and src port 1337",
		"dst host 10.0.0.5 and dst port 1337",
		"src host 127.0.0.1 and src port 8080",
		"dst host 127.0.0.1 and dst port 8080",
	} {
		if !containsSubstring(expr, want) {
			t.Fatalf("filter missing %q; got %q", want, expr)
		}
	}
}

func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		(func() bool {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		})())
}

func TestDefaultExcludedListenPortsIncludeEnvoy(t *testing.T) {
	for _, p := range []uint16{15001, 15006, 15021, 22} {
		if !shouldExcludeListenPort(p, defaultExcludedListenPorts) {
			t.Fatalf("expected port %d to be excluded", p)
		}
	}
	if shouldExcludeListenPort(1337, defaultExcludedListenPorts) {
		t.Fatal("app port 1337 must not be excluded")
	}
}

func TestProcRootAndPIDFromNSPath(t *testing.T) {
	root, pid, ok := procRootAndPIDFromNSPath("/host/proc/12345/ns/net")
	if !ok || root != "/host/proc" || pid != 12345 {
		t.Fatalf("got root=%q pid=%d ok=%v", root, pid, ok)
	}
	root, pid, ok = procRootAndPIDFromNSPath("/proc/9/ns/net")
	if !ok || root != "/proc" || pid != 9 {
		t.Fatalf("got root=%q pid=%d ok=%v", root, pid, ok)
	}
	if _, _, ok := procRootAndPIDFromNSPath("/var/run/netns/foo"); ok {
		t.Fatal("expected non-proc ns path to be rejected")
	}
}

func TestApplyAutoInboundFiltersNoPortsDoesNotHang(t *testing.T) {
	prevTotal, prevInterval := inboundDiscoveryRetryTotal, inboundDiscoveryRetryInterval
	inboundDiscoveryRetryTotal = 0
	inboundDiscoveryRetryInterval = time.Millisecond
	defer func() {
		inboundDiscoveryRetryTotal = prevTotal
		inboundDiscoveryRetryInterval = prevInterval
	}()

	ifaces := map[string]interfaceInfo{"eth0": interfaceWrapper{}}
	filters := map[string]string{"eth0": ""}
	out, _ := applyAutoInboundFilters(ifaces, filters, optionals.None[string](), "")
	if out["eth0"] != "" {
		t.Fatalf("expected empty filter when no listen ports, got %q", out["eth0"])
	}
}
