package trace

import (
	"net"
	"testing"

	"github.com/akitasoftware/akita-libs/akinet"
)

func TestConnectionContextTrackerClassifiesRequestOwnership(t *testing.T) {
	tracker := NewConnectionContextTracker()
	firstCollector := tracker.registerCollector()
	secondCollector := tracker.registerCollector()
	request := connectionContextTraffic(net.IPv4(10, 0, 0, 1), 8080, net.IPv4(10, 0, 0, 2), 50000)
	response := connectionContextTraffic(net.IPv4(10, 0, 0, 2), 50000, net.IPv4(10, 0, 0, 1), 8080)

	tracker.observeRequest(request, firstCollector)
	if got := tracker.classifyResponse(response, firstCollector); got != unmatchedResponseContextRequestSeenLocalCollector {
		t.Fatalf("local response context = %d, want local collector", got)
	}
	if got := tracker.classifyResponse(response, secondCollector); got != unmatchedResponseContextRequestSeenOtherCollector {
		t.Fatalf("other response context = %d, want other collector", got)
	}
	if got := tracker.classifyResponse(connectionContextTraffic(net.IPv4(10, 0, 0, 3), 50001, net.IPv4(10, 0, 0, 1), 8080), firstCollector); got != unmatchedResponseContextResponseFirst {
		t.Fatalf("unseen response context = %d, want response first", got)
	}
	if got := tracker.classifyResponse(akinet.ParsedNetworkTraffic{}, firstCollector); got != unmatchedResponseContextUnknown {
		t.Fatalf("incomplete response context = %d, want unknown", got)
	}
}

func connectionContextTraffic(src net.IP, srcPort int, dst net.IP, dstPort int) akinet.ParsedNetworkTraffic {
	return akinet.ParsedNetworkTraffic{SrcIP: src, SrcPort: srcPort, DstIP: dst, DstPort: dstPort}
}
