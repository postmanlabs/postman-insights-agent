package pcap

import (
	"sync/atomic"
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/postmanlabs/postman-insights-agent/printer"
)

// Capture counters reported by libpcap itself, summed over every handle opened
// during a capture session.
//
// These come from pcap_stats(3): packets the kernel handed us, packets it
// discarded because our userspace buffer was full, and packets the interface
// dropped before the capture filter ran. Nothing else in the agent notices a
// dropped packet; the TCP reassembler just sees a hole in the stream.
//
// The asymmetry is what makes these worth reporting. A request usually fits in
// one packet, while a response spans many, so losing a single packet is much
// more likely to destroy a response than the request it belongs to. A response
// we cannot parse leaves a witness with no response half, which the back end
// then drops as missing_status_code.
var (
	CountPcapPacketsReceived  uint64
	CountPcapPacketsDropped   uint64
	CountPcapPacketsIfDropped uint64
)

// How often we read libpcap's counters.
const pcapStatsPollInterval = 15 * time.Second

// pollPcapStats accumulates libpcap's capture counters until done is closed.
//
// pcap_stats reports totals for the lifetime of one handle, and a session opens
// a handle per interface, so we accumulate deltas rather than absolute values.
//
// The caller must not close handle until this function has returned: pcap_stats
// dereferences the handle without taking a lock.
func pollPcapStats(handle *pcap.Handle, interfaceName string, done <-chan struct{}) {
	ticker := time.NewTicker(pcapStatsPollInterval)
	defer ticker.Stop()

	var prev pcap.Stats

	sample := func() {
		stats, err := handle.Stats()
		if err != nil {
			// Expected while the handle is being torn down.
			printer.Debugf("Could not read pcap stats for %s: %v\n", interfaceName, err)
			return
		}

		// Guard each delta separately: libpcap resets these counters on some
		// platforms, and a reset must not underflow the exported total.
		if stats.PacketsReceived >= prev.PacketsReceived {
			atomic.AddUint64(&CountPcapPacketsReceived, uint64(stats.PacketsReceived-prev.PacketsReceived))
		}
		if stats.PacketsDropped >= prev.PacketsDropped {
			atomic.AddUint64(&CountPcapPacketsDropped, uint64(stats.PacketsDropped-prev.PacketsDropped))
		}
		if stats.PacketsIfDropped >= prev.PacketsIfDropped {
			atomic.AddUint64(&CountPcapPacketsIfDropped, uint64(stats.PacketsIfDropped-prev.PacketsIfDropped))
		}
		prev = *stats
	}

	for {
		select {
		case <-done:
			// Take a final sample so the last interval is not lost.
			sample()
			return
		case <-ticker.C:
			sample()
		}
	}
}

// Messages discarded at parser-creation time, split by which half of the
// exchange they were.
//
// These sit alongside CountNilAssemblerContext and CountBadAssemblerContextType,
// which count the same failures but are shared across both directions of every
// flow. The split matters because the two halves fail differently downstream:
//
//   - A discarded response leaves the request with nothing to pair with, so we
//     upload a witness with a request and no response, which the back end drops
//     as missing_status_code.
//   - A discarded request produces no witness at all. Its response then arrives,
//     fails to match any request in the rate limiter, and is dropped there too.
//     Both halves vanish without appearing in any drop count.
//
// Two caveats when reading these. They count *events*, not messages: after one
// of these the stream is desynced mid-message, so the following bytes are
// discarded as unparseable until a new message boundary is found, and a single
// event can therefore cost more than one message. And they only cover this one
// failure path -- bytes that no parser would accept are counted as Unparsed
// instead.
var (
	CountDiscardedRequests  uint64
	CountDiscardedResponses uint64
	CountDiscardedOther     uint64
)

// Names reported by the akinet HTTP parser factories.
const (
	httpRequestParserFactoryName  = "HTTP/1.x Request Parser Factory"
	httpResponseParserFactoryName = "HTTP/1.x Response Parser Factory"
)

// countDiscardedByParserKind attributes a discarded message to the half of the
// exchange it belonged to, using the name of the parser factory that had already
// agreed to parse it.
func countDiscardedByParserKind(factoryName string) {
	switch factoryName {
	case httpRequestParserFactoryName:
		atomic.AddUint64(&CountDiscardedRequests, 1)
	case httpResponseParserFactoryName:
		atomic.AddUint64(&CountDiscardedResponses, 1)
	default:
		// TLS, HTTP/2 prefaces, and anything else with a parser factory.
		atomic.AddUint64(&CountDiscardedOther, 1)
	}
}
