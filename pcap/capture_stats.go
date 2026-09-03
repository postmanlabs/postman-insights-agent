package pcap

import (
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/postmanlabs/postman-insights-agent/capturestats"
	"github.com/postmanlabs/postman-insights-agent/printer"
)

// How often we read libpcap's counters.
const pcapStatsPollInterval = 15 * time.Second

// pollPcapStats accumulates libpcap's capture counters into stats until done
// is closed.
//
// pcap_stats(3) reports packets the kernel handed us, packets it discarded
// because our userspace buffer was full, and packets the interface dropped
// before the capture filter ran. Nothing else in the agent notices a dropped
// packet; the TCP reassembler just sees a hole in the stream. A request
// usually fits in one packet, while a response spans many, so losing a single
// packet is much more likely to destroy a response than the request it
// belongs to -- a response we cannot parse leaves a witness with no response
// half, which the back end then drops as missing_status_code.
//
// pcap_stats reports totals for the lifetime of one handle, and a session
// opens a handle per interface, so we accumulate deltas rather than absolute
// values.
//
// The caller must not close handle until this function has returned: pcap_stats
// dereferences the handle without taking a lock.
func pollPcapStats(handle *pcap.Handle, interfaceName string, stats *capturestats.Stats, done <-chan struct{}, telemetryCountReporter func(string, uint64)) {
	ticker := time.NewTicker(pcapStatsPollInterval)
	defer ticker.Stop()

	var prev pcap.Stats

	sample := func() {
		s, err := handle.Stats()
		if err != nil {
			// Expected while the handle is being torn down.
			printer.Debugf("Could not read pcap stats for %s: %v\n", interfaceName, err)
			return
		}

		// Guard each delta separately: libpcap resets these counters on some
		// platforms, and a reset must not underflow the exported total.
		if s.PacketsReceived >= prev.PacketsReceived {
			received := uint64(s.PacketsReceived - prev.PacketsReceived)
			stats.AddPcapPacketsReceived(received)
			reportPcapCounter(telemetryCountReporter, "pcap_packets_received", received)
		}
		if s.PacketsDropped >= prev.PacketsDropped {
			dropped := uint64(s.PacketsDropped - prev.PacketsDropped)
			stats.AddPcapPacketsDropped(dropped)
			reportPcapCounter(telemetryCountReporter, "pcap_packets_dropped", dropped)
		}
		if s.PacketsIfDropped >= prev.PacketsIfDropped {
			dropped := uint64(s.PacketsIfDropped - prev.PacketsIfDropped)
			stats.AddPcapPacketsIfDropped(dropped)
			reportPcapCounter(telemetryCountReporter, "pcap_interface_packets_dropped", dropped)
		}
		prev = *s
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

func reportPcapCounter(reporter func(string, uint64), event string, count uint64) {
	if reporter != nil && count > 0 {
		reporter(event, count)
	}
}

// Names reported by the akinet HTTP parser factories.
const (
	httpRequestParserFactoryName  = "HTTP/1.x Request Parser Factory"
	httpResponseParserFactoryName = "HTTP/1.x Response Parser Factory"
)

// countDiscardedByParserKind attributes a discarded message to the half of
// the exchange it belonged to, using the name of the parser factory that had
// already agreed to parse it, and records it on stats.
//
// This sits alongside stats.NilAssemblerContext/BadAssemblerContextType,
// which count the same failures but are shared across both directions of
// every flow. The split matters because the two halves fail differently
// downstream:
//
//   - A discarded response leaves the request with nothing to pair with, so
//     we upload a witness with a request and no response, which the back end
//     drops as missing_status_code.
//   - A discarded request produces no witness at all. Its response then
//     arrives, fails to match any request in the rate limiter, and is
//     dropped there too. Both halves vanish without appearing in any drop
//     count.
//
// Two caveats when reading these. They count *events*, not messages: after
// one of these the stream is desynced mid-message, so the following bytes
// are discarded as unparseable until a new message boundary is found, and a
// single event can therefore cost more than one message. And they only
// cover this one failure path -- bytes that no parser would accept are
// counted as Unparsed instead.
func countDiscardedByParserKind(stats *capturestats.Stats, factoryName string) {
	switch factoryName {
	case httpRequestParserFactoryName:
		stats.IncrDiscardedRequests()
	case httpResponseParserFactoryName:
		stats.IncrDiscardedResponses()
	default:
		// TLS, HTTP/2 prefaces, and anything else with a parser factory.
		stats.IncrDiscardedOther()
	}
}
