package trace

import (
	"testing"

	"github.com/akitasoftware/akita-libs/akinet"
	"github.com/postmanlabs/postman-insights-agent/capturestats"
	"github.com/stretchr/testify/assert"
)

// dropOutboundCollector is the single point where outbound traffic leaves the
// funnel. It sits ahead of rate limiting and the pair cache in every chain, so
// outbound messages must not consume witness budget or pair-cache slots.
//
// Drops are counted, not reported per message: a service that mostly calls
// other services has outbound as its dominant traffic class, so per-message
// telemetry would take the DaemonSet's node-wide lock for most of its traffic.
func TestDropOutboundCollectorCountsOutboundHTTP(t *testing.T) {
	stats := capturestats.New()
	next := &countingCollector{}
	c := NewDropOutboundCollector(next, stats)

	err := c.Process(akinet.ParsedNetworkTraffic{
		Content:   akinet.HTTPRequest{},
		Direction: akinet.DirectionOutbound,
	})
	assert.NoError(t, err)
	err = c.Process(akinet.ParsedNetworkTraffic{
		Content:   akinet.HTTPResponse{},
		Direction: akinet.DirectionOutbound,
	})
	assert.NoError(t, err)

	assert.Equal(t, 0, next.GetNumPackets(), "outbound messages reached the next collector")
	snapshot := stats.Snapshot()
	assert.Equal(t, uint64(1), snapshot.RequestsDroppedOutbound)
	assert.Equal(t, uint64(1), snapshot.ResponsesDroppedOutbound)
}

// Inbound and unknown-direction traffic must pass through untouched. Unknown
// matters because the pcap path reports it whenever no direction hint could be
// built (see pcap.classifyHTTPDirection), and dropping those would silently
// discard every witness on such a capture.
func TestDropOutboundCollectorPassesOtherDirections(t *testing.T) {
	for _, direction := range []akinet.NetTrafficDirection{
		akinet.DirectionInbound,
		akinet.DirectionUnknown,
	} {
		stats := capturestats.New()
		next := &countingCollector{}
		c := NewDropOutboundCollector(next, stats)

		err := c.Process(akinet.ParsedNetworkTraffic{
			Content:   akinet.HTTPRequest{},
			Direction: direction,
		})

		assert.NoError(t, err)
		assert.Equal(t, 1, next.GetNumPackets(), "direction %v was dropped", direction)
		assert.Equal(t, uint64(0), stats.Snapshot().RequestsDroppedOutbound)
	}
}

// Non-HTTP content carries no service-relative direction, so it must pass
// through regardless -- TCP and TLS metadata reports are how the backend
// learns about connections that never produced a witness.
func TestDropOutboundCollectorPassesNonHTTPContent(t *testing.T) {
	stats := capturestats.New()
	next := &countingCollector{}
	c := NewDropOutboundCollector(next, stats)

	err := c.Process(akinet.ParsedNetworkTraffic{
		Content:   akinet.TCPConnectionMetadata{},
		Direction: akinet.DirectionOutbound,
	})

	assert.NoError(t, err)
	assert.Equal(t, 1, next.GetNumPackets(), "non-HTTP content was dropped")
	assert.Equal(t, uint64(0), stats.Snapshot().RequestsDroppedOutbound)
}

// Reachable with a nil Stats from callers that build no capture-diagnostics
// counters; the drop must still happen.
func TestDropOutboundCollectorWithNilStatsDoesNotPanic(t *testing.T) {
	next := &countingCollector{}
	c := NewDropOutboundCollector(next, nil)

	err := c.Process(akinet.ParsedNetworkTraffic{
		Content:   akinet.HTTPRequest{},
		Direction: akinet.DirectionOutbound,
	})

	assert.NoError(t, err)
	assert.Equal(t, 0, next.GetNumPackets())
}
