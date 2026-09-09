package trace

import (
	"testing"

	"github.com/akitasoftware/akita-libs/akinet"
	"github.com/stretchr/testify/assert"
)

// dropOutboundCollector is the single point where outbound traffic leaves the
// funnel. It sits ahead of rate limiting and the pair cache in every chain, so
// outbound messages must not consume witness budget or pair-cache slots.
func TestDropOutboundCollectorDropsOutboundHTTP(t *testing.T) {
	for _, content := range []akinet.ParsedNetworkContent{
		akinet.HTTPRequest{},
		akinet.HTTPResponse{},
	} {
		next := &countingCollector{}
		var events []string
		c := NewDropOutboundCollector(next, func(event string) {
			events = append(events, event)
		})

		err := c.Process(akinet.ParsedNetworkTraffic{
			Content:   content,
			Direction: akinet.DirectionOutbound,
		})

		assert.NoError(t, err)
		assert.Equal(t, 0, next.GetNumPackets(), "outbound message reached the next collector")
		assert.Equal(t, []string{"http_dropped_outbound"}, events)
	}
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
		next := &countingCollector{}
		var events []string
		c := NewDropOutboundCollector(next, func(event string) {
			events = append(events, event)
		})

		err := c.Process(akinet.ParsedNetworkTraffic{
			Content:   akinet.HTTPRequest{},
			Direction: direction,
		})

		assert.NoError(t, err)
		assert.Equal(t, 1, next.GetNumPackets(), "direction %v was dropped", direction)
		assert.Empty(t, events)
	}
}

// Non-HTTP content carries no service-relative direction, so it must pass
// through regardless -- TCP and TLS metadata reports are how the backend
// learns about connections that never produced a witness.
func TestDropOutboundCollectorPassesNonHTTPContent(t *testing.T) {
	next := &countingCollector{}
	c := NewDropOutboundCollector(next, nil)

	err := c.Process(akinet.ParsedNetworkTraffic{
		Content:   akinet.TCPConnectionMetadata{},
		Direction: akinet.DirectionOutbound,
	})

	assert.NoError(t, err)
	assert.Equal(t, 1, next.GetNumPackets(), "non-HTTP content was dropped")
}
