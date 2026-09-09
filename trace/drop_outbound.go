package trace

import (
	"github.com/akitasoftware/akita-libs/akinet"
	"github.com/postmanlabs/postman-insights-agent/capturestats"
	"github.com/postmanlabs/postman-insights-agent/printer"
)

// dropOutboundCollector suppresses DirectionOutbound HTTP messages before they
// reach rate-limit / pair cache. Backend/UI do not support OUTBOUND yet; this
// also drops Istio REDIRECT outbound halves that slip past BPF.
type dropOutboundCollector struct {
	next Collector

	// Outbound drops are counted, not reported per message: a service that
	// mostly calls other services has outbound as its dominant traffic class,
	// and one telemetry event each would take the DaemonSet's node-wide lock
	// for most of its traffic. Split by direction so the counters line up
	// with the request/response columns either side of them in the funnel.
	stats *capturestats.Stats
}

// NewDropOutboundCollector wraps next and drops outbound-direction traffic.
func NewDropOutboundCollector(next Collector, stats *capturestats.Stats) Collector {
	return &dropOutboundCollector{next: next, stats: stats}
}

func (c *dropOutboundCollector) Process(t akinet.ParsedNetworkTraffic) error {
	if t.Direction == akinet.DirectionOutbound {
		switch t.Content.(type) {
		case akinet.HTTPRequest:
			printer.Debugf("Dropping outbound HTTP request (DirectionOutbound)\n")
			c.stats.IncrRequestsDroppedOutbound()
			return nil
		case akinet.HTTPResponse:
			printer.Debugf("Dropping outbound HTTP response (DirectionOutbound)\n")
			c.stats.IncrResponsesDroppedOutbound()
			return nil
		}
	}
	return c.next.Process(t)
}

func (c *dropOutboundCollector) Close() error {
	return c.next.Close()
}
