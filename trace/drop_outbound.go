package trace

import (
	"github.com/akitasoftware/akita-libs/akinet"
	"github.com/postmanlabs/postman-insights-agent/printer"
)

// dropOutboundCollector suppresses DirectionOutbound HTTP messages before they
// reach rate-limit / pair cache. Backend/UI do not support OUTBOUND yet; this
// also drops Istio REDIRECT outbound halves that slip past BPF.
type dropOutboundCollector struct {
	next                   Collector
	telemetryEventReporter func(string)
}

// NewDropOutboundCollector wraps next and drops outbound-direction traffic.
func NewDropOutboundCollector(next Collector, telemetryEventReporter func(string)) Collector {
	return &dropOutboundCollector{next: next, telemetryEventReporter: telemetryEventReporter}
}

func (c *dropOutboundCollector) Process(t akinet.ParsedNetworkTraffic) error {
	switch t.Content.(type) {
	case akinet.HTTPRequest, akinet.HTTPResponse:
		if t.Direction == akinet.DirectionOutbound {
			printer.Debugf("Dropping outbound HTTP message (DirectionOutbound)\n")
			if c.telemetryEventReporter != nil {
				c.telemetryEventReporter("http_dropped_outbound")
			}
			return nil
		}
	}
	return c.next.Process(t)
}

func (c *dropOutboundCollector) Close() error {
	return c.next.Close()
}
