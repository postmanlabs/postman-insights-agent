package trace

import (
	"math"
	"sort"
	"strconv"

	"github.com/OneOfOne/xxhash"
	"github.com/akitasoftware/akita-libs/akid"
	"github.com/akitasoftware/akita-libs/akinet"
	"github.com/akitasoftware/akita-libs/client_telemetry"
	"github.com/postmanlabs/postman-insights-agent/rest"
	"github.com/postmanlabs/postman-insights-agent/util"
	"github.com/spf13/viper"
)

type Collector interface {
	// Hands new data from network to the collector. The implementation may choose
	// to process them asynchronously (e.g. to wait for the response to a
	// corresponding request).
	// Implementations should only return error if the error is unrecoverable and
	// the whole process should stop immediately.
	Process(akinet.ParsedNetworkTraffic) error

	// Implementations must complete processing all requests/responses before
	// returning.
	Close() error
}

// Wraps a Collector and performs sampling.
type SamplingCollector struct {
	// A sample is used if a coin flip is below this threshold.
	sampleThreshold float64

	collector Collector
}

// Wraps a collector and performs sampling. Returns the collector itself if the
// given sampleRate is 1.0.
func NewSamplingCollector(sampleRate float64, collector Collector) Collector {
	if sampleRate == 1.0 {
		return collector
	}

	return &SamplingCollector{
		sampleThreshold: float64(math.MaxUint32) * sampleRate,
		collector:       collector,
	}
}

// Sample based on stream ID and seq so a pair of request and response are
// either both selected or both excluded.
func (sc *SamplingCollector) includeSample(key string) bool {
	h := xxhash.New32()
	h.WriteString(key)
	return float64(h.Sum32()) < sc.sampleThreshold
}

func (sc *SamplingCollector) Process(t akinet.ParsedNetworkTraffic) error {
	var key string
	switch c := t.Content.(type) {
	case akinet.HTTPRequest:
		key = c.StreamID.String() + strconv.Itoa(c.Seq)
	case akinet.HTTPResponse:
		key = c.StreamID.String() + strconv.Itoa(c.Seq)
	case akinet.TCPConnectionMetadata:
		key = akid.String(c.ConnectionID)
	case akinet.TLSHandshakeMetadata:
		key = akid.String(c.ConnectionID)
	default:
		key = ""
	}
	if sc.includeSample(key) {
		return sc.collector.Process(t)
	}
	return nil
}

func (sc *SamplingCollector) Close() error {
	return sc.collector.Close()
}

// Filters out CLI's own traffic to Akita APIs.
type UserTrafficCollector struct {
	Collector Collector
}

func (sc *UserTrafficCollector) Process(t akinet.ParsedNetworkTraffic) error {
	if !util.ContainsCLITraffic(t) {
		return sc.Collector.Process(t)
	}
	return nil
}

func (sc *UserTrafficCollector) Close() error {
	return sc.Collector.Close()
}

// This is a shim to add packet counts based on payload type.
type PacketCountCollector struct {
	PacketCounts         PacketCountConsumer
	Collector            Collector
	SendSuccessTelemetry func()
}

// Don't record self-generated traffic in the breakdown by hostname,
// unless the --dogfood flag has been set.
func (pc *PacketCountCollector) IncludeHostName(tlsName string) bool {
	if tlsName == rest.Domain {
		return viper.GetBool("dogfood")
	}
	return true
}

func (pc *PacketCountCollector) Process(t akinet.ParsedNetworkTraffic) error {
	switch c := t.Content.(type) {
	case akinet.HTTPRequest:
		pc.PacketCounts.Update(client_telemetry.PacketCounts{
			Interface:    t.Interface,
			DstHost:      c.Host,
			SrcPort:      t.SrcPort,
			DstPort:      t.DstPort,
			HTTPRequests: 1,
		})
		// only count the capture as success if we see total.Requests > 0 && total.HTTPResponses > 0
		totalCounts := pc.PacketCounts.Get()
		if totalCounts.HTTPResponses > 0 {
			pc.SendSuccessTelemetry()
		}
	case akinet.HTTPResponse:
		// TODO(cns): There's no easy way to get the host here to count HTTP
		//    responses.  Revisit this if we ever add a pass to pair HTTP
		//    requests and responses independently of the backend collector.
		pc.PacketCounts.Update(client_telemetry.PacketCounts{
			Interface:     t.Interface,
			SrcPort:       t.SrcPort,
			DstPort:       t.DstPort,
			HTTPResponses: 1,
		})
		// only count the capture as success if we see total.Requests > 0 && total.HTTPResponses > 0
		totalCounts := pc.PacketCounts.Get()
		if totalCounts.HTTPRequests > 0 {
			pc.SendSuccessTelemetry()
		}
	case akinet.TLSClientHello:
		dstHost := HostnameUnavailable
		if c.Hostname != nil {
			dstHost = *c.Hostname
		}

		if pc.IncludeHostName(dstHost) {
			pc.PacketCounts.Update(client_telemetry.PacketCounts{
				Interface: t.Interface,
				DstHost:   dstHost,
				SrcPort:   t.SrcPort,
				DstPort:   t.DstPort,
				TLSHello:  1,
			})
		}
	case akinet.TLSServerHello:
		// Ideally, we would pick the DNS name the client used in the
		// Client Hello, but we don't pair those messages.  Barring that, any
		// of the DNS names will serve as a reasonable identifier.  Pick the
		// largest, which avoids "*" prefixes when possible.
		dstHost := HostnameUnavailable
		if 0 < len(c.DNSNames) {
			sort.Strings(c.DNSNames)
			dstHost = c.DNSNames[len(c.DNSNames)-1]
		}

		if pc.IncludeHostName(dstHost) {
			pc.PacketCounts.Update(client_telemetry.PacketCounts{
				Interface: t.Interface,
				DstHost:   dstHost,
				SrcPort:   t.SrcPort,
				DstPort:   t.DstPort,
				TLSHello:  1,
			})
		}
	case akinet.TCPPacketMetadata, akinet.TCPConnectionMetadata:
		// Don't count TCP metadata.
	case akinet.TLSHandshakeMetadata:
		// Don't count TLS metadata.
	case akinet.HTTP2ConnectionPreface:
		pc.PacketCounts.Update(client_telemetry.PacketCounts{
			Interface:     t.Interface,
			SrcPort:       t.SrcPort,
			DstPort:       t.DstPort,
			HTTP2Prefaces: 1,
		})
	case akinet.QUICHandshakeMetadata:
		pc.PacketCounts.Update(client_telemetry.PacketCounts{
			Interface:      t.Interface,
			SrcPort:        t.SrcPort,
			DstPort:        t.DstPort,
			QUICHandshakes: 1,
		})
	default:
		pc.PacketCounts.Update(client_telemetry.PacketCounts{
			Interface: t.Interface,
			SrcPort:   t.SrcPort,
			DstPort:   t.DstPort,
			Unparsed:  1,
		})
	}
	return pc.Collector.Process(t)
}

func (pc *PacketCountCollector) Close() error {
	return pc.Collector.Close()
}
