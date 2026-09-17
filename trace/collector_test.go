package trace

import (
	"net/http"
	"net/url"
	"regexp"
	"testing"

	"github.com/akitasoftware/akita-libs/akinet"
	"github.com/akitasoftware/akita-libs/client_telemetry"
	"github.com/akitasoftware/akita-libs/spec_util"
	"github.com/google/uuid"
	"github.com/postmanlabs/postman-insights-agent/capturestats"
	"github.com/stretchr/testify/assert"
)

type noopCollector struct{}

func (noopCollector) Process(akinet.ParsedNetworkTraffic) error { return nil }
func (noopCollector) Close() error                              { return nil }

func TestPacketCountCollectorCountsHTTP(t *testing.T) {
	packetCounts := NewPacketCounter()
	collector := &PacketCountCollector{
		PacketCounts: packetCounts,
		Collector:    noopCollector{},
	}

	streamID := uuid.New()
	if err := collector.Process(akinet.ParsedNetworkTraffic{
		Interface: "en0",
		SrcPort:   1234,
		DstPort:   8080,
		Content: akinet.HTTPRequest{
			StreamID: streamID,
			Seq:      1,
			Host:     "example.com",
		},
	}); err != nil {
		t.Fatalf("processing request: %v", err)
	}
	if err := collector.Process(akinet.ParsedNetworkTraffic{
		Interface: "en0",
		SrcPort:   8080,
		DstPort:   1234,
		Content: akinet.HTTPResponse{
			StreamID: streamID,
			Seq:      1,
		},
	}); err != nil {
		t.Fatalf("processing response: %v", err)
	}

	total := packetCounts.Total()
	if total.HTTPRequests != 1 || total.HTTPResponses != 1 {
		t.Fatalf("expected HTTP counts to be incremented, got %+v", total)
	}
	if total.HTTPSRequests != 0 || total.HTTPSResponses != 0 {
		t.Fatalf("expected HTTPS counts to remain zero, got %+v", total)
	}
}

func TestPacketCountCollectorCountsHTTPS(t *testing.T) {
	packetCounts := NewPacketCounter()
	collector := &PacketCountCollector{
		PacketCounts: packetCounts,
		Collector:    noopCollector{},
	}

	streamID := uuid.New()
	if err := collector.Process(akinet.ParsedNetworkTraffic{
		Interface:         "en0",
		SrcPort:           1234,
		DstPort:           443,
		TransportSecurity: akinet.TransportSecurityTLS,
		Content: akinet.HTTPRequest{
			StreamID: streamID,
			Seq:      1,
			Host:     "example.com",
		},
	}); err != nil {
		t.Fatalf("processing request: %v", err)
	}
	if err := collector.Process(akinet.ParsedNetworkTraffic{
		Interface:         "en0",
		SrcPort:           443,
		DstPort:           1234,
		TransportSecurity: akinet.TransportSecurityTLS,
		Content: akinet.HTTPResponse{
			StreamID: streamID,
			Seq:      1,
		},
	}); err != nil {
		t.Fatalf("processing response: %v", err)
	}

	total := packetCounts.Total()
	if total.HTTPSRequests != 1 || total.HTTPSResponses != 1 {
		t.Fatalf("expected HTTPS counts to be incremented, got %+v", total)
	}
	if total.HTTPRequests != 0 || total.HTTPResponses != 0 {
		t.Fatalf("expected HTTP counts to remain zero, got %+v", total)
	}
	if !packetCounts.HasRequestAndResponse() {
		t.Fatal("expected HTTPS request/response pair to count as captured traffic")
	}
}

func TestPacketCounterRequiresMatchingProtocolPair(t *testing.T) {
	packetCounts := NewPacketCounter()
	packetCounts.Update(client_telemetry.PacketCounts{
		HTTPRequests: 1,
	})
	packetCounts.Update(client_telemetry.PacketCounts{
		HTTPSResponses: 1,
	})

	if packetCounts.HasRequestAndResponse() {
		t.Fatal("expected mixed HTTP/HTTPS counts without a matching pair to remain incomplete")
	}
}

// Filtered traffic is recorded on the session's counters, not as one
// telemetry event per message: a broad filter can exclude nearly everything on
// the interface, and per-message reporting would take the DaemonSet's
// node-wide telemetry lock that many times on the capture path.
func TestRequestFilterCountsBothDirections(t *testing.T) {
	stats := capturestats.New()
	collector := NewHTTPPathFilterCollector([]*regexp.Regexp{regexp.MustCompile("^/private")}, noopCollector{}, stats)
	streamID := uuid.New()

	collector.Process(akinet.ParsedNetworkTraffic{Content: akinet.HTTPRequest{
		StreamID: streamID, Seq: 1, URL: &url.URL{Path: "/private"},
	}})
	collector.Process(akinet.ParsedNetworkTraffic{Content: akinet.HTTPResponse{
		StreamID: streamID, Seq: 1,
	}})

	snapshot := stats.Snapshot()
	assert.Equal(t, uint64(1), snapshot.RequestsFiltered)
	assert.Equal(t, uint64(1), snapshot.ResponsesFiltered)
}

// Unfiltered traffic must reach the next collector and leave the counters
// alone, so the counter cannot be read as "messages seen".
func TestRequestFilterPassesUnmatchedTraffic(t *testing.T) {
	stats := capturestats.New()
	next := &countingCollector{}
	collector := NewHTTPPathFilterCollector([]*regexp.Regexp{regexp.MustCompile("^/private")}, next, stats)

	collector.Process(akinet.ParsedNetworkTraffic{Content: akinet.HTTPRequest{
		StreamID: uuid.New(), Seq: 1, URL: &url.URL{Path: "/public"},
	}})

	assert.Equal(t, 1, next.GetNumPackets())
	assert.Equal(t, uint64(0), stats.Snapshot().RequestsFiltered)
}

// Same rationale as filtering: below a sample rate of 1.0 the excluded
// messages are the majority by definition.
func TestSamplingCountsHTTPDirections(t *testing.T) {
	stats := capturestats.New()
	collector := NewSamplingCollector(0, noopCollector{}, stats)
	streamID := uuid.New()

	collector.Process(akinet.ParsedNetworkTraffic{Content: akinet.HTTPRequest{
		StreamID: streamID, Seq: 1,
	}})
	collector.Process(akinet.ParsedNetworkTraffic{Content: akinet.HTTPResponse{
		StreamID: streamID, Seq: 1,
	}})

	snapshot := stats.Snapshot()
	assert.Equal(t, uint64(1), snapshot.RequestsSampledOut)
	assert.Equal(t, uint64(1), snapshot.ResponsesSampledOut)
}

// A nil Stats must not panic: NewSamplingCollector is reachable from commands
// that do not build a capture-diagnostics Stats.
func TestSamplingWithNilStatsDoesNotPanic(t *testing.T) {
	collector := NewSamplingCollector(0, noopCollector{}, nil)

	err := collector.Process(akinet.ParsedNetworkTraffic{Content: akinet.HTTPRequest{
		StreamID: uuid.New(), Seq: 1,
	}})

	assert.NoError(t, err)
}

func TestUserTrafficCollectorRecordsHTTPDropReasons(t *testing.T) {
	stats := capturestats.New()
	collector := &UserTrafficCollector{
		Collector:          noopCollector{},
		DropDogfoodTraffic: true,
		DropNginxTraffic:   true,
		Stats:              stats,
	}
	agentRequestHeaders := http.Header{}
	agentRequestHeaders.Set(spec_util.XAkitaRequestID, "request-id")
	agentResponseHeaders := http.Header{}
	agentResponseHeaders.Set(spec_util.XAkitaCLIGitVersion, "version")

	collector.Process(akinet.ParsedNetworkTraffic{Content: akinet.HTTPRequest{
		Header: agentRequestHeaders,
	}})
	collector.Process(akinet.ParsedNetworkTraffic{Content: akinet.HTTPResponse{
		Header: agentResponseHeaders,
	}})
	collector.Process(akinet.ParsedNetworkTraffic{Content: akinet.HTTPRequest{
		Header: http.Header{"Server": {"nginx"}},
	}})
	collector.Process(akinet.ParsedNetworkTraffic{Content: akinet.HTTPResponse{
		Header: http.Header{"Server": {"nginx"}},
	}})

	snapshot := stats.Snapshot()
	if snapshot.RequestsDroppedAgentTraffic != 1 || snapshot.ResponsesDroppedAgentTraffic != 1 ||
		snapshot.RequestsDroppedNginxTraffic != 1 || snapshot.ResponsesDroppedNginxTraffic != 1 {
		t.Fatalf("unexpected user-traffic counters: %+v", snapshot)
	}
}
