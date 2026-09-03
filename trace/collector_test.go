package trace

import (
	"net/url"
	"regexp"
	"testing"

	"github.com/akitasoftware/akita-libs/akinet"
	"github.com/akitasoftware/akita-libs/client_telemetry"
	"github.com/google/uuid"
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

func TestRequestFilterReportsBothDirections(t *testing.T) {
	var events []string
	collector := NewHTTPPathFilterCollector([]*regexp.Regexp{regexp.MustCompile("^/private")}, noopCollector{}, func(event string) {
		events = append(events, event)
	})
	streamID := uuid.New()

	collector.Process(akinet.ParsedNetworkTraffic{Content: akinet.HTTPRequest{
		StreamID: streamID, Seq: 1, URL: &url.URL{Path: "/private"},
	}})
	collector.Process(akinet.ParsedNetworkTraffic{Content: akinet.HTTPResponse{
		StreamID: streamID, Seq: 1,
	}})

	if len(events) != 2 || events[0] != "request_filtered" || events[1] != "response_filtered" {
		t.Fatalf("unexpected filter events: %v", events)
	}
}

func TestSamplingReportsHTTPDirections(t *testing.T) {
	var events []string
	collector := NewSamplingCollector(0, noopCollector{}, func(event string) {
		events = append(events, event)
	})
	streamID := uuid.New()

	collector.Process(akinet.ParsedNetworkTraffic{Content: akinet.HTTPRequest{
		StreamID: streamID, Seq: 1,
	}})
	collector.Process(akinet.ParsedNetworkTraffic{Content: akinet.HTTPResponse{
		StreamID: streamID, Seq: 1,
	}})

	if len(events) != 2 || events[0] != "request_sampled_out" || events[1] != "response_sampled_out" {
		t.Fatalf("unexpected sampling events: %v", events)
	}
}
