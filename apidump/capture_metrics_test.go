package apidump

import (
	"sync"
	"testing"

	"github.com/akitasoftware/akita-libs/client_telemetry"
	"github.com/akitasoftware/go-utils/optionals"
	"github.com/postmanlabs/postman-insights-agent/capturestats"
	"github.com/postmanlabs/postman-insights-agent/trace"
)

func TestTelemetryWorkerFinalizationIncludesLateCaptureMetrics(t *testing.T) {
	var mu sync.Mutex
	reported := map[string]uint64{}
	a := &apidump{
		Args: &Args{
			TelemetryInterval: 60,
			DaemonsetArgs: optionals.Some(DaemonsetArgs{
				ReportTelemetryCount: func(event string, count uint64) {
					mu.Lock()
					defer mu.Unlock()
					reported[event] += count
				},
			}),
		},
		captureStats: capturestats.New(),
		dumpSummary: &Summary{
			PrefilterSummary: trace.NewPacketCounter(),
			FilterSummary:    trace.NewPacketCounter(),
		},
		successTelemetry: &trace.SuccessTelemetry{Channel: make(chan struct{})},
	}

	stopTelemetry := a.startTelemetryWorker()

	// These emulate message and pair-cache work completed while collectors stop.
	a.dumpSummary.PrefilterSummary.Update(client_telemetry.PacketCounts{HTTPRequests: 2})
	a.dumpSummary.FilterSummary.Update(client_telemetry.PacketCounts{HTTPRequests: 2})
	a.captureStats.IncrWitnessesPaired()
	a.captureStats.IncrWitnessesPaired()

	stopTelemetry()

	mu.Lock()
	defer mu.Unlock()
	if reported["pcap_http_request_prefilter"] != 2 {
		t.Fatalf("pcap_http_request_prefilter = %d, want 2", reported["pcap_http_request_prefilter"])
	}
	if reported["pcap_http_request_postfilter"] != 2 {
		t.Fatalf("pcap_http_request_postfilter = %d, want 2", reported["pcap_http_request_postfilter"])
	}
	if reported["pcap_witness_paired"] != 2 {
		t.Fatalf("pcap_witness_paired = %d, want 2", reported["pcap_witness_paired"])
	}
}
