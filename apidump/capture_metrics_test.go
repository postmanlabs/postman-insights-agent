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
	a.captureStats.IncrRequestsRateLimited()
	a.captureStats.IncrRequestsRateLimited()
	a.captureStats.IncrRequestsRateLimited()
	a.captureStats.AddRequestKeysExpired(2)
	a.captureStats.IncrRequestsDroppedAgentTraffic()
	a.captureStats.IncrResponsesDroppedNginxTraffic()
	a.captureStats.IncrResponsesDroppedNoMatchingRequest()
	a.captureStats.IncrResponsesDroppedNoMatchingRequest()
	a.captureStats.IncrResponsesDroppedNoMatchingRequestRateLimited()
	a.captureStats.IncrResponsesDroppedNoMatchingRequestActiveRequestStream()
	a.captureStats.IncrResponsesDroppedNoMatchingRequestResponseFirst()
	a.captureStats.IncrResponsesDroppedNoMatchingRequestRequestSeenLocalCollector()
	a.captureStats.IncrResponsesDroppedNoMatchingRequestRequestSeenOtherCollector()

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
	if reported["pcap_request_rate_limited"] != 3 {
		t.Fatalf("pcap_request_rate_limited = %d, want 3", reported["pcap_request_rate_limited"])
	}
	if reported["pcap_request_key_expired"] != 2 {
		t.Fatalf("pcap_request_key_expired = %d, want 2", reported["pcap_request_key_expired"])
	}
	if reported["pcap_request_dropped_agent_traffic"] != 1 {
		t.Fatalf("pcap_request_dropped_agent_traffic = %d, want 1", reported["pcap_request_dropped_agent_traffic"])
	}
	if reported["pcap_response_dropped_nginx_traffic"] != 1 {
		t.Fatalf("pcap_response_dropped_nginx_traffic = %d, want 1", reported["pcap_response_dropped_nginx_traffic"])
	}
	if reported["pcap_response_dropped_no_matching_request"] != 2 {
		t.Fatalf("pcap_response_dropped_no_matching_request = %d, want 2", reported["pcap_response_dropped_no_matching_request"])
	}
	if reported["pcap_response_dropped_no_matching_request_rate_limited"] != 1 {
		t.Fatalf("pcap_response_dropped_no_matching_request_rate_limited = %d, want 1", reported["pcap_response_dropped_no_matching_request_rate_limited"])
	}
	if reported["pcap_response_dropped_no_matching_request_active_request_stream"] != 1 {
		t.Fatalf("pcap_response_dropped_no_matching_request_active_request_stream = %d, want 1", reported["pcap_response_dropped_no_matching_request_active_request_stream"])
	}
	if reported["pcap_response_dropped_no_matching_request_response_first"] != 1 {
		t.Fatalf("pcap_response_dropped_no_matching_request_response_first = %d, want 1", reported["pcap_response_dropped_no_matching_request_response_first"])
	}
	if reported["pcap_response_dropped_no_matching_request_request_seen_local_collector"] != 1 {
		t.Fatalf("pcap_response_dropped_no_matching_request_request_seen_local_collector = %d, want 1", reported["pcap_response_dropped_no_matching_request_request_seen_local_collector"])
	}
	if reported["pcap_response_dropped_no_matching_request_request_seen_other_collector"] != 1 {
		t.Fatalf("pcap_response_dropped_no_matching_request_request_seen_other_collector = %d, want 1", reported["pcap_response_dropped_no_matching_request_request_seen_other_collector"])
	}
}
