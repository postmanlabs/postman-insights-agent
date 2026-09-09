package apidump

import (
	"sync"
	"testing"

	"github.com/akitasoftware/akita-libs/client_telemetry"
	"github.com/akitasoftware/go-utils/optionals"
	"github.com/postmanlabs/postman-insights-agent/capturestats"
	"github.com/postmanlabs/postman-insights-agent/trace"
)

// Covers the read side of the eBPF metric holders: the worker reports them
// while another goroutine writes the same counters, which is the steady state
// once the eBPF chain is running.
//
// What this does NOT cover: the field-publication ordering in Run. Run must
// assign a.ebpfCaptureStats and the two HTTPS counters before it starts the
// worker, because the worker reads them every 15s; assigning them in the eBPF
// setup block instead is an unsynchronized write racing that read. This test
// constructs apidump with the fields already set, so moving those assignments
// back after startTelemetryWorker would not fail it. Catching that needs a
// test that drives Run end to end with HTTPS enabled.
func TestReportCaptureMetricsReadsEBPFMetricsUnderRace(t *testing.T) {
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
		// Published the way Run does it: before anything reads them.
		ebpfCaptureStats: capturestats.New(),
		dumpSummary: &Summary{
			PrefilterSummary:      trace.NewPacketCounter(),
			FilterSummary:         trace.NewPacketCounter(),
			HTTPSPrefilterSummary: trace.NewPacketCounter(),
			HTTPSSummary:          trace.NewPacketCounter(),
		},
		successTelemetry: &trace.SuccessTelemetry{Channel: make(chan struct{})},
	}

	stopTelemetry := a.startTelemetryWorker()

	// Stand in for the eBPF collector chain writing counters while the worker
	// is already running.
	var writers sync.WaitGroup
	writers.Add(1)
	go func() {
		defer writers.Done()
		for i := 0; i < 100; i++ {
			a.dumpSummary.HTTPSPrefilterSummary.Update(client_telemetry.PacketCounts{HTTPSRequests: 1})
			a.dumpSummary.HTTPSSummary.Update(client_telemetry.PacketCounts{HTTPSRequests: 1})
			a.ebpfCaptureStats.IncrWitnessesPaired()
		}
	}()
	writers.Wait()

	stopTelemetry()

	mu.Lock()
	defer mu.Unlock()
	if reported["ebpf_http_request_prefilter"] != 100 {
		t.Fatalf("ebpf_http_request_prefilter = %d, want 100", reported["ebpf_http_request_prefilter"])
	}
	if reported["ebpf_witness_paired"] != 100 {
		t.Fatalf("ebpf_witness_paired = %d, want 100", reported["ebpf_witness_paired"])
	}
}

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
	a.captureStats.IncrRequestsFiltered()
	a.captureStats.IncrResponsesFiltered()
	a.captureStats.IncrRequestsSampledOut()
	a.captureStats.IncrResponsesSampledOut()
	a.captureStats.IncrRequestsDroppedOutbound()
	a.captureStats.IncrResponsesDroppedOutbound()
	a.captureStats.IncrRequestsDroppedAgentTraffic()
	a.captureStats.IncrResponsesDroppedNginxTraffic()
	a.captureStats.IncrResponsesDroppedNoMatchingRequest()
	a.captureStats.IncrResponsesDroppedNoMatchingRequest()
	a.captureStats.IncrResponsesDroppedNoMatchingRequestRateLimited()
	a.captureStats.IncrResponsesDroppedNoMatchingRequestActiveRequestStream()
	a.captureStats.IncrResponsesDroppedNoMatchingRequestResponseFirst()
	a.captureStats.IncrResponsesDroppedNoMatchingRequestRequestSeenLocalCollector()
	a.captureStats.IncrResponsesDroppedNoMatchingRequestRequestSeenOtherCollector()
	a.captureStats.IncrResponsesDroppedNoMatchingRequestRequestSeenSameStream()
	a.captureStats.IncrResponsesDroppedNoMatchingRequestContextKeyInvalid()
	a.captureStats.IncrResponsesDroppedNoMatchingRequestContextUnavailable()
	a.captureStats.AddConnectionContextPruned(4)
	a.captureStats.AddConnectionContextCapacityEvicted(3)
	a.captureStats.AddConnectionContextOccupancy(7)
	a.captureStats.AddConnectionContextOccupancy(5)
	a.captureStats.AddUnmatchedResponseStreamPruned(6)
	a.captureStats.AddUnmatchedResponseStreamCapacityEvicted(2)

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
	for _, event := range []string{
		"pcap_request_filtered", "pcap_response_filtered",
		"pcap_request_sampled_out", "pcap_response_sampled_out",
		"pcap_request_dropped_outbound", "pcap_response_dropped_outbound",
	} {
		if reported[event] != 1 {
			t.Fatalf("%s = %d, want 1", event, reported[event])
		}
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
	if reported["pcap_response_dropped_no_matching_request_request_seen_same_stream"] != 1 {
		t.Fatalf("pcap_response_dropped_no_matching_request_request_seen_same_stream = %d, want 1", reported["pcap_response_dropped_no_matching_request_request_seen_same_stream"])
	}
	if reported["pcap_response_dropped_no_matching_request_context_key_invalid"] != 1 {
		t.Fatalf("pcap_response_dropped_no_matching_request_context_key_invalid = %d, want 1", reported["pcap_response_dropped_no_matching_request_context_key_invalid"])
	}
	if reported["pcap_response_dropped_no_matching_request_context_unavailable"] != 1 {
		t.Fatalf("pcap_response_dropped_no_matching_request_context_unavailable = %d, want 1", reported["pcap_response_dropped_no_matching_request_context_unavailable"])
	}
	if reported["pcap_connection_context_pruned"] != 4 {
		t.Fatalf("pcap_connection_context_pruned = %d, want 4", reported["pcap_connection_context_pruned"])
	}
	if reported["pcap_connection_context_capacity_evicted"] != 3 {
		t.Fatalf("pcap_connection_context_capacity_evicted = %d, want 3", reported["pcap_connection_context_capacity_evicted"])
	}
	// Occupancy went 7 then 5, so the peak delta reports 7 -- not the last
	// observed size, and not their sum.
	if reported["pcap_connection_context_entries_peak"] != 7 {
		t.Fatalf("pcap_connection_context_entries_peak = %d, want 7", reported["pcap_connection_context_entries_peak"])
	}
	if reported["pcap_unmatched_response_stream_pruned"] != 6 {
		t.Fatalf("pcap_unmatched_response_stream_pruned = %d, want 6", reported["pcap_unmatched_response_stream_pruned"])
	}
	if reported["pcap_unmatched_response_stream_capacity_evicted"] != 2 {
		t.Fatalf("pcap_unmatched_response_stream_capacity_evicted = %d, want 2", reported["pcap_unmatched_response_stream_capacity_evicted"])
	}
}
