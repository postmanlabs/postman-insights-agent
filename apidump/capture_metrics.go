package apidump

import (
	"github.com/akitasoftware/akita-libs/client_telemetry"
	"github.com/postmanlabs/postman-insights-agent/capturestats"
)

// captureMetricsSnapshot records cumulative session values at the last
// telemetry tick. The DaemonSet accepts interval deltas, so this keeps
// high-volume paired/message counts off the capture path.
type captureMetricsSnapshot struct {
	pcapStats capturestats.Snapshot
	ebpfStats capturestats.Snapshot

	pcapPrefilter, pcapPostfilter client_telemetry.PacketCounts
	ebpfPrefilter, ebpfPostfilter client_telemetry.PacketCounts
}

func (a *apidump) reportCaptureMetrics(previous *captureMetricsSnapshot) {
	if a.DaemonsetArgs.IsNone() || a.dumpSummary == nil {
		return
	}

	current := captureMetricsSnapshot{
		pcapStats:      a.captureStats.Snapshot(),
		pcapPrefilter:  a.dumpSummary.PrefilterSummary.Total(),
		pcapPostfilter: a.dumpSummary.FilterSummary.Total(),
	}
	if a.ebpfCaptureStats != nil {
		current.ebpfStats = a.ebpfCaptureStats.Snapshot()
	}
	if a.dumpSummary.HTTPSPrefilterSummary != nil {
		current.ebpfPrefilter = a.dumpSummary.HTTPSPrefilterSummary.Total()
	}
	if a.dumpSummary.HTTPSSummary != nil {
		current.ebpfPostfilter = a.dumpSummary.HTTPSSummary.Total()
	}

	a.reportSourceFunnel("pcap", current.pcapStats, previous.pcapStats, current.pcapPrefilter, previous.pcapPrefilter, current.pcapPostfilter, previous.pcapPostfilter)
	a.reportSourceFunnel("ebpf", current.ebpfStats, previous.ebpfStats, current.ebpfPrefilter, previous.ebpfPrefilter, current.ebpfPostfilter, previous.ebpfPostfilter)
	*previous = current
}

func (a *apidump) reportSourceFunnel(source string, currentStats, previousStats capturestats.Snapshot, currentPrefilter, previousPrefilter, currentPostfilter, previousPostfilter client_telemetry.PacketCounts) {
	a.reportTelemetryCount(source+"_http_request_prefilter", counterDelta(httpRequests(currentPrefilter), httpRequests(previousPrefilter)))
	a.reportTelemetryCount(source+"_http_response_prefilter", counterDelta(httpResponses(currentPrefilter), httpResponses(previousPrefilter)))
	a.reportTelemetryCount(source+"_http_request_postfilter", counterDelta(httpRequests(currentPostfilter), httpRequests(previousPostfilter)))
	a.reportTelemetryCount(source+"_http_response_postfilter", counterDelta(httpResponses(currentPostfilter), httpResponses(previousPostfilter)))
	a.reportTelemetryCount(source+"_witness_paired", counterDelta(currentStats.WitnessesPaired, previousStats.WitnessesPaired))
	a.reportTelemetryCount(source+"_request_rate_limited", counterDelta(currentStats.RequestsRateLimited, previousStats.RequestsRateLimited))
	a.reportTelemetryCount(source+"_request_key_expired", counterDelta(currentStats.RequestKeysExpired, previousStats.RequestKeysExpired))
	a.reportTelemetryCount(source+"_request_dropped_agent_traffic", counterDelta(currentStats.RequestsDroppedAgentTraffic, previousStats.RequestsDroppedAgentTraffic))
	a.reportTelemetryCount(source+"_response_dropped_agent_traffic", counterDelta(currentStats.ResponsesDroppedAgentTraffic, previousStats.ResponsesDroppedAgentTraffic))
	a.reportTelemetryCount(source+"_request_dropped_nginx_traffic", counterDelta(currentStats.RequestsDroppedNginxTraffic, previousStats.RequestsDroppedNginxTraffic))
	a.reportTelemetryCount(source+"_response_dropped_nginx_traffic", counterDelta(currentStats.ResponsesDroppedNginxTraffic, previousStats.ResponsesDroppedNginxTraffic))
	a.reportTelemetryCount(source+"_response_dropped_no_matching_request", counterDelta(currentStats.ResponsesDroppedNoMatchingRequest, previousStats.ResponsesDroppedNoMatchingRequest))
	a.reportTelemetryCount(source+"_response_dropped_no_matching_request_rate_limited", counterDelta(currentStats.ResponsesDroppedNoMatchingRequestRateLimited, previousStats.ResponsesDroppedNoMatchingRequestRateLimited))
	a.reportTelemetryCount(source+"_response_dropped_no_matching_request_expired", counterDelta(currentStats.ResponsesDroppedNoMatchingRequestExpired, previousStats.ResponsesDroppedNoMatchingRequestExpired))
	a.reportTelemetryCount(source+"_response_dropped_no_matching_request_active_request_stream", counterDelta(currentStats.ResponsesDroppedNoMatchingRequestActiveRequestStream, previousStats.ResponsesDroppedNoMatchingRequestActiveRequestStream))
	a.reportTelemetryCount(source+"_response_dropped_no_matching_request_request_seen_same_stream", counterDelta(currentStats.ResponsesDroppedNoMatchingRequestRequestSeenSameStream, previousStats.ResponsesDroppedNoMatchingRequestRequestSeenSameStream))
	a.reportTelemetryCount(source+"_response_dropped_no_matching_request_response_first", counterDelta(currentStats.ResponsesDroppedNoMatchingRequestResponseFirst, previousStats.ResponsesDroppedNoMatchingRequestResponseFirst))
	a.reportTelemetryCount(source+"_response_dropped_no_matching_request_request_seen_local_collector", counterDelta(currentStats.ResponsesDroppedNoMatchingRequestRequestSeenLocalCollector, previousStats.ResponsesDroppedNoMatchingRequestRequestSeenLocalCollector))
	a.reportTelemetryCount(source+"_response_dropped_no_matching_request_request_seen_other_collector", counterDelta(currentStats.ResponsesDroppedNoMatchingRequestRequestSeenOtherCollector, previousStats.ResponsesDroppedNoMatchingRequestRequestSeenOtherCollector))
	a.reportTelemetryCount(source+"_response_dropped_no_matching_request_context_key_invalid", counterDelta(currentStats.ResponsesDroppedNoMatchingRequestContextKeyInvalid, previousStats.ResponsesDroppedNoMatchingRequestContextKeyInvalid))
	a.reportTelemetryCount(source+"_response_dropped_no_matching_request_context_unavailable", counterDelta(currentStats.ResponsesDroppedNoMatchingRequestContextUnavailable, previousStats.ResponsesDroppedNoMatchingRequestContextUnavailable))
	a.reportTelemetryCount(source+"_response_dropped_no_matching_request_unknown", counterDelta(currentStats.ResponsesDroppedNoMatchingRequestUnknown, previousStats.ResponsesDroppedNoMatchingRequestUnknown))

	// Health of the tracker behind the response_first and request_seen_*
	// reasons above. These qualify those reasons rather than partitioning any
	// drop count, so they are deliberately not part of the
	// response_dropped_no_matching_request identity.
	a.reportTelemetryCount(source+"_connection_context_pruned", counterDelta(currentStats.ConnectionContextPruned, previousStats.ConnectionContextPruned))
	a.reportTelemetryCount(source+"_connection_context_capacity_evicted", counterDelta(currentStats.ConnectionContextCapacityEvicted, previousStats.ConnectionContextCapacityEvicted))
	// Delta of a running maximum, so summing this event over any range yields
	// the tracker's peak occupancy over that range -- see
	// capturestats.AddConnectionContextOccupancy for why the live gauge
	// itself cannot be shipped through a summed-count pipeline.
	a.reportTelemetryCount(source+"_connection_context_entries_peak", counterDelta(currentStats.ConnectionContextEntriesPeak, previousStats.ConnectionContextEntriesPeak))

	// Attrition of the stream-keyed index behind the pair-expiry peer_rejected
	// reason. Named apart from the connection-context counters above because
	// they track different populations; a loss here turns a peer_rejected into
	// a peer_never_observed.
	a.reportTelemetryCount(source+"_unmatched_response_stream_pruned", counterDelta(currentStats.UnmatchedResponseStreamPruned, previousStats.UnmatchedResponseStreamPruned))
	a.reportTelemetryCount(source+"_unmatched_response_stream_capacity_evicted", counterDelta(currentStats.UnmatchedResponseStreamCapacityEvicted, previousStats.UnmatchedResponseStreamCapacityEvicted))
}

func httpRequests(counts client_telemetry.PacketCounts) uint64 {
	return uint64(counts.HTTPRequests + counts.HTTPSRequests)
}

func httpResponses(counts client_telemetry.PacketCounts) uint64 {
	return uint64(counts.HTTPResponses + counts.HTTPSResponses)
}

func counterDelta(current, previous uint64) uint64 {
	if current < previous {
		// Session counters should be monotonic, but treating an unexpected reset
		// as a new baseline prevents an unsigned underflow from corrupting data.
		return current
	}
	return current - previous
}
