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
	a.reportTelemetryCount(source+"_response_dropped_no_matching_request_response_first", counterDelta(currentStats.ResponsesDroppedNoMatchingRequestResponseFirst, previousStats.ResponsesDroppedNoMatchingRequestResponseFirst))
	a.reportTelemetryCount(source+"_response_dropped_no_matching_request_request_seen_local_collector", counterDelta(currentStats.ResponsesDroppedNoMatchingRequestRequestSeenLocalCollector, previousStats.ResponsesDroppedNoMatchingRequestRequestSeenLocalCollector))
	a.reportTelemetryCount(source+"_response_dropped_no_matching_request_request_seen_other_collector", counterDelta(currentStats.ResponsesDroppedNoMatchingRequestRequestSeenOtherCollector, previousStats.ResponsesDroppedNoMatchingRequestRequestSeenOtherCollector))
	a.reportTelemetryCount(source+"_response_dropped_no_matching_request_unknown", counterDelta(currentStats.ResponsesDroppedNoMatchingRequestUnknown, previousStats.ResponsesDroppedNoMatchingRequestUnknown))
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
