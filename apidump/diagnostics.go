package apidump

import (
	"fmt"
	"os"
	"strconv"
	"sync/atomic"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/akitasoftware/akita-libs/tags"
	"github.com/postmanlabs/postman-insights-agent/pcap"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/postmanlabs/postman-insights-agent/trace"
)

// Set POSTMAN_INSIGHTS_AGENT_CAPTURE_DIAGNOSTICS=false to suppress the capture
// diagnostics line. It is on by default: one line per telemetry interval, which
// defaults to five minutes, so twelve lines an hour per monitored pod.
const captureDiagnosticsEnvVar = "POSTMAN_INSIGHTS_AGENT_CAPTURE_DIAGNOSTICS"

func captureDiagnosticsEnabled() bool {
	v, present := os.LookupEnv(captureDiagnosticsEnvVar)
	if !present {
		return true
	}
	enabled, err := strconv.ParseBool(v)
	if err != nil {
		printer.Warningf("Could not parse %s value %q, defaulting to enabled: %v\n",
			captureDiagnosticsEnvVar, v, err)
		return true
	}
	return enabled
}

// logCaptureDiagnostics reports this session's capture counters. Called on each
// telemetry tick.
//
// The line is prefixed with the client ID and the monitored pod name so it can
// be attributed. That matters because the agent runs as a DaemonSet with one
// apidump process per monitored pod, so a node's logs interleave several
// processes, and because client_id is the only pod-level identifier that reaches
// the back end -- the pod name is sent once at startup and then discarded there.
// Without this prefix there is no way to tell which pod a counter belongs to.
func (a *apidump) logCaptureDiagnostics() {
	if a.dumpSummary == nil || !captureDiagnosticsEnabled() {
		return
	}

	pod := a.Args.Tags[tags.XAkitaKubernetesPod]
	if pod == "" {
		pod = "unknown"
	}

	LogCaptureDiagnostics(
		akid.String(a.ClientID),
		pod,
		akid.String(a.backendSvc),
		a.dumpSummary.PrefilterSummary,
		a.dumpSummary.FilterSummary,
	)
}

// LogCaptureDiagnostics writes the capture counters that we maintain but do not
// send to the back end.
//
// Every counter here sits on a path that can silently lose one half of a
// request/response pair. Because we upload a witness for the request either
// way, that loss surfaces only at the back end, as a missing_status_code drop,
// with no way to tell from there which layer lost it. Printing these
// periodically makes the layer visible in `kubectl logs` for a running agent.
//
// PrintWarnings covers some of the same ground, but it only runs when a capture
// ends, which for a long-lived DaemonSet is never.
//
// prefilter and postfilter are the request/response counts from either side of
// the collector chain's filtering and rate limiting. They are the pair that
// matters most: if prefilter responses roughly match prefilter requests but
// postfilter responses do not, the response reached us and something in the
// chain discarded it. If neither matches, we never parsed the response at all.
func LogCaptureDiagnostics(clientID, podName, serviceID string, prefilter, postfilter *trace.PacketCounter) {
	printer.Stderr.Infof(
		"Capture diagnostics: client=%s pod=%s service=%s "+
			"kernel[recv=%d drop=%d ifdrop=%d] "+
			"parse[nil_ctx=%d bad_ctx=%d nil_ctx_after=%d zero_ts=%d ts_inverted=%d] "+
			"discarded[req=%d resp=%d other=%d] "+
			"chain[resp_no_request=%d] "+
			"pair[ok=%d req_only=%d resp_only=%d same_dir_merge=%d] "+
			"neg_latency[sub_ms=%d sub_s=%d over_s=%d]%s\n",

		// Identify which apidump process this line came from. A node runs one
		// per monitored pod, so the logs interleave.
		clientID, podName, serviceID,

		// Packets the kernel gave us, and packets it threw away because we could
		// not keep up. A drop in the middle of a response usually costs us the
		// whole response while sparing the request.
		atomic.LoadUint64(&pcap.CountPcapPacketsReceived),
		atomic.LoadUint64(&pcap.CountPcapPacketsDropped),
		atomic.LoadUint64(&pcap.CountPcapPacketsIfDropped),

		// Messages we refused to parse. nil_ctx and bad_ctx are the cases where
		// the first byte carried no TCP sequence number, so we discarded the
		// message rather than parsing it.
		atomic.LoadUint64(&pcap.CountNilAssemblerContext),
		atomic.LoadUint64(&pcap.CountBadAssemblerContextType),
		atomic.LoadUint64(&pcap.CountNilAssemblerContextAfterParse),
		atomic.LoadUint64(&pcap.CountZeroValuePacketTimestamp),
		atomic.LoadUint64(&pcap.CountLastPacketBeforeFirstPacket),

		// The same failures as nil_ctx and bad_ctx, but split by which half we
		// threw away. This is the pair to read for the "response starts in a
		// later reassembly page" theory.
		atomic.LoadUint64(&pcap.CountDiscardedRequests),
		atomic.LoadUint64(&pcap.CountDiscardedResponses),
		atomic.LoadUint64(&pcap.CountDiscardedOther),

		// Responses we parsed and then dropped for want of a matching request.
		atomic.LoadUint64(&trace.CountResponsesDroppedNoMatchingRequest),

		// How witnesses left the pair cache.
		atomic.LoadUint64(&trace.CountWitnessesPaired),
		atomic.LoadUint64(&trace.CountUnpairedRequestsFlushed),
		atomic.LoadUint64(&trace.CountUnpairedResponsesFlushed),
		atomic.LoadUint64(&trace.CountSameDirectionMerges),

		// Negative processing latency, bucketed by size. Small values can be
		// genuine (a server answering before the request body finished); large
		// ones mean we paired a response with the wrong request.
		atomic.LoadUint64(&trace.CountNegativeLatencyUnder1ms),
		atomic.LoadUint64(&trace.CountNegativeLatencyUnder1s),
		atomic.LoadUint64(&trace.CountNegativeLatencyOver1s),

		formatFilterCounts(prefilter, postfilter),
	)
}

// formatFilterCounts renders the request and response counts from both ends of
// the collector chain, so the gap between them attributes response loss to the
// chain rather than to parsing.
func formatFilterCounts(prefilter, postfilter *trace.PacketCounter) string {
	if prefilter == nil || postfilter == nil {
		return ""
	}

	pre := prefilter.Total()
	post := postfilter.Total()
	return fmt.Sprintf(
		" prefilter[req=%d resp=%d] postfilter[req=%d resp=%d]",
		pre.HTTPRequests+pre.HTTPSRequests,
		pre.HTTPResponses+pre.HTTPSResponses,
		post.HTTPRequests+post.HTTPSRequests,
		post.HTTPResponses+post.HTTPSResponses,
	)
}
