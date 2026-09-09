package apidump

import (
	"fmt"
	"os"
	"strconv"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/akitasoftware/akita-libs/tags"
	"github.com/postmanlabs/postman-insights-agent/capturestats"
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

// logCaptureDiagnostics reports this session's capture counters. Called on
// each telemetry tick.
//
// The line is prefixed with the client ID and the monitored pod name so it
// can be attributed. That matters because the agent runs as a DaemonSet with
// one apidump session (one apidump.Run() goroutine) per monitored pod inside a
// single OS process (see cmd/internal/kube/daemonset/apidump_process.go), so a
// node's logs interleave several sessions -- and client_id is the only
// pod-level identifier that reaches the back end, since the pod name is sent
// once at startup and then discarded there. Without this prefix there would
// be no way to tell which pod a line belongs to.
//
// The pod name comes from a.traceTags, not a.Args.Tags: in the Kubernetes
// DaemonSet path, tags.XAkitaKubernetesPod only ever reaches the trace tags
// that collectTraceTags merges from DaemonsetArgs.TraceTags (see Run()) --
// Args.Tags is never updated with that merge, so reading it here always
// misses and reports pod=unknown.
func (a *apidump) logCaptureDiagnostics() {
	if a.dumpSummary == nil || !captureDiagnosticsEnabled() {
		return
	}

	pod := a.traceTags[tags.XAkitaKubernetesPod]
	if pod == "" {
		pod = "unknown"
	}

	LogCaptureDiagnostics(
		akid.String(a.ClientID),
		pod,
		akid.String(a.backendSvc),
		a.captureStats,
		a.dumpSummary.PrefilterSummary,
		a.dumpSummary.FilterSummary,
	)
}

// LogCaptureDiagnostics writes the capture counters that we maintain but do
// not send to the back end.
//
// Every counter here sits on a path that can silently lose one half of a
// request/response pair. Because we upload a witness for the request either
// way, that loss surfaces only at the back end, as a missing_status_code
// drop, with no way to tell from there which layer lost it. Printing these
// periodically makes the layer visible in `kubectl logs` for a running
// agent.
//
// PrintWarnings covers some of the same ground, but it only runs when a
// capture ends, which for a long-lived DaemonSet is never.
//
// stats must be the same *capturestats.Stats passed to this session's
// pcap.Collect, trace.NewRateLimit, and trace.NewBackendCollector calls --
// see capturestats.Stats for why a shared, per-session value (rather than a
// package-level counter) is what keeps every number below scoped to the one
// pod this session is monitoring.
//
// prefilter and postfilter are the request/response counts from either side
// of the collector chain's filtering and rate limiting. They are the pair
// that matters most: if prefilter responses roughly match prefilter requests
// but postfilter responses do not, the response reached us and something in
// the chain discarded it. If neither matches, we never parsed the response
// at all.
func LogCaptureDiagnostics(clientID, podName, serviceID string, stats *capturestats.Stats, prefilter, postfilter *trace.PacketCounter) {
	snap := stats.Snapshot()

	printer.Stderr.Infof(
		"Capture diagnostics: client=%s pod=%s service=%s "+
			"kernel[recv=%d drop=%d ifdrop=%d] "+
			"parse[nil_ctx=%d bad_ctx=%d nil_ctx_after=%d zero_ts=%d ts_inverted=%d reassembly_gap_flushed=%d] "+
			"discarded[req=%d resp=%d other=%d] "+
			"chain[filtered_req=%d filtered_resp=%d sampled_out_req=%d sampled_out_resp=%d "+
			"outbound_req=%d outbound_resp=%d resp_no_request=%d] "+
			"resp_no_request_why[rate_limited=%d expired=%d active_stream=%d same_stream=%d "+
			"resp_first=%d local=%d other=%d key_invalid=%d ctx_unavail=%d unknown=%d] "+
			"conn_ctx[entries=%d peak=%d pruned=%d cap_evicted=%d] "+
			"pair[ok=%d req_only=%d resp_only=%d same_dir_merge=%d parse_failed=%d] "+
			"pair_expiry_why[resp_rejected=%d resp_never=%d resp_no_stream=%d resp_no_tracker=%d "+
			"req_rejected=%d req_never=%d req_no_stream=%d req_no_tracker=%d] "+
			"unmatched_stream_idx[pruned=%d cap_evicted=%d] "+
			"rl_tombstones[dropped=%d] "+
			"neg_latency[sub_ms=%d sub_s=%d over_s=%d]%s\n",

		// Identify which apidump session this line came from. A node runs one
		// per monitored pod, so the logs interleave.
		clientID, podName, serviceID,

		// Packets the kernel gave us, and packets it threw away because we could
		// not keep up. A drop in the middle of a response usually costs us the
		// whole response while sparing the request.
		snap.PcapPacketsReceived,
		snap.PcapPacketsDropped,
		snap.PcapPacketsIfDropped,

		// Messages we refused to parse. nil_ctx and bad_ctx are the cases where
		// the first byte carried no TCP sequence number, so we discarded the
		// message rather than parsing it. reassembly_gap_flushed counts TCP
		// streams the reassembler force-flushed because a sequence-number gap
		// sat unfilled past its timeout -- usually the downstream consequence
		// of a kernel packet drop.
		snap.NilAssemblerContext,
		snap.BadAssemblerContextType,
		snap.NilAssemblerContextAfterParse,
		snap.ZeroValuePacketTimestamp,
		snap.LastPacketBeforeFirstPacket,
		snap.ReassemblyGapFlushed,

		// The same nil_ctx/bad_ctx failures, but split by which half we threw
		// away. This is the pair to read for the "response starts in a later
		// reassembly page" theory.
		snap.DiscardedRequests,
		snap.DiscardedResponses,
		snap.DiscardedOther,

		// Traffic-proportional collector-chain drops, then responses we parsed
		// and dropped for want of a matching request. The first six are
		// counters rather than per-message telemetry events precisely because
		// any of them can account for most of the traffic on the interface.
		snap.RequestsFiltered,
		snap.ResponsesFiltered,
		snap.RequestsSampledOut,
		snap.ResponsesSampledOut,
		snap.RequestsDroppedOutbound,
		snap.ResponsesDroppedOutbound,
		snap.ResponsesDroppedNoMatchingRequest,

		// The same total, partitioned by what we knew about the missing
		// request at the moment we dropped the response. The reasons are
		// mutually exclusive and ordered strongest evidence first, so they
		// sum back to resp_no_request above.
		//
		// same_stream is the one to read against resp_first: it means a
		// request *was* admitted on this response's own TCP stream and the
		// keys still disagreed, whereas resp_first means the tracker held no
		// request for the connection at all -- a claim only as good as
		// conn_ctx below, since pruning and capacity eviction both erase the
		// request that would have contradicted it.
		snap.ResponsesDroppedNoMatchingRequestRateLimited,
		snap.ResponsesDroppedNoMatchingRequestExpired,
		snap.ResponsesDroppedNoMatchingRequestActiveRequestStream,
		snap.ResponsesDroppedNoMatchingRequestRequestSeenSameStream,
		snap.ResponsesDroppedNoMatchingRequestResponseFirst,
		snap.ResponsesDroppedNoMatchingRequestRequestSeenLocalCollector,
		snap.ResponsesDroppedNoMatchingRequestRequestSeenOtherCollector,
		snap.ResponsesDroppedNoMatchingRequestContextKeyInvalid,
		snap.ResponsesDroppedNoMatchingRequestContextUnavailable,
		snap.ResponsesDroppedNoMatchingRequestUnknown,

		// Connection-context tracker occupancy and attrition. A nonzero
		// cap_evicted means the tracker was discarding connections
		// arbitrarily to stay under its entry cap, which downgrades every
		// resp_first in the same interval to "we no longer know".
		snap.ConnectionContextEntries,
		snap.ConnectionContextEntriesPeak,
		snap.ConnectionContextPruned,
		snap.ConnectionContextCapacityEvicted,

		// How witnesses left the pair cache, plus parse_failed: a request or
		// response that reached the backend collector -- so it already passed
		// prefilter, filters, rate limiting, and sampling, and postfilter
		// already counted it -- but failed to parse into a witness. That
		// failure is invisible to the prefilter/postfilter comparison, since
		// postfilter counted it before the parse was attempted.
		snap.WitnessesPaired,
		snap.UnpairedRequestsFlushed,
		snap.UnpairedResponsesFlushed,
		snap.SameDirectionMerges,
		snap.WitnessParseFailed,

		// Why the missing half of an expired witness never arrived. Each
		// direction's four counters sum to req_only and resp_only above.
		//
		// resp_rejected is the one to read against the response side's
		// resp_no_request_why[same_stream=...]: both say "a message on this
		// TCP stream was captured and then discarded before it could pair",
		// seen from opposite ends. They will not match exactly -- this is
		// stream-level, and a keep-alive stream carries many exchanges.
		//
		// resp_never covers streams the index dropped as well as companions
		// that truly never arrived, which is what unmatched_stream_idx
		// qualifies.
		snap.PairExpiredResponsePeerRejected,
		snap.PairExpiredResponsePeerNeverObserved,
		snap.PairExpiredResponsePeerStreamUnknown,
		snap.PairExpiredResponsePeerTrackerUnavailable,
		snap.PairExpiredRequestPeerRejected,
		snap.PairExpiredRequestPeerNeverObserved,
		snap.PairExpiredRequestPeerStreamUnknown,
		snap.PairExpiredRequestPeerTrackerUnavailable,

		snap.UnmatchedResponseStreamPruned,
		snap.UnmatchedResponseStreamCapacityEvicted,

		// Rejection tombstones the rate limiter's bounded map could not hold.
		// Nonzero means resp_no_request_why[rate_limited=...] undercounts by
		// this much, with those responses landing in a weaker reason.
		snap.RateLimitTombstonesDropped,

		// Negative processing latency, bucketed by size. Small values can be
		// genuine (a server answering before the request body finished); large
		// ones mean we paired a response with the wrong request.
		snap.NegativeLatencyUnder1ms,
		snap.NegativeLatencyUnder1s,
		snap.NegativeLatencyOver1s,

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
