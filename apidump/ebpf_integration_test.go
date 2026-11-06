package apidump

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/akitasoftware/akita-libs/akinet"
	akihttp "github.com/akitasoftware/akita-libs/akinet/http"
	"github.com/akitasoftware/akita-libs/buffer_pool"
	"github.com/postmanlabs/postman-insights-agent/ebpf"
	"github.com/postmanlabs/postman-insights-agent/ebpf/events"
	"github.com/postmanlabs/postman-insights-agent/ebpf/jvm"
	"github.com/postmanlabs/postman-insights-agent/telemetry"
	"github.com/stretchr/testify/assert"
)

// The worker must report once more when its context is cancelled. Reporting
// only on the ticker discarded up to one interval of these counters on every
// shutdown, and a session shorter than one interval reported none of them --
// which is exactly the session where drops matter most.
func TestHTTPSTelemetryWorkerReportsFinalDeltaOnCancel(t *testing.T) {
	var mu sync.Mutex
	reported := map[string]uint64{}
	reportCount := func(event string, count uint64) {
		mu.Lock()
		defer mu.Unlock()
		reported[event] += count
	}

	// Zero-value Adapter: Stats() and Snapshot() only read Go-side fields, so
	// no BPF machinery is needed. These are the two counters the worker
	// reports as telemetry.
	adapter := &events.Adapter{}
	adapter.FlowsDropped = 7
	adapter.H2HPACKDesyncs = 3

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// An interval far longer than the test can run, so only the cancellation
	// branch can possibly report.
	httpsTelemetryWorker(ctx, time.Hour, scopeCapture, httpsStatsSources{adapter: adapter}, nil, reportCount, "")

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, uint64(7), reported["ebpf_flow_dropped"],
		"final flow-drop delta was not reported on cancellation")
	assert.Equal(t, uint64(3), reported["ebpf_h2_hpack_desync"],
		"final HPACK-desync delta was not reported on cancellation")
}

// A nil reportCount is the non-DaemonSet case and must not panic on the
// cancellation path.
func TestHTTPSTelemetryWorkerNilReporterOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	httpsTelemetryWorker(ctx, time.Hour, scopeCapture, httpsStatsSources{adapter: &events.Adapter{}}, nil, nil, "")
}

// The Java fields appear on the ebpf-stats line only while Java capture runs,
// so the line is unchanged for everyone else.
func TestHTTPSCaptureStatsStringJava(t *testing.T) {
	s := HTTPSCaptureStats{JavaFrames: 5, JavaEvents: 4, JavaNetnsRejected: 1}
	assert.NotContains(t, s.String(), "java_")

	s.JavaEnabled = true
	s.JavaAgentsAlive, s.JavaAgentsCapturing = 2, 1
	s.JavaConnUnbound, s.JavaConnHandoffs = 3, 1
	assert.Contains(t, s.String(),
		" java_frames=5 java_events=4 java_dropped_ringbuf=0 java_netns_rejected=1 java_malformed=0"+
			" java_conn_unbound=3 java_conn_handoffs=1 java_agents_alive=2 java_agents_capturing=1")
}

// The JVM attach counters appear only where JVMs are attached.
func TestHTTPSCaptureStatsStringJVMs(t *testing.T) {
	s := HTTPSCaptureStats{JVMsSeen: 3}
	assert.NotContains(t, s.String(), "jvms")

	s.JVMAttach = true
	s.JVMsAttached, s.JVMsAgentRunning, s.JVMsAgentOther, s.JVMsSkipped = 1, 1, 1, 1
	assert.Contains(t, s.String(),
		" jvms=3 jvms_attached=1 jvms_agent_running=1 jvms_agent_other_version=1 jvms_skipped=1 jvms_attach_failed=0")
}

// The node's worker reads the JVM attach counters it is given, summing the
// reasons.
func TestHTTPSTelemetryWorkerJVMStats(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var line string
	tracker := &recordingTracker{onStep: func(step, detail string) {
		if step == "ebpf_node_capture_stats" {
			line = detail
			cancel()
		}
	}}
	stats := func() (jvm.AttachStats, bool) {
		return jvm.AttachStats{
			Seen: 4, Attached: 1, AlreadyRunning: 1, OtherVersion: 1,
			Skipped: map[string]uint64{jvm.SkipOpenJ9: 1, jvm.SkipAttachDisabled: 1},
			Failed:  map[string]uint64{jvm.FailHelper: 1},
		}, true
	}
	httpsTelemetryWorker(ctx, time.Millisecond, scopeNode, httpsStatsSources{jvmStats: stats}, tracker, nil, "")
	assert.Contains(t, line, " jvms=4 jvms_attached=1 jvms_agent_running=1 jvms_agent_other_version=1 jvms_skipped=2 jvms_attach_failed=1")
}

// A DaemonSet logs one ebpf-stats line per pod, which names it, and one for
// the node.
func TestStatsLogLine(t *testing.T) {
	s := HTTPSCaptureStats{MessagesEmitted: 18}
	assert.Equal(t, "ebpf-stats: "+s.String(), statsLogLine(scopeCapture, "", s))
	assert.Equal(t, "ebpf-stats: pod=java-service "+s.format(scopePod), statsLogLine(scopePod, "java-service", s))
	assert.Equal(t, "ebpf-stats: node "+s.format(scopeNode), statsLogLine(scopeNode, "", s))
}

// A pod's line has only what is the pod's own, and the node's only what all
// pods share; a standalone capture's has both.
func TestHTTPSCaptureStatsScopes(t *testing.T) {
	s := HTTPSCaptureStats{JavaEnabled: true, JVMAttach: true}
	keys := func(line string) []string {
		var out []string
		for _, f := range strings.Fields(line) {
			k, _, _ := strings.Cut(f, "=")
			out = append(out, k)
		}
		return out
	}
	assert.Equal(t, []string{"probes", "flows_active", "events", "bytes", "msgs", "dropped_flows", "h2_hpack_desyncs",
		"java_events", "java_agents_alive", "java_agents_capturing"}, keys(s.format(scopePod)))
	assert.Equal(t, []string{"probes", "events", "bytes", "dropped_ringbuf", "read_failures", "cap_bytes", "cpu",
		"java_frames", "java_events", "java_dropped_ringbuf", "java_netns_rejected", "java_malformed",
		"java_conn_unbound", "java_conn_handoffs",
		"jvms", "jvms_attached", "jvms_agent_running", "jvms_agent_other_version", "jvms_skipped", "jvms_attach_failed"},
		keys(s.format(scopeNode)))
	all := keys(s.String())
	for _, k := range append(keys(s.format(scopePod)), keys(s.format(scopeNode))...) {
		assert.Contains(t, all, k)
	}
}

// Two pods on one node report their own probes, events, bytes and messages,
// not the node's: each line is read from the pod's adapter and probes.
func TestReadHTTPSStatsPerPod(t *testing.T) {
	pool, err := buffer_pool.MakeBufferPool(1024*1024, 4096)
	if err != nil {
		t.Fatal(err)
	}
	newAdapter := func() *events.Adapter {
		return events.NewAdapter(akinet.TCPParserFactorySelector{
			akihttp.NewHTTPRequestParserFactory(pool),
			akihttp.NewHTTPResponseParserFactory(pool),
		}, make(chan akinet.ParsedNetworkTraffic, 16))
	}
	feed := func(a *events.Adapter, sslCtx uint64, data string) {
		ev := &events.SSLEvent{PID: 1, TID: 1, SSLCtx: sslCtx, Direction: events.DirEgress,
			LenCaptured: uint32(len(data)), LenTotal: uint32(len(data))}
		copy(ev.Payload[:], data)
		a.Feed(ev, time.Unix(0, 0))
	}
	req := "GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n"

	busy, idle := newAdapter(), newAdapter()
	feed(busy, 0xAAAA, req)
	feed(busy, 0xBBBB, req)
	feed(busy, 1<<63|5, req) // a Java connection's

	busyStats := readHTTPSStats(scopePod, httpsStatsSources{adapter: busy, probes: func() int { return 2 }})
	idleStats := readHTTPSStats(scopePod, httpsStatsSources{adapter: idle, probes: func() int { return 0 }})
	assert.Equal(t, 2, busyStats.ProbesAttached)
	assert.Equal(t, uint64(2), busyStats.EventsEmitted)
	assert.Equal(t, uint64(2*len(req)), busyStats.BytesCaptured)
	assert.Equal(t, uint64(1), busyStats.JavaEvents)
	assert.Equal(t, uint64(3), busyStats.MessagesEmitted)
	assert.Equal(t, HTTPSCaptureStats{}, idleStats)
}

// recordingTracker passes WorkflowStep to onStep; nothing else may be called.
type recordingTracker struct {
	telemetry.Tracker
	onStep func(step, detail string)
}

func (r *recordingTracker) WorkflowStep(step, detail string) { r.onStep(step, detail) }

// prepareHTTPSCapture decides whether HTTPS capture runs, before the pcap
// filters are final: pcap leaves out the TLS port only when it does.
func TestPrepareHTTPSCapture(t *testing.T) {
	var a Args
	assert.Nil(t, prepareHTTPSCapture(&a), "HTTPS capture off")

	// The DaemonSet chose the pod's libraries, and the NodeCollector loaded
	// the programs for the node.
	a.HTTPS.Enabled = true
	a.HTTPS.Libraries = ebpf.Libraries{Java: true}
	a.HTTPS.NodeCollector = &ebpf.NodeCollector{}
	h := prepareHTTPSCapture(&a)
	if assert.NotNil(t, h) {
		assert.Equal(t, ebpf.Libraries{Java: true}, h.libraries)
		assert.Nil(t, h.standalone)
	}
}

// pcap leaves out the TLS port only when HTTPS capture runs.
func TestHTTPSCapturePcapFilters(t *testing.T) {
	filters := map[string]string{"eth0": "tcp"}
	var off *httpsCapture
	assert.Equal(t, filters, off.pcapFilters(filters, 443), "HTTPS capture not running")
	on := &httpsCapture{libraries: ebpf.Libraries{OpenSSL: true}}
	assert.Equal(t, filters, on.pcapFilters(filters, 0), "no port to leave out")
	assert.Equal(t, excludePortFromBPF(filters, 443), on.pcapFilters(filters, 443))
	assert.NotEqual(t, filters, on.pcapFilters(filters, 443))
}
