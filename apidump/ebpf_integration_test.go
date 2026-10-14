package apidump

import (
	"context"
	"sync"
	"testing"
	"time"

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
	httpsTelemetryWorker(ctx, time.Hour, nil, nil, nil, adapter, nil, nil, reportCount)

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

	httpsTelemetryWorker(ctx, time.Hour, nil, nil, nil, &events.Adapter{}, nil, nil, nil)
}

// The Java fields appear on the ebpf-stats line only while Java capture runs,
// so the line is unchanged for everyone else.
func TestHTTPSCaptureStatsStringJava(t *testing.T) {
	s := HTTPSCaptureStats{JavaFrames: 5, JavaEvents: 4, JavaNetnsRejected: 1}
	assert.NotContains(t, s.String(), "java_")

	s.JavaEnabled = true
	assert.Contains(t, s.String(),
		" java_frames=5 java_events=4 java_dropped_ringbuf=0 java_netns_rejected=1 java_malformed=0")
}

// The JVM attach counters appear only where JVMs are attached.
func TestHTTPSCaptureStatsStringJVMs(t *testing.T) {
	s := HTTPSCaptureStats{JVMsSeen: 3}
	assert.NotContains(t, s.String(), "jvms")

	s.JVMAttach = true
	s.JVMsAttached, s.JVMsAgentRunning, s.JVMsSkipped = 1, 1, 1
	assert.Contains(t, s.String(),
		" jvms=3 jvms_attached=1 jvms_agent_running=1 jvms_skipped=1 jvms_attach_failed=0")
}

// The worker reads the JVM attach counters it is given, summing the reasons.
func TestHTTPSTelemetryWorkerJVMStats(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var line string
	tracker := &recordingTracker{onStep: func(step, detail string) {
		if step == "ebpf_capture_stats" {
			line = detail
			cancel()
		}
	}}
	stats := func() (jvm.AttachStats, bool) {
		return jvm.AttachStats{
			Seen: 4, Attached: 1,
			Skipped: map[string]uint64{jvm.SkipOpenJ9: 1, jvm.SkipAttachDisabled: 1},
			Failed:  map[string]uint64{jvm.FailHelper: 1},
		}, true
	}
	httpsTelemetryWorker(ctx, time.Millisecond, nil, nil, nil, nil, stats, tracker, nil)
	assert.Contains(t, line, " jvms=4 jvms_attached=1 jvms_agent_running=0 jvms_skipped=2 jvms_attach_failed=1")
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
