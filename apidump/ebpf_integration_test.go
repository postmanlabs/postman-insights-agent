package apidump

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/postmanlabs/postman-insights-agent/ebpf/events"
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
	httpsTelemetryWorker(ctx, time.Hour, nil, nil, nil, adapter, nil, reportCount)

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

	httpsTelemetryWorker(ctx, time.Hour, nil, nil, nil, &events.Adapter{}, nil, nil)
}
