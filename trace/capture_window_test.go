package trace

import (
	"testing"
	"time"

	pb "github.com/akitasoftware/akita-ir/go/api_spec"
	"github.com/stretchr/testify/assert"
)

// alwaysRecordAll is an unscoped, always-open record-all policy: the behavior
// of --record-all before capture windows and allowlists existed. Shared with
// util_test.go and backend_collector_test.go.
func alwaysRecordAll() *RecordAllPolicy {
	return NewRecordAllPolicy(NewCaptureWindow(0, 0), nil, nil)
}

// recordAllFromBool maps a table test's boolean to a policy, so existing tables
// keep reading as "record-all on/off".
func recordAllFromBool(on bool) *RecordAllPolicy {
	if !on {
		return nil
	}
	return alwaysRecordAll()
}

func TestCaptureWindowIsOpen(t *testing.T) {
	start := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

	testCases := []struct {
		name     string
		duration time.Duration
		period   time.Duration
		at       time.Duration // offset from start
		expected bool
	}{
		// No window configured: the pre-window --record-all behavior.
		{"unset window is always open at start", 0, 0, 0, true},
		{"unset window is always open much later", 0, 0, 100 * time.Hour, true},

		// One-shot.
		{"one-shot open at start", 15 * time.Minute, 0, 0, true},
		{"one-shot open inside", 15 * time.Minute, 0, 14 * time.Minute, true},
		{"one-shot closed at the boundary", 15 * time.Minute, 0, 15 * time.Minute, false},
		{"one-shot closed after", 15 * time.Minute, 0, time.Hour, false},
		{"one-shot does not reopen a day later", 15 * time.Minute, 0, 24 * time.Hour, false},

		// Periodic: 30m out of every 24h.
		{"periodic open at start", 30 * time.Minute, 24 * time.Hour, 0, true},
		{"periodic open inside first window", 30 * time.Minute, 24 * time.Hour, 29 * time.Minute, true},
		{"periodic closed after first window", 30 * time.Minute, 24 * time.Hour, 31 * time.Minute, false},
		{"periodic closed mid-period", 30 * time.Minute, 24 * time.Hour, 12 * time.Hour, false},
		{"periodic reopens next period", 30 * time.Minute, 24 * time.Hour, 24 * time.Hour, true},
		{"periodic open inside second window", 30 * time.Minute, 24 * time.Hour, 24*time.Hour + 10*time.Minute, true},
		{"periodic closed after second window", 30 * time.Minute, 24 * time.Hour, 24*time.Hour + 45*time.Minute, false},

		// Degenerate: a window at least as long as the period never closes.
		{"duration equal to period is always open", time.Hour, time.Hour, 90 * time.Minute, true},
		{"duration longer than period is always open", 2 * time.Hour, time.Hour, 90 * time.Minute, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w := &CaptureWindow{start: start, duration: tc.duration, period: tc.period}
			assert.Equal(t, tc.expected, w.IsOpen(start.Add(tc.at)))
		})
	}
}

// A nil window is open, so a policy built without one behaves like plain
// record-all rather than silently capturing nothing.
func TestCaptureWindowNilIsOpen(t *testing.T) {
	var w *CaptureWindow
	assert.True(t, w.IsOpen(time.Now()))
}

// A backwards clock jump closes the window rather than guessing: an
// unexpectedly open window uploads payloads, a closed one only loses a sample.
func TestCaptureWindowClosedBeforeStart(t *testing.T) {
	start := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	w := &CaptureWindow{start: start, duration: 15 * time.Minute}
	assert.False(t, w.IsOpen(start.Add(-time.Minute)))
}

func witnessForHostAndPath(host, path string) *pb.Witness {
	return &pb.Witness{
		Method: &pb.Method{
			Meta: &pb.MethodMeta{
				Meta: &pb.MethodMeta_Http{
					Http: &pb.HTTPMethodMeta{
						Method:       "GET",
						Host:         host,
						PathTemplate: path,
					},
				},
			},
		},
	}
}

func TestRecordAllPolicyAllowlists(t *testing.T) {
	// The allowlist the mock-service PoC runs with: the product CRUD surface,
	// excluding the support (/x, /support), webhook (/synapse) and health paths
	// that share the same service.
	mockCRUDPaths := []string{`^/v2/(mocks|code-mocks|mock-servers|mock-starts|simulation-starts)(/|$)`, `^/mocks(/|$)`}

	testCases := []struct {
		name     string
		hosts    []string
		paths    []string
		host     string
		path     string
		expected bool
	}{
		{"no allowlist admits anything", nil, nil, "anything.internal", "/whatever", true},

		{"path allowlist admits mock CRUD collection", nil, mockCRUDPaths, "mock.internal", "/v2/mocks", true},
		{"path allowlist admits mock CRUD item", nil, mockCRUDPaths, "mock.internal", "/v2/mocks/abc-123", true},
		{"path allowlist admits nested state", nil, mockCRUDPaths, "mock.internal", "/v2/mocks/abc-123/state/k", true},
		{"path allowlist admits legacy mocks", nil, mockCRUDPaths, "mock.internal", "/mocks/abc-123/endpoints", true},
		{"path allowlist admits code mocks", nil, mockCRUDPaths, "mock.internal", "/v2/code-mocks/xyz/generate", true},

		// The point of the allowlist: these share the service but are not CRUD.
		{"path allowlist rejects support dashboard", nil, mockCRUDPaths, "mock.internal", "/x/mocks/abc-123", false},
		{"path allowlist rejects support surface", nil, mockCRUDPaths, "mock.internal", "/support/mocks/abc", false},
		{"path allowlist rejects synapse webhooks", nil, mockCRUDPaths, "mock.internal", "/synapse/workspace/move", false},
		{"path allowlist rejects health", nil, mockCRUDPaths, "mock.internal", "/livez", false},
		// Prefix-adjacent paths must not sneak past the (/|$) anchor.
		{"path allowlist rejects prefix collision", nil, mockCRUDPaths, "mock.internal", "/v2/mocksomething", false},

		{"host allowlist admits matching host", []string{`^mock\.internal$`}, nil, "mock.internal", "/v2/mocks", true},
		{"host allowlist rejects other host", []string{`^mock\.internal$`}, nil, "billing.internal", "/v2/mocks", false},

		// Both lists must pass.
		{"both match", []string{`^mock\.internal$`}, mockCRUDPaths, "mock.internal", "/v2/mocks", true},
		{"host matches but path does not", []string{`^mock\.internal$`}, mockCRUDPaths, "mock.internal", "/livez", false},
		{"path matches but host does not", []string{`^mock\.internal$`}, mockCRUDPaths, "other.internal", "/v2/mocks", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p := NewRecordAllPolicy(NewCaptureWindow(0, 0), tc.hosts, tc.paths)
			got := p.Allows(witnessForHostAndPath(tc.host, tc.path), time.Now())
			assert.Equal(t, tc.expected, got)
		})
	}
}

// A nil policy means record-all is off and must never admit a witness.
func TestRecordAllPolicyNilRejects(t *testing.T) {
	var p *RecordAllPolicy
	assert.False(t, p.Allows(witnessForHostAndPath("mock.internal", "/v2/mocks"), time.Now()))
}

// A closed window rejects even a witness both allowlists admit -- the window is
// what bounds upload volume, so it has to win.
func TestRecordAllPolicyClosedWindowRejectsAllowlistedWitness(t *testing.T) {
	start := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	p := &RecordAllPolicy{
		window: &CaptureWindow{start: start, duration: 15 * time.Minute},
	}

	w := witnessForHostAndPath("mock.internal", "/v2/mocks")
	assert.True(t, p.Allows(w, start.Add(time.Minute)), "inside the window")
	assert.False(t, p.Allows(w, start.Add(time.Hour)), "after the window")
}

// An unparseable pattern is dropped rather than fatal, and dropping it must
// narrow capture, not widen it.
func TestRecordAllPolicyInvalidPatternNarrows(t *testing.T) {
	p := NewRecordAllPolicy(NewCaptureWindow(0, 0), nil, []string{`^/v2/mocks(/|$)`, `([`})

	assert.True(t, p.Allows(witnessForHostAndPath("h", "/v2/mocks/1"), time.Now()))
	assert.False(t, p.Allows(witnessForHostAndPath("h", "/livez"), time.Now()))
	assert.True(t, p.Scoped(), "one bad pattern must not leave the policy unscoped")
}

// Non-HTTP witnesses carry no host or path, so there is nothing to match an
// allowlist against; they must not be admitted.
func TestRecordAllPolicyRejectsNonHTTP(t *testing.T) {
	p := NewRecordAllPolicy(NewCaptureWindow(0, 0), nil, nil)
	assert.False(t, p.Allows(&pb.Witness{Method: &pb.Method{}}, time.Now()))
}
