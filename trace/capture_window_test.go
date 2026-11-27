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

// An allowlist whose patterns are all unusable must capture nothing, not
// everything. matchesAny reads an empty pattern list as "match everything", so
// without the neverMatches sentinel a single missing bracket in a deployment
// config would turn a narrow allowlist into the widest possible capture.
func TestRecordAllPolicyAllInvalidPatternsFailClosed(t *testing.T) {
	// One missing ')' -- a typo of the example the DaemonSet's own error
	// message documents.
	policy := NewRecordAllPolicy(nil, nil, []string{"^/v2/mocks(/|$"})

	assert.True(t, policy.Scoped(), "a supplied allowlist still counts as scoped")
	assert.False(
		t,
		policy.Allows(witnessForHostAndPath("mock.internal", "/anything/at/all"), time.Now()),
		"an unusable allowlist must capture nothing",
	)
	assert.False(
		t,
		policy.Allows(witnessForHostAndPath("mock.internal", "/v2/mocks"), time.Now()),
		"not even the path the operator meant, until the pattern is fixed",
	)
}

// An empty string compiles and matches every input, so it must be rejected
// rather than silently widening the allowlist. This is what a trailing comma in
// a CSV flag or an empty JSON element produces.
func TestRecordAllPolicyEmptyPatternIsIgnored(t *testing.T) {
	policy := NewRecordAllPolicy(nil, nil, []string{"^/v2/mocks(/|$)", ""})

	assert.True(
		t,
		policy.Allows(witnessForHostAndPath("mock.internal", "/v2/mocks"), time.Now()),
		"the valid pattern still applies",
	)
	assert.False(
		t,
		policy.Allows(witnessForHostAndPath("mock.internal", "/v1/users"), time.Now()),
		"the empty pattern must not widen the allowlist to everything",
	)
}

// A witness with no host and no path -- what learn.UnknownHTTPMethodMeta
// produces -- must not slip through an allowlist. `$^` as a never-match
// sentinel matched the empty string, since position 0 of "" is both the start
// and the end of the text, so exactly these witnesses were captured by an
// allowlist that was meant to deny everything.
func TestRecordAllPolicyEmptyHostAndPathAreNotAllowlisted(t *testing.T) {
	unusable := NewRecordAllPolicy(nil, []string{"^mock\\.internal("}, nil)

	assert.False(
		t,
		unusable.Allows(witnessForHostAndPath("", ""), time.Now()),
		"an unusable host allowlist must not admit a witness with no host",
	)

	scoped := NewRecordAllPolicy(nil, []string{"^mock\\.internal$"}, []string{"^/v2/mocks(/|$)"})

	assert.False(
		t,
		scoped.Allows(witnessForHostAndPath("", ""), time.Now()),
		"a witness with no host or path matches neither allowlist",
	)
	assert.False(
		t,
		scoped.Allows(witnessForHostAndPath("mock.internal", ""), time.Now()),
		"an empty path is not inside the path allowlist",
	)
}

// A response seen without its request carries UnknownHTTPMethodMeta: no method,
// host or path. With no allowlist configured matchesAny would admit it, so
// record-all would capture a payload that cannot be shown to be in scope.
func TestRecordAllPolicyRejectsUnattributableWitness(t *testing.T) {
	unscoped := NewRecordAllPolicy(nil, nil, nil)

	assert.True(
		t,
		unscoped.Allows(witnessForHostAndPath("mock.internal", "/v2/mocks"), time.Now()),
		"an unscoped policy still admits an ordinary witness",
	)
	assert.False(
		t,
		unscoped.Allows(witnessForHostAndPath("", ""), time.Now()),
		"but never one with no request metadata at all",
	)
}

// The service owner's grant, served by the back end, is the authority on
// whether successful response bodies may be collected. These tests pin the
// three things that make that safe.
func TestCaptureWindowRemoteGrant(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)

	t.Run("no answer falls back to the local window", func(t *testing.T) {
		// An older back end does not answer the question, and a capture with no
		// service never asks. Neither may turn record-all off for everyone who
		// upgraded the agent first.
		w := NewCaptureWindow(0, 0)

		assert.True(t, w.IsOpen(now), "an unanswered question is not a refusal")

		bounded := NewCaptureWindow(30*time.Minute, 0)
		bounded.start = now

		assert.True(t, bounded.IsOpen(now.Add(10*time.Minute)))
		assert.False(t, bounded.IsOpen(now.Add(31*time.Minute)))
	})

	t.Run("a refusal closes an otherwise open window", func(t *testing.T) {
		w := NewCaptureWindow(0, 0)
		w.SetRemoteGrant(false, now.Add(time.Minute))

		assert.False(t, w.IsOpen(now),
			"the owner said no; no local configuration may widen that")
	})

	t.Run("a grant does not widen a local window... it replaces it", func(t *testing.T) {
		// The grant is the authority, so a service whose owner has switched
		// capture on collects even where the local window has shut. That is the
		// point of moving the decision to the product.
		w := NewCaptureWindow(30*time.Minute, 0)
		w.start = now
		w.SetRemoteGrant(true, now.Add(2*time.Hour))

		assert.True(t, w.IsOpen(now.Add(45*time.Minute)))
	})

	t.Run("a stale answer stops capture rather than assuming it stands", func(t *testing.T) {
		// The crux. The grant expires server-side, so an agent that can no
		// longer ask -- partitioned, key revoked, back end down -- would
		// otherwise keep uploading payloads on an answer from an hour ago.
		w := NewCaptureWindow(0, 0)
		w.SetRemoteGrant(true, now.Add(time.Minute))

		assert.True(t, w.IsOpen(now))
		assert.False(t, w.IsOpen(now.Add(time.Minute)), "exactly at the staleness bound")
		assert.False(t, w.IsOpen(now.Add(time.Hour)))
	})

	t.Run("a stale answer does not fall back to the local window", func(t *testing.T) {
		// Falling back here would reopen capture on a grant nobody has
		// confirmed, which is the failure the staleness bound exists to prevent.
		w := NewCaptureWindow(0, 0)
		w.SetRemoteGrant(true, now.Add(time.Minute))

		assert.False(t, w.IsOpen(now.Add(time.Hour)),
			"an always-open local window must not resurrect an aged-out grant")
	})

	t.Run("a later answer replaces an earlier one", func(t *testing.T) {
		w := NewCaptureWindow(0, 0)

		w.SetRemoteGrant(true, now.Add(time.Hour))
		assert.True(t, w.IsOpen(now))

		w.SetRemoteGrant(false, now.Add(time.Hour))
		assert.False(t, w.IsOpen(now), "switching off takes effect on the next witness")

		w.SetRemoteGrant(true, now.Add(time.Hour))
		assert.True(t, w.IsOpen(now), "and back on again")
	})

	t.Run("nil window tolerates a grant", func(t *testing.T) {
		var w *CaptureWindow

		assert.NotPanics(t, func() { w.SetRemoteGrant(true, now) })
		assert.True(t, w.IsOpen(now))
	})
}
