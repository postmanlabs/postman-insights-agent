package trace

import (
	"regexp"
	"time"

	pb "github.com/akitasoftware/akita-ir/go/api_spec"
	"github.com/postmanlabs/postman-insights-agent/printer"
)

// CaptureWindow bounds *when* record-all captures payloads.
//
// Without a window, --record-all sends the body of every successful response
// for as long as the agent runs, which is the volume objection raised against
// it: successful bodies are far larger and far more numerous than error bodies.
// A window turns that into a bounded sample -- "capture for 30 minutes, then
// stop" -- which is what makes the flag deployable beyond a local cluster.
//
// The window is derived from arithmetic on a fixed start time rather than a
// timer, so IsOpen is lock-free and allocation-free. It is consulted once per
// witness on the upload path, so that matters.
type CaptureWindow struct {
	start time.Time

	// How long the window stays open. Zero means "no window": always open, the
	// pre-window --record-all behavior.
	duration time.Duration

	// How often the window reopens. Zero means one-shot: the window opens at
	// `start` and never reopens.
	period time.Duration
}

// NewCaptureWindow builds a window that is open for `duration` out of every
// `period`, counting from now.
//
// duration == 0 yields an always-open window, preserving the behavior of
// --record-all before windows existed. period == 0 yields a one-shot window.
// A duration at or above the period is also always open -- there is no gap
// left to close in -- and says so, because the operator who wrote
// `--capture-window 2h --capture-every 1h` meant something else.
func NewCaptureWindow(duration, period time.Duration) *CaptureWindow {
	if duration < 0 {
		printer.Stderr.Warningf("Negative capture window %v; treating as unset (always open).\n", duration)
		duration = 0
	}
	if period < 0 {
		printer.Stderr.Warningf("Negative capture period %v; treating as one-shot.\n", period)
		period = 0
	}

	if duration > 0 && period > 0 && duration >= period {
		printer.Stderr.Warningf(
			"Capture window %v is not shorter than the capture period %v, so the window never closes. "+
				"Payload capture will stay on continuously.\n",
			duration, period,
		)
	}

	return &CaptureWindow{
		start:    time.Now(),
		duration: duration,
		period:   period,
	}
}

// IsOpen reports whether payload capture is permitted at `now`.
func (w *CaptureWindow) IsOpen(now time.Time) bool {
	if w == nil || w.duration == 0 {
		// No window configured: always open.
		return true
	}

	elapsed := now.Sub(w.start)
	if elapsed < 0 {
		// Clock moved backwards. Fall back to closed rather than guessing: an
		// unexpectedly open window uploads payloads, an unexpectedly closed one
		// only loses a sample.
		return false
	}

	if w.period == 0 {
		// One-shot.
		return elapsed < w.duration
	}

	if w.duration >= w.period {
		return true
	}

	return elapsed%w.period < w.duration
}

// Describe renders the window for startup logging.
func (w *CaptureWindow) Describe() string {
	switch {
	case w == nil || w.duration == 0:
		return "continuously (no capture window set)"
	case w.period == 0:
		return "once, for " + w.duration.String() + " from agent start"
	default:
		return "for " + w.duration.String() + " out of every " + w.period.String()
	}
}

// RecordAllPolicy decides whether a given witness is eligible for record-all
// payload capture: the right time (CaptureWindow) and the right endpoint (host
// and path allowlists).
//
// The allowlists exist so that turning record-all on for one service cannot
// capture successful bodies from anything else sharing the capture. An agent
// watching a network interface sees every service on that interface, so
// "capture 2xx payloads for the mock service" has to mean the mock service's
// endpoints specifically, not whatever else happens to be on the wire.
//
// A nil *RecordAllPolicy means record-all is off.
type RecordAllPolicy struct {
	window *CaptureWindow

	// Empty means "any host". Matched against the witness's HTTP host.
	hosts []*regexp.Regexp

	// Empty means "any path". Matched against the witness's path.
	paths []*regexp.Regexp
}

// NewRecordAllPolicy compiles the host and path allowlists and attaches the
// window. Invalid patterns are reported and dropped rather than fatal: losing
// one pattern narrows capture, which is the safe direction.
func NewRecordAllPolicy(window *CaptureWindow, hostPatterns, pathPatterns []string) *RecordAllPolicy {
	return &RecordAllPolicy{
		window: window,
		hosts:  compilePatterns(hostPatterns, "host"),
		paths:  compilePatterns(pathPatterns, "path"),
	}
}

// neverMatches stands in for an allowlist whose patterns were all unusable. An
// empty pattern list means "match everything" (see matchesAny), so returning one
// for a list the operator did supply would turn a typo into the widest possible
// capture -- the opposite of what they asked for.
var neverMatches = regexp.MustCompile(`$^`)

func compilePatterns(patterns []string, kind string) []*regexp.Regexp {
	if len(patterns) == 0 {
		return nil
	}

	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		// An empty pattern compiles happily and matches every string, so it
		// would silently widen the allowlist to everything. It is never what
		// someone means; it is a trailing comma or an empty JSON element.
		if p == "" {
			printer.Stderr.Errorf(
				"Ignoring empty record-all %s pattern: an empty pattern matches everything.\n",
				kind,
			)
			continue
		}

		re, err := regexp.Compile(p)
		if err != nil {
			printer.Stderr.Errorf(
				"Ignoring invalid record-all %s pattern %q: %v. Payloads will NOT be captured for it.\n",
				kind, p, err,
			)
			continue
		}
		compiled = append(compiled, re)
	}

	// Patterns were supplied and none survived: fail closed. Capturing nothing
	// is recoverable by fixing the pattern; capturing everything is not.
	if len(compiled) == 0 {
		printer.Stderr.Errorf(
			"No usable record-all %s patterns: record-all will capture no payloads until one is valid.\n",
			kind,
		)

		return []*regexp.Regexp{neverMatches}
	}

	return compiled
}

// Allows reports whether this witness may have its payload captured under
// record-all.
func (p *RecordAllPolicy) Allows(witness *pb.Witness, now time.Time) bool {
	if p == nil {
		return false
	}

	if !p.window.IsOpen(now) {
		return false
	}

	httpMeta := witness.GetMethod().GetMeta().GetHttp()
	if httpMeta == nil {
		return false
	}

	if !matchesAny(p.hosts, httpMeta.GetHost()) {
		return false
	}

	// The agent has only the concrete request path here: PathTemplate is set
	// from req.URL.Path in learn/parse_http.go, and templating happens in the
	// back end. Patterns therefore have to tolerate concrete ids -- use
	// `^/v2/mocks(/|$)` rather than `^/v2/mocks/\{id\}$`.
	return matchesAny(p.paths, httpMeta.GetPathTemplate())
}

// matchesAny reports whether value matches any pattern, treating an empty
// pattern list as "match everything".
func matchesAny(patterns []*regexp.Regexp, value string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, re := range patterns {
		if re.MatchString(value) {
			return true
		}
	}
	return false
}

// Scoped reports whether this policy restricts capture to specific endpoints,
// so startup can warn when record-all is enabled wide open.
func (p *RecordAllPolicy) Scoped() bool {
	return p != nil && (len(p.hosts) > 0 || len(p.paths) > 0)
}
