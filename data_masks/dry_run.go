// SPDX-License-Identifier: Apache-2.0
//
// Dry-run reporter for --privacy-mode=dry-run.
//
// The single most important Phase 4 deliverable per
// docs/phases/phase-4.md task #7.
//
// Customer story:
//
//   "Run the agent in dry-run mode for 24 hours. Read the resulting
//    redaction reports. If the redaction looks sufficient for your
//    compliance posture, flip the switch to live mode by changing one
//    config value."
//
// Implementation:
//
//   1. Capture + redact normally (the existing redactor pipeline).
//   2. Skip the backend upload (apidump.go gates upload on
//      redactor.PrivacyConfig.UploadEnabled).
//   3. Every reportInterval, write a JSON file containing:
//        - the window's start/end timestamps,
//        - per-rule redaction hit counts (from CoverageCounters),
//        - 5 randomly-selected redacted samples (after redaction, so
//          customers can audit exactly what we would have shipped).
//
// Samples are bounded so a high-traffic workload doesn't pin memory.
// Reservoir sampling (Vitter's Algorithm R) picks a uniformly-random
// subset of the requests scanned in this window.

package data_masks

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DryRunSample is a single redacted request/response pair captured for
// customer audit. The fields mirror the JSON shape committed-to in
// docs/phases/phase-4.md.
type DryRunSample struct {
	Method          string            `json:"method"`
	Path            string            `json:"path"`
	StatusCode      int               `json:"status_code,omitempty"`
	RedactedHeaders map[string]string `json:"redacted_headers,omitempty"`
	RedactedBody    string            `json:"redacted_body,omitempty"`
	CapturedAt      time.Time         `json:"captured_at"`
}

// dryRunReport is the JSON document written per window.
type dryRunReport struct {
	WindowStart      time.Time         `json:"window_start"`
	WindowEnd        time.Time         `json:"window_end"`
	RequestsScanned  uint64            `json:"requests_scanned"`
	Redactions       map[string]uint64 `json:"redactions"`
	BodyTruncations  uint64            `json:"body_truncations"`
	BodiesDropped    uint64            `json:"bodies_dropped"`
	HeadersDropped   uint64            `json:"headers_dropped"`
	Samples          []DryRunSample    `json:"samples"`
	AgentVersion     string            `json:"agent_version,omitempty"`
	PrivacyMode      string            `json:"privacy_mode"`
}

// DryRunReporter accumulates samples and emits periodic JSON reports.
type DryRunReporter struct {
	dir            string
	coverage       *CoverageCounters
	reportInterval time.Duration
	maxSamples     int

	mu             sync.Mutex
	samples        []DryRunSample
	requestsSeen   uint64
	windowStart    time.Time
	lastCoverage   CoverageSnapshot
	closed         bool
	closeCh        chan struct{}
}

// NewDryRunReporter creates a reporter that writes JSON reports to dir.
// dir is created (mode 0755) if it doesn't exist. The reporter retains
// up to 5 randomly-selected samples per window via reservoir sampling.
func NewDryRunReporter(dir string, coverage *CoverageCounters) (*DryRunReporter, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create dry-run dir %q: %w", dir, err)
	}
	return &DryRunReporter{
		dir:            dir,
		coverage:       coverage,
		reportInterval: time.Minute,
		maxSamples:     5,
		windowStart:    time.Now(),
		closeCh:        make(chan struct{}),
	}, nil
}

// Run is the reporter's main loop; call as a goroutine. It blocks until
// stop is closed (or Close is called).
func (r *DryRunReporter) Run(stop <-chan struct{}) {
	ticker := time.NewTicker(r.reportInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			r.flush()
			return
		case <-r.closeCh:
			r.flush()
			return
		case <-ticker.C:
			r.flush()
		}
	}
}

// Close stops the reporter and writes a final report.
func (r *DryRunReporter) Close() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	r.mu.Unlock()
	close(r.closeCh)
}

// AddSample records a (potential) sample via reservoir sampling. Safe to
// call concurrently. The redactor pipeline is expected to call this AFTER
// running redaction so what we write to disk is what the customer would
// have shipped.
func (r *DryRunReporter) AddSample(s DryRunSample) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requestsSeen++
	if len(r.samples) < r.maxSamples {
		r.samples = append(r.samples, s)
		return
	}
	// Reservoir sampling (Algorithm R): replace a random existing sample
	// with probability maxSamples / requestsSeen.
	j := rand.Int63n(int64(r.requestsSeen))
	if j < int64(r.maxSamples) {
		r.samples[j] = s
	}
}

// flush writes the current window to disk and rotates state.
func (r *DryRunReporter) flush() {
	now := time.Now()
	cov := r.coverage.Snapshot()

	r.mu.Lock()
	samples := r.samples
	requestsSeen := r.requestsSeen
	windowStart := r.windowStart
	r.samples = nil
	r.requestsSeen = 0
	r.windowStart = now
	r.mu.Unlock()

	if requestsSeen == 0 && cov.TotalRequestsScanned == r.lastCoverage.TotalRequestsScanned {
		// Idle window \u2014 don't litter disk.
		return
	}

	report := dryRunReport{
		WindowStart:     windowStart,
		WindowEnd:       now,
		RequestsScanned: requestsSeen,
		Redactions:      flattenCoverage(cov, r.lastCoverage),
		BodyTruncations: cov.BodyTruncations - r.lastCoverage.BodyTruncations,
		BodiesDropped:   cov.BodiesDropped - r.lastCoverage.BodiesDropped,
		HeadersDropped:  cov.HeadersDropped - r.lastCoverage.HeadersDropped,
		Samples:         samples,
		PrivacyMode:     string(PrivacyDryRun),
	}
	r.lastCoverage = cov

	filename := filepath.Join(r.dir, fmt.Sprintf("dry-run-%s.json", now.UTC().Format("20060102T150405Z")))
	f, err := os.Create(filename)
	if err != nil {
		// We don't want to crash the agent over a dry-run write failure;
		// log via stderr.
		fmt.Fprintf(os.Stderr, "dry-run reporter: failed to create %s: %v\n", filename, err)
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(&report); err != nil {
		fmt.Fprintf(os.Stderr, "dry-run reporter: failed to encode %s: %v\n", filename, err)
	}
}

// flattenCoverage subtracts the previous snapshot from the current one so
// each report contains the per-window delta, not the cumulative count.
func flattenCoverage(cur, prev CoverageSnapshot) map[string]uint64 {
	out := map[string]uint64{}
	for k, v := range cur.SensitiveKeyHits {
		d := v - prev.SensitiveKeyHits[k]
		if d > 0 {
			out["header."+k] = d
		}
	}
	for k, v := range cur.SensitiveRegexHits {
		d := v - prev.SensitiveRegexHits[k]
		if d > 0 {
			out["regex."+k] = d
		}
	}
	for k, v := range cur.UserRuleHits {
		d := v - prev.UserRuleHits[k]
		if d > 0 {
			out["user."+k] = d
		}
	}
	return out
}
