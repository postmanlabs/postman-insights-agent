// SPDX-License-Identifier: Apache-2.0
//
// Redaction-coverage counters.
//
// Each redaction rule (sensitive-key match, regex match, body truncation,
// user-supplied rule) increments a counter. The agent's telemetry pipeline
// emits a snapshot every hour and Postman Insights surfaces it in the
// per-service redaction dashboard.
//
// Customers' security teams use these counters as proof that the redactor
// is firing on real data. Zero hits on `header.authorization` over a
// busy hour is a smoke signal that something is wrong with the redactor
// or the rule, not that no requests carried Authorization.
//
// Design intent:
//   - Counters are increment-only and atomic. No locking on the hot path.
//   - Snapshot() copies values out under a single mutex acquisition.
//   - Reset() is offered for tests; production never calls it.

package data_masks

import (
	"sync"
	"sync/atomic"
)

// CoverageCounters tracks how often each redaction rule fires.
type CoverageCounters struct {
	// Per-rule counters. Keys are STABLE telemetry names; never rename
	// without coordinating with the backend dashboard.
	mu             sync.Mutex
	sensitiveKey   map[string]*uint64 // key -> hits (e.g. "authorization")
	sensitiveRegex map[string]*uint64 // rule label -> hits
	userRule       map[string]*uint64 // customer-supplied label -> hits

	bodyTruncations atomic.Uint64
	requestsScanned atomic.Uint64
	bodiesDropped   atomic.Uint64 // PrivacyStrict body drops
	headersDropped  atomic.Uint64 // PrivacyStrict allowlist evictions
}

// NewCoverageCounters returns a zero-initialised counter set.
func NewCoverageCounters() *CoverageCounters {
	return &CoverageCounters{
		sensitiveKey:   make(map[string]*uint64),
		sensitiveRegex: make(map[string]*uint64),
		userRule:       make(map[string]*uint64),
	}
}

// IncSensitiveKey bumps the per-key counter. Safe to call concurrently.
func (c *CoverageCounters) IncSensitiveKey(name string) {
	if c == nil {
		return
	}
	c.inc(c.sensitiveKey, name, &c.mu)
}

// IncSensitiveRegex bumps the per-regex counter. Label is the regex's
// stable identifier, NOT the regex source (which can change).
func (c *CoverageCounters) IncSensitiveRegex(label string) {
	if c == nil {
		return
	}
	c.inc(c.sensitiveRegex, label, &c.mu)
}

// IncUserRule bumps the per-user-rule counter.
func (c *CoverageCounters) IncUserRule(label string) {
	if c == nil {
		return
	}
	c.inc(c.userRule, label, &c.mu)
}

func (c *CoverageCounters) inc(m map[string]*uint64, k string, mu *sync.Mutex) {
	// Fast path: counter already exists.
	mu.Lock()
	p, ok := m[k]
	if !ok {
		p = new(uint64)
		m[k] = p
	}
	mu.Unlock()
	atomic.AddUint64(p, 1)
}

// IncBodyTruncation records a body that was truncated at the size cap.
func (c *CoverageCounters) IncBodyTruncation() {
	if c == nil {
		return
	}
	c.bodyTruncations.Add(1)
}

// IncRequestScanned records a request the redactor inspected (whether or
// not anything fired).
func (c *CoverageCounters) IncRequestScanned() {
	if c == nil {
		return
	}
	c.requestsScanned.Add(1)
}

// IncBodyDropped records a body removed by PrivacyStrict.
func (c *CoverageCounters) IncBodyDropped() {
	if c == nil {
		return
	}
	c.bodiesDropped.Add(1)
}

// IncHeaderDropped records a header removed by PrivacyStrict's allowlist.
func (c *CoverageCounters) IncHeaderDropped() {
	if c == nil {
		return
	}
	c.headersDropped.Add(1)
}

// CoverageSnapshot is the immutable copy of all counters at one moment.
type CoverageSnapshot struct {
	SensitiveKeyHits     map[string]uint64
	SensitiveRegexHits   map[string]uint64
	UserRuleHits         map[string]uint64
	BodyTruncations      uint64
	BodiesDropped        uint64
	HeadersDropped       uint64
	TotalRequestsScanned uint64
}

// Snapshot returns a deep copy of the current counters. Safe to call from
// the telemetry worker without coordinating with redactor goroutines.
func (c *CoverageCounters) Snapshot() CoverageSnapshot {
	if c == nil {
		return CoverageSnapshot{}
	}
	c.mu.Lock()
	keys := copyAtomicMap(c.sensitiveKey)
	regexes := copyAtomicMap(c.sensitiveRegex)
	users := copyAtomicMap(c.userRule)
	c.mu.Unlock()
	return CoverageSnapshot{
		SensitiveKeyHits:     keys,
		SensitiveRegexHits:   regexes,
		UserRuleHits:         users,
		BodyTruncations:      c.bodyTruncations.Load(),
		BodiesDropped:        c.bodiesDropped.Load(),
		HeadersDropped:       c.headersDropped.Load(),
		TotalRequestsScanned: c.requestsScanned.Load(),
	}
}

func copyAtomicMap(src map[string]*uint64) map[string]uint64 {
	out := make(map[string]uint64, len(src))
	for k, v := range src {
		out[k] = atomic.LoadUint64(v)
	}
	return out
}

// Reset zeros all counters. Tests only.
func (c *CoverageCounters) Reset() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.sensitiveKey = make(map[string]*uint64)
	c.sensitiveRegex = make(map[string]*uint64)
	c.userRule = make(map[string]*uint64)
	c.mu.Unlock()
	c.bodyTruncations.Store(0)
	c.requestsScanned.Store(0)
	c.bodiesDropped.Store(0)
	c.headersDropped.Store(0)
}
