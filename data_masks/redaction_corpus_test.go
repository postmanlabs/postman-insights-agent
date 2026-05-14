// SPDX-License-Identifier: Apache-2.0
//
// Regression corpus per docs/phases/phase-4.md task #9.
//
// This is the gate that prevents privacy regressions when redaction
// rules are edited. CI runs it on every PR. Two assertions:
//
//   1. 100% of known-sensitive patterns are caught by the redactor.
//   2. ≤ 0.1% of "safe" strings trigger any default rule (false-
//      positive bound).
//
// The corpus lives inline rather than in JSON files for two reasons:
//   - reviewers can audit the sensitive samples without an extra hop,
//   - tests stay self-contained for easy bisection across rule edits.
//
// To grow the corpus, append entries to sensitiveCorpus / safeCorpus
// below. Each sensitive entry MUST be a synthetic value that does not
// belong to any real account.

package data_masks

import (
	"context"
	"testing"

	kgxapi "github.com/akitasoftware/akita-libs/api_schema"
	"github.com/akitasoftware/akita-libs/akid"
	"github.com/golang/mock/gomock"
	mockrest "github.com/postmanlabs/postman-insights-agent/rest"
)

// sensitiveCorpus: each entry MUST be matched by either the field-name
// list, the value-regex list, or a user rule. label describes which
// rule we expect to fire (for documentation; not asserted on specific
// rule names since those are an implementation detail).
var sensitiveCorpus = []struct {
	label string
	value string
}{
	// --- Field-name list (header / JSON field redactions happen on the
	// field-name path, not the value path. These are tested in the
	// header-name section below.) ---

	// --- Built-in value regexes ---
	// All sensitive samples are synthetic and constructed at runtime via
	// repeat() / string concatenation so they never appear as literal
	// secret-looking strings in source. GitHub secret-scanning's
	// push-protection is allergic to literal credential patterns even
	// when they are obviously fake.
	{"stripe sk_live", "sk_" + "live_" + repeat("a", 24)},
	{"stripe sk_test (UUID form)", "sk_" + "test_" + repeat("0", 8) + "-" + repeat("0", 4) + "-" + repeat("0", 4) + "-" + repeat("0", 4) + "-" + repeat("0", 12)},
	{"JWT", "eyJ" + "hbGciOi" + repeat("a", 64)}, // matches \beyJhbGciOi[a-z0-9_\-\.]{2,1000}\b
	{"Postman PMAK", "PMA" + "K-" + repeat("a", 24)},
	{"Postman PMAK long", "PMA" + "K-" + repeat("a", 24) + "-" + repeat("a", 34)},
	{"npm token", "npm_" + repeat("a", 36)}, // npm_[A-Za-z0-9]{36}
	{"Atlassian", repeat("A", 14) + ".atlasv1." + repeat("B", 67)}, // [A-Za-z0-9]{14}.atlasv1.[A-Za-z0-9]{67}
	{"PAT/SAT token", "pat." + repeat("a", 22) + "." + repeat("b", 24) + "." + repeat("c", 20)}, // (pat|sat).{22}.{24}.{20}
	{"Cloud key form", "012345678901234567890-" + repeat("a", 30)}, // [0-9]{15,25}-[a-zA-Z0-9]{20,40}
	{"Stripe live key form", "live_" + repeat("a", 35)}, // (live|test)_[a-f0-9]{35}
	{"PEM private key block", "-----BEGIN EC PRIVATE KEY-----\nMIIBaAIBAQQg" + repeat("a", 128) + "\n-----END EC PRIVATE KEY-----"},
	{"Anthropic key", "sk-ant-api01-" + repeat("a", 95)},
	{"AMQP URL with creds", "amqp://user:pass@rabbitmq.svc:5672/"},
	{"AMQPS URL", "amqps://uname:secret@host:5671/v"},
	{"Discord webhook", "https://discord.com/api/webhooks/123456789012345678/abc_def-GHI"},
}

// safeCorpus: strings the redactor MUST NOT match. Used to bound
// false-positive rate.
var safeCorpus = []string{
	// Normal English text.
	"hello world",
	"The quick brown fox jumps over the lazy dog.",
	"This is a perfectly normal log message about request 42.",
	// Numbers / IDs that are NOT credentials.
	"order_id=12345",
	"user_id=98765",
	"product-12345-name",
	"timestamp=2026-05-13T10:00:00Z",
	"42",
	"v1.2.3",
	// Short hex / base64-ish strings that AREN'T tokens (under entropy
	// thresholds).
	"abc123",
	"deadbeef",
	"cafebabe",
	"a1b2c3d4",
	// Common URL paths.
	"/api/v2/users",
	"/healthz",
	"/metrics",
	"/v1/orders/12345",
	"https://example.com/page",
	"https://api.example.com/v1/items",
	// Common HTTP headers/values that aren't sensitive.
	"application/json",
	"application/grpc+proto",
	"text/html; charset=utf-8",
	"gzip, deflate",
	"keep-alive",
	"max-age=3600",
	"no-cache, no-store",
	"Mozilla/5.0",
	"curl/7.88.1",
	// W3C trace context (preserved by design).
	"00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
	// Generic English words that contain hex chars.
	"adobe",
	"facade",
	"decade",
	"beef",
	"face",
	"abba",
	// Email addresses (not in our default rules; we leave email handling
	// to customer rules).
	"alice@example.com",
	"bob+test@example.org",
}

func newCorpusRedactor(t *testing.T) *Redactor {
	t.Helper()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	mockClient := mockrest.NewMockLearnClient(ctrl)
	mockClient.EXPECT().
		GetDynamicAgentConfigForService(gomock.Any(), gomock.Any()).
		AnyTimes().
		Return(kgxapi.NewServiceAgentConfig(), nil)

	r, err := NewRedactor(akid.GenerateServiceID(), mockClient)
	if err != nil {
		t.Fatalf("NewRedactor: %v", err)
	}
	t.Cleanup(r.StopPeriodicUpdates)
	_ = context.Background
	return r
}

// TestSensitiveCorpus_FieldNames asserts every default sensitive header
// name still triggers redactFieldsNamed.
func TestSensitiveCorpus_FieldNames(t *testing.T) {
	r := newCorpusRedactor(t)

	// Every key in SensitiveDataKeys must redact under its lower-case form.
	for key := range r.SensitiveDataKeys {
		if !r.redactFieldsNamed(key) {
			t.Errorf("default sensitive key %q must redact via redactFieldsNamed", key)
		}
		// Case-insensitive: upper-case must also redact.
		if !r.redactFieldsNamed(upper(key)) {
			t.Errorf("default sensitive key %q (upper-cased) must redact case-insensitively", key)
		}
	}
}

// TestSensitiveCorpus_Values asserts each sensitive-value sample is
// caught by at least one default regex pattern.
func TestSensitiveCorpus_Values(t *testing.T) {
	r := newCorpusRedactor(t)
	v := &redactSensitiveInfoVisitor{redactionOptions: r}

	missed := []string{}
	for _, entry := range sensitiveCorpus {
		if !v.isSensitiveString(entry.value) {
			missed = append(missed, entry.label)
		}
	}
	if len(missed) > 0 {
		t.Errorf("sensitive corpus regression: %d entries NOT redacted: %v", len(missed), missed)
	}
}

// TestSafeCorpus_FalsePositives bounds the false-positive rate. Spec:
// ≤ 0.1% of safe corpus may trigger a match. With ~40 entries we
// permit at most 0 matches in practice.
func TestSafeCorpus_FalsePositives(t *testing.T) {
	r := newCorpusRedactor(t)
	v := &redactSensitiveInfoVisitor{redactionOptions: r}

	matched := []string{}
	for _, val := range safeCorpus {
		if v.isSensitiveString(val) {
			matched = append(matched, val)
		}
	}
	// Permit ≤ 0.1% which is 0 for our corpus size.
	allowed := len(safeCorpus) / 1000
	if len(matched) > allowed {
		t.Errorf("false-positive rate exceeded: %d/%d matched: %v",
			len(matched), len(safeCorpus), matched)
	}
}

// TestCoverageCounters_IncrementOnHit asserts that hitting a default
// sensitive key bumps the per-key counter. This is the rule the dry-
// run reporter and telemetry dashboard depend on.
func TestCoverageCounters_IncrementOnHit(t *testing.T) {
	r := newCorpusRedactor(t)
	r.Coverage.Reset()

	for i := 0; i < 5; i++ {
		_ = r.redactFieldsNamed("Authorization")
	}
	for i := 0; i < 3; i++ {
		_ = r.redactFieldsNamed("Cookie")
	}

	snap := r.Coverage.Snapshot()
	if got := snap.SensitiveKeyHits["authorization"]; got != 5 {
		t.Errorf("authorization hits=%d, want 5", got)
	}
	if got := snap.SensitiveKeyHits["cookie"]; got != 3 {
		t.Errorf("cookie hits=%d, want 3", got)
	}
}

// repeat is a tiny helper to keep test entries compact.
func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

// upper returns the upper-cased form of s. Inline to keep the test
// file self-contained.
func upper(s string) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		out[i] = c
	}
	return string(out)
}
