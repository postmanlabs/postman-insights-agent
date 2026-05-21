// SPDX-License-Identifier: Apache-2.0

package data_masks

import (
	"testing"
)

// Tests for the per-namespace PrivacyMode override path (Phase 4c).
//
// These tests exercise the redactor's lookup table (PerNamespacePrivacyConfig)
// + lookupConfigForNamespace helper directly. End-to-end tests that feed
// real *pb.Method values through RedactSensitiveDataForNamespace live in
// redaction_test.go; the goal here is to pin down the precedence rules
// without coupling to the protobuf-walker surface.

func TestLookupConfigForNamespace_EmptyMapFallsBackToDefault(t *testing.T) {
	defaultCfg := PrivacyStrict.Config()
	r := &Redactor{
		PrivacyConfig:             defaultCfg,
		PerNamespacePrivacyConfig: nil,
	}
	got := r.lookupConfigForNamespace("any-namespace")
	if got.Mode != PrivacyStrict {
		t.Errorf("nil map: lookup returned %v, want default %v", got.Mode, PrivacyStrict)
	}
}

func TestLookupConfigForNamespace_EmptyNamespaceFallsBackToDefault(t *testing.T) {
	r := &Redactor{
		PrivacyConfig: PrivacyStandard.Config(),
		PerNamespacePrivacyConfig: map[string]PrivacyModeConfig{
			"team-a": PrivacyStrict.Config(),
		},
	}
	// netInterface = "" reaches the redactor when the witness came from
	// the pcap path (no PID encoded). Must use the default.
	got := r.lookupConfigForNamespace("")
	if got.Mode != PrivacyStandard {
		t.Errorf("empty namespace: got %v, want default %v", got.Mode, PrivacyStandard)
	}
}

func TestLookupConfigForNamespace_KnownNamespaceUsesOverride(t *testing.T) {
	r := &Redactor{
		PrivacyConfig: PrivacyStandard.Config(),
		PerNamespacePrivacyConfig: map[string]PrivacyModeConfig{
			"team-payments": PrivacyStrict.Config(),
			"team-staging":  PrivacyDryRun.Config(),
		},
	}
	if r.lookupConfigForNamespace("team-payments").Mode != PrivacyStrict {
		t.Error("team-payments did not get its strict override")
	}
	if r.lookupConfigForNamespace("team-staging").Mode != PrivacyDryRun {
		t.Error("team-staging did not get its dry-run override")
	}
}

func TestLookupConfigForNamespace_UnknownNamespaceUsesDefault(t *testing.T) {
	r := &Redactor{
		PrivacyConfig: PrivacyStandard.Config(),
		PerNamespacePrivacyConfig: map[string]PrivacyModeConfig{
			"team-payments": PrivacyStrict.Config(),
		},
	}
	// team-c is NOT in the override map. Must fall back to default.
	got := r.lookupConfigForNamespace("team-c")
	if got.Mode != PrivacyStandard {
		t.Errorf("unknown namespace 'team-c': got %v, want default %v",
			got.Mode, PrivacyStandard)
	}
}

func TestLookupConfigForNamespace_OverrideIndependentPerCall(t *testing.T) {
	// Critical invariant: lookup must NOT mutate the redactor's default
	// PrivacyConfig as a side effect of returning an override. Otherwise
	// a request from "team-payments" would silently flip the redactor to
	// strict mode for subsequent requests from any namespace.
	r := &Redactor{
		PrivacyConfig: PrivacyStandard.Config(),
		PerNamespacePrivacyConfig: map[string]PrivacyModeConfig{
			"team-payments": PrivacyStrict.Config(),
		},
	}
	// Hit the override first
	_ = r.lookupConfigForNamespace("team-payments")
	// Then hit an unknown namespace — must still get default
	got := r.lookupConfigForNamespace("team-other")
	if got.Mode != PrivacyStandard {
		t.Errorf("lookup leaked override into redactor state: got %v",
			got.Mode)
	}
	// And the default field itself must be untouched
	if r.PrivacyConfig.Mode != PrivacyStandard {
		t.Errorf("Redactor.PrivacyConfig.Mode mutated to %v", r.PrivacyConfig.Mode)
	}
}

func TestRedactSensitiveDataForNamespace_RoutesByNamespace(t *testing.T) {
	// Smoke test that the public entry point routes to the right config.
	// We don't run a full protobuf-walker here; we just verify that the
	// internal lookup matches what we'd expect via the helper. End-to-end
	// behaviour (DropBodies actually zeroing protobuf primitives) is
	// covered by the existing redaction_test.go corpus.
	r := &Redactor{
		PrivacyConfig: PrivacyStandard.Config(),
		PerNamespacePrivacyConfig: map[string]PrivacyModeConfig{
			"sensitive-ns": PrivacyStrict.Config(),
		},
	}
	if r.lookupConfigForNamespace("sensitive-ns").DropBodies != true {
		t.Error("sensitive-ns override should produce DropBodies=true")
	}
	if r.lookupConfigForNamespace("normal-ns").DropBodies != false {
		t.Error("normal-ns (no override) should produce DropBodies=false")
	}
}
