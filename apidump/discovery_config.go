// SPDX-License-Identifier: Apache-2.0

package apidump

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v2"
)

// ValidPrivacyModes is the set of strings accepted in
// `discovery.namespaces[].privacyMode`. Kept here (not in data_masks) so
// the YAML loader has zero dependency on the redactor package — we
// validate by string match, then the data_masks layer parses for real
// when the override is consumed.
var ValidPrivacyModes = map[string]struct{}{
	"standard": {},
	"strict":   {},
	"dry-run":  {},
	"dryrun":   {}, // accepted alias; matches data_masks.ParsePrivacyMode
}

// DiscoveryConfig is the YAML form of HTTPS-capture opt-in controls,
// closing design doc §7.3 gap #4 (per-namespace `decrypt: true|false`).
//
// The CLI flag `--https-target-namespaces` already provides the same
// allow-list semantics; this YAML form exists so config-driven deployments
// (Helm values, GitOps repos, daemonset manifests) can express the policy
// declaratively without long comma-separated CLI strings.
//
// Schema:
//
//   discovery:
//     namespaces:
//       - name: app-prod
//         decrypt: true
//       - name: payments-prod
//         decrypt: false     # eBPF probes do not attach; HTTPS stays opaque
//       - name: legacy
//         decrypt: true
//
// Semantics (v1):
//
//   - Any namespace listed with `decrypt: true` is added to the
//     allow-list.
//   - Any namespace listed with `decrypt: false` is explicitly excluded
//     from the allow-list (and from any pre-existing CLI flag list — the
//     YAML can revoke a CLI inclusion).
//   - Namespaces NOT mentioned in the YAML are treated by the existing
//     CLI flag if any; otherwise they default to "no filter" (capture
//     allowed) when no other filtering is set.
//
// Future extensions (not v1): per-namespace `privacyMode`, per-workload
// (Deployment/StatefulSet/etc.) selectors, label-based matching. The
// current shape stays forward-compatible with all of those.
type DiscoveryConfig struct {
	Discovery DiscoverySection `yaml:"discovery"`
}

// DiscoverySection holds the namespaces block. A separate struct keeps the
// top-level YAML shape extensible (we can add `discovery.workloads:` or
// `discovery.defaults:` later without breaking existing files).
type DiscoverySection struct {
	Namespaces []DiscoveryNamespace `yaml:"namespaces"`
}

// DiscoveryNamespace is one entry in `discovery.namespaces`.
//
// PrivacyMode is a POINTER so we can distinguish three distinct states:
//
//   nil   → not specified — fall back to the global --privacy-mode flag
//   ""   → specified-but-empty — rejected at parse time (likely a typo)
//   "std" → specified — override the global flag for THIS namespace
//
// Without the pointer we couldn't tell "user omitted the field" from "user
// wrote `privacyMode: \"\"` thinking it would reset to default" — the
// latter is almost certainly a mistake we should catch.
type DiscoveryNamespace struct {
	Name        string  `yaml:"name"`
	Decrypt     bool    `yaml:"decrypt"`
	PrivacyMode *string `yaml:"privacyMode,omitempty"`
}

// PrivacyModeOverride returns (mode, ok) where ok=false means "no override;
// caller should use its global default". Use this instead of touching
// PrivacyMode directly so the pointer-vs-empty discipline stays in one place.
func (n DiscoveryNamespace) PrivacyModeOverride() (string, bool) {
	if n.PrivacyMode == nil {
		return "", false
	}
	return *n.PrivacyMode, true
}

// LoadDiscoveryConfig reads and validates a YAML config file. It returns
// a non-nil error if:
//   - the file can't be read,
//   - the YAML can't be parsed,
//   - any namespace entry is missing `name`,
//   - the same namespace name appears more than once.
//
// An empty or absent `discovery.namespaces` is valid and produces an empty
// result; the caller is expected to fall back to whatever CLI flag is set.
func LoadDiscoveryConfig(path string) (*DiscoveryConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read discovery config %q: %w", path, err)
	}

	var cfg DiscoveryConfig
	if err := yaml.UnmarshalStrict(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse discovery config %q: %w", path, err)
	}

	seen := make(map[string]struct{}, len(cfg.Discovery.Namespaces))
	for i, ns := range cfg.Discovery.Namespaces {
		if ns.Name == "" {
			return nil, fmt.Errorf("discovery config %q: namespaces[%d].name is required", path, i)
		}
		if _, dup := seen[ns.Name]; dup {
			return nil, fmt.Errorf("discovery config %q: duplicate namespace %q", path, ns.Name)
		}
		seen[ns.Name] = struct{}{}

		// Validate privacyMode if specified. Empty-string-but-present is a
		// likely typo (user typed `privacyMode: ` then nothing); refuse
		// rather than silently treat as "no override".
		if mode, ok := ns.PrivacyModeOverride(); ok {
			normalised := strings.ToLower(strings.TrimSpace(mode))
			if normalised == "" {
				return nil, fmt.Errorf(
					"discovery config %q: namespace %q has empty privacyMode; "+
						"omit the field entirely to inherit the global --privacy-mode flag",
					path, ns.Name)
			}
			if _, ok := ValidPrivacyModes[normalised]; !ok {
				return nil, fmt.Errorf(
					"discovery config %q: namespace %q has unknown privacyMode %q "+
						"(want one of: standard, strict, dry-run)",
					path, ns.Name, mode)
			}
		}
	}

	return &cfg, nil
}

// MergeTargetNamespaces applies the discovery config to an existing CLI
// allow-list. The result is a deduplicated list of namespaces that the
// eBPF capture layer should attach probes to.
//
// Rules:
//   - Start with `cliList` (whatever --https-target-namespaces produced).
//   - Add every YAML namespace with `decrypt: true` that isn't already in
//     the list.
//   - Remove every YAML namespace with `decrypt: false` (the YAML can
//     veto a CLI inclusion — the design's intent is that the config file
//     is the source of truth when both are set).
//
// The returned slice is sorted-stable: CLI-provided entries keep their
// original order, then any YAML-added entries appear in YAML order. This
// keeps log output predictable for operators.
func (c *DiscoveryConfig) MergeTargetNamespaces(cliList []string) []string {
	if c == nil {
		return cliList
	}

	// Build a "decrypt:false" set and a "decrypt:true" set in YAML order.
	veto := make(map[string]struct{}, len(c.Discovery.Namespaces))
	yamlAdd := make([]string, 0, len(c.Discovery.Namespaces))
	for _, ns := range c.Discovery.Namespaces {
		if !ns.Decrypt {
			veto[ns.Name] = struct{}{}
			continue
		}
		yamlAdd = append(yamlAdd, ns.Name)
	}

	// Filter cliList through veto, deduplicating.
	out := make([]string, 0, len(cliList)+len(yamlAdd))
	added := make(map[string]struct{}, len(cliList)+len(yamlAdd))
	for _, ns := range cliList {
		if _, vetoed := veto[ns]; vetoed {
			continue
		}
		if _, dup := added[ns]; dup {
			continue
		}
		out = append(out, ns)
		added[ns] = struct{}{}
	}

	// Append YAML-added namespaces that aren't already in the output.
	for _, ns := range yamlAdd {
		if _, dup := added[ns]; dup {
			continue
		}
		out = append(out, ns)
		added[ns] = struct{}{}
	}

	return out
}

// PerNamespacePrivacyOverrides returns a {namespace → privacyMode-string}
// map for namespaces whose YAML entry specified `privacyMode`. Namespaces
// without an override are absent from the map; the caller is expected to
// fall back to its global default for those.
//
// The returned strings are NOT normalised — the caller (typically
// data_masks.ParsePrivacyMode) is the source of truth for canonicalising
// "dryrun" → "dry-run", uppercase, etc. We deliberately don't import
// data_masks here to avoid a package cycle (apidump → data_masks → … →
// apidump would be created via the redactor's eventual config-reload
// pathways).
func (c *DiscoveryConfig) PerNamespacePrivacyOverrides() map[string]string {
	if c == nil {
		return nil
	}
	out := make(map[string]string)
	for _, ns := range c.Discovery.Namespaces {
		if mode, ok := ns.PrivacyModeOverride(); ok {
			out[ns.Name] = mode
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
