// SPDX-License-Identifier: Apache-2.0

package apidump

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// writeYAML is a tiny helper that writes a YAML string to a temp file and
// returns its path. t.TempDir cleans up automatically.
func writeYAML(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "discovery.yaml")
	if err := os.WriteFile(p, []byte(contents), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadDiscoveryConfig_Valid(t *testing.T) {
	yaml := `
discovery:
  namespaces:
    - name: app-prod
      decrypt: true
    - name: payments-prod
      decrypt: false
    - name: legacy
      decrypt: true
`
	cfg, err := LoadDiscoveryConfig(writeYAML(t, yaml))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(cfg.Discovery.Namespaces); got != 3 {
		t.Fatalf("namespaces count = %d, want 3", got)
	}
	if cfg.Discovery.Namespaces[0].Name != "app-prod" || !cfg.Discovery.Namespaces[0].Decrypt {
		t.Errorf("entry 0 = %+v", cfg.Discovery.Namespaces[0])
	}
	if cfg.Discovery.Namespaces[1].Name != "payments-prod" || cfg.Discovery.Namespaces[1].Decrypt {
		t.Errorf("entry 1 = %+v", cfg.Discovery.Namespaces[1])
	}
}

func TestLoadDiscoveryConfig_EmptyIsValid(t *testing.T) {
	// An empty file is valid YAML and produces an empty result. Caller is
	// expected to fall back to the CLI flag in that case.
	cfg, err := LoadDiscoveryConfig(writeYAML(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Discovery.Namespaces) != 0 {
		t.Errorf("expected 0 namespaces, got %d", len(cfg.Discovery.Namespaces))
	}
}

func TestLoadDiscoveryConfig_FileNotFound(t *testing.T) {
	_, err := LoadDiscoveryConfig("/no/such/path.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "read discovery config") {
		t.Errorf("error message = %q, want contains 'read discovery config'", err)
	}
}

func TestLoadDiscoveryConfig_MalformedYAML(t *testing.T) {
	yaml := `
discovery:
  namespaces:
    - name: app-prod
      decrypt: maybe   # not a bool
`
	_, err := LoadDiscoveryConfig(writeYAML(t, yaml))
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestLoadDiscoveryConfig_MissingName(t *testing.T) {
	yaml := `
discovery:
  namespaces:
    - decrypt: true     # no name → must reject
`
	_, err := LoadDiscoveryConfig(writeYAML(t, yaml))
	if err == nil {
		t.Fatal("expected error for missing name")
	}
	if !strings.Contains(err.Error(), "name is required") {
		t.Errorf("error message = %q, want contains 'name is required'", err)
	}
}

func TestLoadDiscoveryConfig_DuplicateNamespace(t *testing.T) {
	yaml := `
discovery:
  namespaces:
    - name: app-prod
      decrypt: true
    - name: app-prod
      decrypt: false
`
	_, err := LoadDiscoveryConfig(writeYAML(t, yaml))
	if err == nil {
		t.Fatal("expected error for duplicate namespace")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("error message = %q, want contains 'duplicate'", err)
	}
}

func TestLoadDiscoveryConfig_UnknownField_StrictRejects(t *testing.T) {
	// UnmarshalStrict catches typos / future fields so users get an early
	// error instead of a silently-ignored config.
	yaml := `
discovery:
  namespaces:
    - name: app-prod
      decrypt: true
      ttypo: oops
`
	_, err := LoadDiscoveryConfig(writeYAML(t, yaml))
	if err == nil {
		t.Fatal("expected strict parse to reject unknown field")
	}
}

// -- MergeTargetNamespaces -------------------------------------------------

func TestMergeTargetNamespaces_NilConfig(t *testing.T) {
	var c *DiscoveryConfig
	got := c.MergeTargetNamespaces([]string{"a", "b"})
	if !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("nil config dropped CLI list: got %v", got)
	}
}

func TestMergeTargetNamespaces_OnlyCLI(t *testing.T) {
	c := &DiscoveryConfig{}
	got := c.MergeTargetNamespaces([]string{"foo", "bar"})
	if !reflect.DeepEqual(got, []string{"foo", "bar"}) {
		t.Errorf("empty YAML changed CLI list: got %v", got)
	}
}

func TestMergeTargetNamespaces_YAMLAddsAndVetos(t *testing.T) {
	c := &DiscoveryConfig{
		Discovery: DiscoverySection{Namespaces: []DiscoveryNamespace{
			{Name: "team-a", Decrypt: true},
			{Name: "team-b", Decrypt: false}, // veto
			{Name: "team-c", Decrypt: true},
		}},
	}
	got := c.MergeTargetNamespaces([]string{"team-b", "existing"})
	// Expected: "team-b" vetoed by YAML; "existing" survives from CLI;
	// "team-a" + "team-c" added by YAML (in YAML order).
	want := []string{"existing", "team-a", "team-c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("merge = %v, want %v", got, want)
	}
}

func TestMergeTargetNamespaces_DedupsCLIInput(t *testing.T) {
	c := &DiscoveryConfig{}
	got := c.MergeTargetNamespaces([]string{"foo", "foo", "bar", "foo"})
	want := []string{"foo", "bar"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("dedup failed: got %v, want %v", got, want)
	}
}

func TestMergeTargetNamespaces_DedupsAcrossCLIAndYAML(t *testing.T) {
	c := &DiscoveryConfig{
		Discovery: DiscoverySection{Namespaces: []DiscoveryNamespace{
			{Name: "foo", Decrypt: true}, // already in CLI list
		}},
	}
	got := c.MergeTargetNamespaces([]string{"foo"})
	want := []string{"foo"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("cross-source dedup failed: got %v, want %v", got, want)
	}
}

func TestMergeTargetNamespaces_VetoOnlyConfig(t *testing.T) {
	// A YAML with only `decrypt: false` entries is the "deny list" form.
	c := &DiscoveryConfig{
		Discovery: DiscoverySection{Namespaces: []DiscoveryNamespace{
			{Name: "secret-ns", Decrypt: false},
		}},
	}
	got := c.MergeTargetNamespaces([]string{"app", "secret-ns", "other"})
	want := []string{"app", "other"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("veto-only = %v, want %v", got, want)
	}
}
