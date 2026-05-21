# Phase 4c — Per-namespace `privacyMode` override (full enforcement)

**Session goal:** complete item 4 of the post-launch follow-up backlog.
The phase-4b `decrypt: true|false` YAML extension shipped the field
schema; this session adds the **`privacyMode`** per-namespace override
and—crucially—actually enforces it at redaction time.

**Branch:** `feat/https-capture-ebpf` (rolling PR #173).

**Blast radius:** moderate. Touches three packages (`apidump`, `data_masks`,
`trace`) and the Linux-only `apidump/ebpf_integration.go`. New behaviour
is gated on `--https-discovery-config` being supplied + the kube-API
client initialising successfully — every error path falls back to the
existing global `--privacy-mode` default. No BPF / kernel-side changes.

---

## TL;DR

| Goal | Result |
| --- | --- |
| YAML schema extended with `privacyMode` | ✅ string field with strict validation |
| Per-namespace overrides actually applied at redact time | ✅ `Redactor.PerNamespacePrivacyConfig` + `RedactSensitiveDataForNamespace` |
| Namespace plumbed from BPF event → witness → redactor | ✅ via existing `ifaceTag` + new `BackendCollector.SetNamespaceResolver` callback |
| Graceful degradation when kube client fails | ✅ falls back to global default, warns |
| Schema typos rejected at parse time (empty-string / unknown mode) | ✅ both rejected with clear errors |
| 21 new unit tests | ✅ all pass in <1 s |
| Mac build + Linux build clean | ✅ both green |
| Linux full-suite regression | ✅ 14 ok / 0 fails |

## Design

### 1. The plumbing problem

The redactor's hot path is `RedactSensitiveData(*pb.Method)` — no
namespace info at that point. To make per-namespace overrides work I
needed to thread the namespace from the BPF event all the way through
to the redact site.

The good news: every eBPF witness already carries an `ebpf-pid-<N>`
tag in its `Interface` field, set by `events.Adapter` (Phase 1). And
the `KubeNamespaceResolver` (Phase 2) already knows how to translate
PID → Kubernetes namespace. So the plumbing was a callback rather than
a structural change to the witness pipeline.

### 2. Where the new code lives

```
apidump/discovery_config.go     +PrivacyMode field on DiscoveryNamespace
                                +validation in LoadDiscoveryConfig
                                +PerNamespacePrivacyOverrides() helper

apidump/apidump.go              after Redactor construction, build a
                                {namespace → PrivacyModeConfig} map from
                                the discovery YAML; assign to
                                Redactor.PerNamespacePrivacyConfig

apidump/ebpf_integration.go     +newNamespaceResolverForCollector(pidResolver):
                                parses "ebpf-pid-<N>" → calls Namespace(pid);
                                wired onto the BackendCollector once the
                                KubeNamespaceResolver finishes init

trace/backend_collector.go      +namespaceResolver func field
                                +SetNamespaceResolver setter
                                at redact site, look up namespace from
                                w.netInterface, call new redactor entry point

data_masks/redactor.go          +PerNamespacePrivacyConfig map field
                                +RedactSensitiveDataForNamespace(m, ns)
                                +lookupConfigForNamespace(ns)
                                RedactSensitiveData unchanged in behaviour
                                (calls the internal path with empty ns)
```

### 3. Precedence rules (documented in `discovery-mode.md`)

1. Witness has namespace tag → look up in `PerNamespacePrivacyConfig`
   → if found, use that config.
2. Witness has namespace tag but it isn't in the override map →
   use global `PrivacyConfig`.
3. Witness has no namespace tag (pcap, or kube resolver missed) →
   use global `PrivacyConfig`.
4. kube-API client failed to init → no resolver wired; everything
   uses global `PrivacyConfig`. Agent warns once at startup.

### 4. Why the redactor's lookup is per-call, not per-construction

The natural alternative — construct one `Redactor` per namespace at
startup — was rejected because:

* The agent doesn't know which namespaces it'll see until pods are
  created. New namespaces appearing post-startup (CI clusters create
  hundreds of namespaces per day in some setups) would need redactor
  re-instantiation. Hot reload is the wrong layer to handle this.
* Sharing the rest of the redactor's state (regex patterns, dynamic
  config from the backend, coverage counters) is the right default.
  Per-namespace branching only on `PrivacyModeConfig`, which is what
  the user actually said they wanted to override.
* `lookupConfigForNamespace` is a `O(1)` map lookup; the per-call cost
  is negligible.

## Schema validation (gap-4 hardening)

`LoadDiscoveryConfig` rejects three classes of mistakes at startup:

* `privacyMode: ` (empty value) — caller almost certainly meant to
  type a real mode. Rejected with `discovery config %q: namespace %q
  has empty privacyMode; omit the field entirely to inherit the
  global --privacy-mode flag`.
* `privacyMode: paranoid` (typo / unknown mode) — rejected with
  `unknown privacyMode "paranoid" (want one of: standard, strict, dry-run)`.
* Unknown YAML field (e.g. `privacymode:` lowercase) — already
  rejected by `UnmarshalStrict` from Phase 4b.

Accepted modes mirror what `data_masks.ParsePrivacyMode` accepts:
`standard`, `strict`, `dry-run`, `dryrun` (alias). Case-insensitive
at the YAML layer; canonical normalisation happens in
`ParsePrivacyMode`.

## What this session does NOT change

* Bytecode of the BPF programs. No kernel-side changes.
* The pcap capture path. Pcap witnesses have no PID-encoded namespace,
  so they always use the global default. Documented in
  `discovery-mode.md`.
* `--privacy-mode` semantics. The global flag is still the source of
  truth when no override applies, and it's still the default for any
  namespace not listed in the discovery config.
* The redactor's public `RedactSensitiveData(*pb.Method)` signature.
  Existing callers (tests, plugin packages) keep working.

## Validation — full evidence

### Mac build

```
$ go build ./...
(no output; exit 0)
```

### Linux build (insights_bpf tag)

```
$ docker exec pia-bpf-dev bash -lc 'cd /workspace && make build-ebpf'
go clean
cd ebpf/loader && go generate -tags insights_bpf ./...
go build -tags insights_bpf -o bin/postman-insights-agent .
```

### Linux full test suite

```
$ docker exec pia-bpf-dev bash -lc 'cd /workspace && make test'
ok count: 14
FAIL count: 0
```

### New tests (21 total)

```
$ go test -count=1 -timeout 30s -v -run "TestLoadDiscoveryConfig_PrivacyMode|TestPerNamespacePrivacyOverrides|TestDiscoveryNamespace_PrivacyModeOverride|TestNamespaceResolverForCollector" ./apidump/

--- PASS: TestLoadDiscoveryConfig_PrivacyMode_Valid              (0.00s)
--- PASS: TestLoadDiscoveryConfig_PrivacyMode_EmptyStringRejected (0.00s)
--- PASS: TestLoadDiscoveryConfig_PrivacyMode_UnknownRejected    (0.00s)
--- PASS: TestLoadDiscoveryConfig_PrivacyMode_DryrunAliasAccepted (0.00s)
--- PASS: TestLoadDiscoveryConfig_PrivacyMode_CaseInsensitive    (0.00s)
--- PASS: TestPerNamespacePrivacyOverrides_NilConfig             (0.00s)
--- PASS: TestPerNamespacePrivacyOverrides_NoOverrides           (0.00s)
--- PASS: TestDiscoveryNamespace_PrivacyModeOverride             (0.00s)
    --- PASS: .../absent                                          (0.00s)
    --- PASS: .../present                                         (0.00s)
--- PASS: TestNamespaceResolverForCollector_HappyPath            (0.00s)
--- PASS: TestNamespaceResolverForCollector_NonEbpfTagSkipped    (0.00s)
--- PASS: TestNamespaceResolverForCollector_GarbagePIDSkipped    (0.00s)
--- PASS: TestNamespaceResolverForCollector_LargePID             (0.00s)
--- PASS: TestNamespaceResolverForCollector_OverflowPIDReturnsEmpty (0.00s)
--- PASS: TestNamespaceResolverForCollector_NilResolverReturnsNil (0.00s)
--- PASS: TestNamespaceResolverForCollector_ResolverReturnsEmpty (0.00s)
PASS    apidump   0.55s
```

```
$ go test -count=1 -timeout 30s -v -run "TestLookupConfigForNamespace|TestRedactSensitiveDataForNamespace" ./data_masks/

--- PASS: TestLookupConfigForNamespace_EmptyMapFallsBackToDefault   (0.00s)
--- PASS: TestLookupConfigForNamespace_EmptyNamespaceFallsBackToDefault (0.00s)
--- PASS: TestLookupConfigForNamespace_KnownNamespaceUsesOverride   (0.00s)
--- PASS: TestLookupConfigForNamespace_UnknownNamespaceUsesDefault  (0.00s)
--- PASS: TestLookupConfigForNamespace_OverrideIndependentPerCall   (0.00s)
--- PASS: TestRedactSensitiveDataForNamespace_RoutesByNamespace     (0.00s)
PASS    data_masks   0.50s
```

### Notable test invariants

| Test | Invariant |
| --- | --- |
| `LookupConfigForNamespace_OverrideIndependentPerCall` | Calling lookup with namespace `team-payments` (override = strict) must NOT mutate `Redactor.PrivacyConfig`. Otherwise subsequent calls from any other namespace would silently flip to strict. |
| `LookupConfigForNamespace_EmptyNamespaceFallsBackToDefault` | Pcap-sourced witnesses (no PID, namespace = "") MUST use the global default, never a per-namespace override. |
| `NamespaceResolverForCollector_GarbagePIDSkipped` | `"ebpf-pid-foo"` MUST NOT call `Namespace(0)` — that would silently match PID 0 if it were ever in the table. |
| `NamespaceResolverForCollector_NonEbpfTagSkipped` | Pcap interfaces (`eth0`, `lo`) MUST NOT call `Namespace()` — those tags carry no PID. |
| `LoadDiscoveryConfig_PrivacyMode_EmptyStringRejected` | `privacyMode: ` (no value) MUST be a parse error, not silently treated as "no override". |

## Commit reference

This is committed as a single change spanning the three packages plus
docs. The atomic unit makes sense because:

* The feature is the *enforcement*, not the schema; shipping the
  schema alone (Phase 4b style) would leave a misleading config knob
  that has no effect.
* The plumbing (BackendCollector ↔ Redactor) is tightly coupled to
  the schema; splitting them would require interim no-op code.

## What's NEXT in the follow-up backlog

* **Item 5 — CI smoke test for the kind e2e flow.** Helm lint + helm
  template validation in CircleCI; full kind e2e remains deferred.

After item 5, the follow-up backlog (items 1-5) is complete and the
program reaches steady state.
