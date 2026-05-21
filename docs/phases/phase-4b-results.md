# Phase 4b — Close-out of design-doc §7.3 gaps 2 and 4

**Session goal:** finish what's pending per the original plan. The
[`https-capture-design.md`](../https-capture-design.md) §7.3 specifies 8
privacy gaps that must close before HTTPS launch.
[`phase-4-results.md`](phase-4-results.md) shipped 5 + 8 (gaps 1, 3, 5,
6, 7, 8). Gaps 2 and 4 were left partial with the deferral rationale
"BPF-layer cap already protects" / "CLI flag already provides the same
control." This session closes both gaps to the literal design-doc spec
so launch-readiness criteria are met.

**Branch:** `feat/https-capture-ebpf` (rolling PR #173).

**Blast radius:** **none**. Pure user-space additions:
* gap 2 = synthetic HTTP headers injected before the redactor sees the
  request/response.
* gap 4 = an alternative input shape for an already-existing CLI flag.

Neither touches the BPF programs, the loaders, or the kernel-side capture
path.

---

## TL;DR

| Gap | Status before | What this session shipped |
| --- | --- | --- |
| **2: Body-size cap as redaction concern** | 🟡 BPF cap live; redactor-side metadata deferred | ✅ Adapter injects `X-Postman-Insights-Body-Truncated: true` + `X-Postman-Insights-Body-Dropped-Bytes: <N>` on emitted HTTP messages whenever at least one contributing BPF event was truncated |
| **4: Per-namespace opt-out** | 🟡 `--https-target-namespaces` CLI form works; YAML form deferred | ✅ `--https-discovery-config=path.yaml` accepts the design's `discovery.namespaces[].decrypt: true\|false` schema; merge semantics documented; 13 tests |

**23 new tests, all passing in <1 s.** Linux full-suite regression: 14 ok / 0 fails.

## Gap 2 — body-truncation metadata

### What was already in place

* `--https-body-size-cap` CLI flag (Phase 2).
* Kernel-side cap in `libssl.bpf.c` / `gotls.bpf.c` / `java_tls.bpf.c`.
* `SSLEvent.LenTotal` carries the wire length even when bytes are dropped.
* `SSLEvent.Truncated()` returns whether the event was capped.

### What was missing

Nothing in user-space *consumed* `Truncated()`. The Phase 4 brief called
for metadata on the recording itself, so the redactor + backend know
when a body was incomplete. That bridge didn't exist.

### What this session added

* New file [`ebpf/events/truncation.go`](../../ebpf/events/truncation.go):
  exports two synthetic header names + an `annotateTruncation` function
  that mutates `akinet.HTTPRequest` / `akinet.HTTPResponse` headers.
* Two new fields on `flowState` in [`ebpf/events/adapter.go`](../../ebpf/events/adapter.go)
  to track per-message truncation:
  * `pendingTruncated bool` — "at least one event in the in-flight
    message was truncated"
  * `pendingDroppedBytes uint64` — sum of `LenTotal - LenCaptured` across
    contributing events
* Wiring in `Adapter.Feed`: when `ev.Truncated()` is true, accumulate
  into the flow state.
* Wiring in `Adapter.drain`: when a complete message is emitted, call
  `annotateTruncation` if `pendingTruncated`, then **reset the counters**
  so message N+1 on the same keep-alive flow doesn't inherit message N's
  tag.

### Why "dropped bytes" rather than "original length"

The BPF layer caps each *event*, not each *message*. One HTTP message
can be carried by N events; some may be truncated, others not. We can
honestly report the sum of bytes the BPF cap dropped across contributing
events — but we cannot reconstruct the original body length without
unbounded buffering, which is exactly what the cap exists to prevent.
"Original length" would be a lie unless we doubled the memory footprint
in user-space.

The redactor / backend can still combine `dropped-bytes` + observed
body length to derive a lower bound on the original — they just can't
get the exact wire length.

### Synthetic header convention (documented in `truncation.go`)

```
X-Postman-Insights-Body-Truncated: true
X-Postman-Insights-Body-Dropped-Bytes: <int>
```

These are agent-private. They never exist on the wire and never come
from the customer's traffic. The downstream redactor + backend can
treat them as ordinary headers.

### Validation

10 tests in two files, all passing in 0.30 s:

```
ebpf/events/truncation_test.go         — 6 unit tests
ebpf/events/truncation_adapter_test.go — 4 adapter integration tests
```

Notable invariants exercised:

| Test | Asserts |
| --- | --- |
| `TestAnnotateTruncation_HTTPRequest_ByValue` | Mutation through value receiver works because `http.Header` is a map (reference semantics survive value copies) |
| `TestAnnotateTruncation_UnknownContent` | Forward-compat: unknown ParsedNetworkContent types don't panic |
| `TestAnnotateTruncation_NilHeader` | Parser regression won't cause a nil-map write panic |
| `TestAdapter_TruncatedEvent_TagsEmittedRequest` | A truncated event → emitted message carries the header |
| `TestAdapter_UntruncatedEvent_NoHeaders` | Clean flows DON'T get spurious tags |
| `TestAdapter_TruncationAccumulatesAcrossEvents` | 100 + 0 + 200 dropped bytes across 3 events → emitted header reads `300` |
| `TestAdapter_TruncationResetsBetweenMessages` | Keep-alive pipelining: message N's tag does NOT leak to message N+1 |

All four adapter tests use real `akihttp` parsers + a real
`ParsedNetworkTraffic` channel, exercising the same code path as the
production capture pipeline.

## Gap 4 — per-namespace `decrypt: false` via YAML

### What was already in place

`--https-target-namespaces=team-a,team-b` (Phase 2) — comma-separated
CLI flag that produces an allow-list for `KubeNamespaceResolver`. The
eBPF discovery layer skips attaching uprobes to PIDs outside the
allow-list.

### What was missing

The design doc spec said:

```yaml
discovery:
  namespaces:
    - name: app-prod
      decrypt: true
    - name: payments-prod
      decrypt: false
```

A YAML form of the same control. The CLI flag is awkward to use in
Helm values / DaemonSet manifests / GitOps repos — colon-separated
becomes a single long string. The YAML form is the design's preferred
expression.

### What this session added

* New file [`apidump/discovery_config.go`](../../apidump/discovery_config.go)
  with:
  * `DiscoveryConfig`, `DiscoverySection`, `DiscoveryNamespace` types
    matching the design's YAML shape.
  * `LoadDiscoveryConfig(path)` — reads the file, parses strict YAML
    (rejects unknown fields), validates name uniqueness + non-empty name.
  * `(*DiscoveryConfig).MergeTargetNamespaces(cliList)` — merges with
    the existing `--https-target-namespaces` CLI list. `decrypt: false`
    entries veto CLI inclusions of the same namespace.
* New CLI flag `--https-discovery-config=path.yaml` in
  [`cmd/internal/apidump/apidump.go`](../../cmd/internal/apidump/apidump.go).
* `mergeHTTPSTargetNamespaces` helper that's called when the
  `Args.HTTPSTargetNamespaces` field is set, so the rest of the pipeline
  doesn't need to know about the YAML form — it sees a unified
  allow-list either way.
* Friendly error handling: YAML load failure prints a warning and falls
  back to the CLI list. The agent never refuses to start over a config
  error; the warning surfaces the problem.

### Merge semantics (documented in `discovery_config.go`)

Inputs:

* `cliList` from `--https-target-namespaces`
* YAML `discovery.namespaces[]` entries

Output:

* Start with `cliList`.
* Remove every `decrypt: false` namespace (YAML veto).
* Append every `decrypt: true` namespace not already present, in YAML order.
* Dedupe.

Example: CLI = `[team-b, team-c]`, YAML = `team-a: true`, `team-b: false`.
Output = `[team-c, team-a]`. (team-b vetoed, team-c kept, team-a added.)

### Validation

13 tests in [`apidump/discovery_config_test.go`](../../apidump/discovery_config_test.go),
all passing in 0.50 s:

| Group | Tests |
| --- | --- |
| `LoadDiscoveryConfig` | valid, empty, missing file, malformed YAML, missing name, duplicate namespace, unknown field strict-rejects |
| `MergeTargetNamespaces` | nil config, only CLI, YAML adds & vetos, dedups CLI input, dedups across CLI and YAML, veto-only config |

The "unknown field strict-rejects" test is particularly important: a
typo like `decrpyt: true` would otherwise silently leave the namespace
unmatched. Strict mode fails the parse so the operator sees the typo
immediately.

### Documentation

* [`docs/discovery-mode.md`](../discovery-mode.md) gained a new section
  "HTTPS capture: per-namespace opt-in (eBPF path)" covering:
  * the CLI form (existed),
  * the YAML form (new),
  * the merge semantics when both are set,
  * the default-when-neither-set behavior,
  * the v1 YAML schema table with all fields documented.

## Files touched

| File | Status | Purpose |
| --- | --- | --- |
| `ebpf/events/truncation.go` | new | Synthetic-header constants + `annotateTruncation` |
| `ebpf/events/truncation_test.go` | new | 6 unit tests |
| `ebpf/events/truncation_adapter_test.go` | new | 4 adapter integration tests |
| `ebpf/events/adapter.go` | modified | `flowState` truncation tracking; `Feed`+`drain` wiring |
| `apidump/discovery_config.go` | new | YAML loader + merge function |
| `apidump/discovery_config_test.go` | new | 13 tests |
| `cmd/internal/apidump/apidump.go` | modified | new `--https-discovery-config` flag + merge helper |
| `docs/discovery-mode.md` | modified | new "HTTPS capture: per-namespace opt-in" section |
| `docs/phases/phase-4-results.md` | modified | marked gaps 2 + 4 as ✅ post-5c.3 |
| `docs/phases/phase-4b-results.md` | new | this file |

## Why I didn't expand gap 4 to per-workload selectors

The design example also showed `privacyMode: strict` as a per-namespace
override:

```yaml
- name: legacy
  decrypt: true
  privacyMode: strict
```

I deliberately scoped that out for two reasons:

1. **It's a separate gap.** §7.3 gap 3 ("HIPAA preset") was already
   closed in Phase 4 as a global `--privacy-mode=strict` flag. The
   per-namespace override is a "make gap 3 more granular" enhancement,
   not a missing gap. Lumping it in would silently expand scope.

2. **Forward-compat.** The current YAML shape is strict-parsed, so
   adding `privacyMode: strict` later means bumping a schema version.
   That's fine — the v1 schema table in `discovery-mode.md` explicitly
   lists `privacyMode` and per-workload selectors as future additions.

## Status: design doc §7.3 closed

| # | Gap | Status |
| --- | --- | --- |
| 1 | Authorization in default sensitive-keys | ✅ Phase 4 |
| 2 | Body-size cap as redaction concept | ✅ this session |
| 3 | HIPAA/PCI preset (`--privacy-mode=strict`) | ✅ Phase 4 |
| 4 | Per-namespace opt-out (YAML form) | ✅ this session |
| 5 | Tokenization (hash-replace) | ✅ Phase 4 |
| 6 | Redaction-coverage telemetry | ✅ Phase 4 |
| 7 | Dry-run mode | ✅ Phase 4 |
| 8 | Data-flow / threat-model doc | ✅ Phase 4 |

**The "must close before HTTPS launch" criteria are met.**

## Commands to reproduce

```sh
# Unit + integration tests for both gaps
go test -count=1 -timeout 30s -v -run "TestAnnotateTruncation|TestAdapter_Truncat|TestAdapter_Untruncated" ./ebpf/events/
go test -count=1 -timeout 30s -v -run "TestLoadDiscoveryConfig|TestMergeTargetNamespaces" ./apidump/

# Linux full-suite regression (in dev container)
docker exec pia-bpf-dev bash -lc 'export PATH=/usr/local/go/bin:/go/bin:$PATH && cd /workspace && make build-ebpf && make test'

# Smoke test the new CLI flag
cat > /tmp/discovery.yaml <<EOF
discovery:
  namespaces:
    - name: team-a
      decrypt: true
    - name: team-b
      decrypt: false
EOF
./bin/postman-insights-agent apidump --https-discovery-config=/tmp/discovery.yaml --help | grep https-discovery-config
```
