# Phase 4 — Privacy & redaction hardening

**Starting branch:** `feat/https-capture-ebpf` after Phase 2 has merged. Can run **in parallel** with Phase 3 — no dependency.

**Working branch:** `feat/https-capture-ebpf-phase4`.

**Requires:** Linux dev host (for validation against real captured traffic), no clusters needed. The bulk of the work is Go code in `data_masks/` + doc work.

**Effort:** 2 weeks.

**Why this is high priority:** This is what gates the customer demo for security-sensitive verticals (finance, healthcare, government). A working Phase 1+2 with weak redaction is worse than no HTTPS capture at all — it's a liability.

---

## Goal

Close all 8 privacy gaps identified in `docs/https-capture-design.md` §7.3. Match the "Datadog USM" baseline in the industry comparison table (§7.4). Ship customer-facing security review artifacts.

## Hard exit criteria

All 8 items from §7.3 implemented and tested:

1. ✅ `authorization`, `cookie`, `www-authenticate`, `proxy-authenticate`, `grpc-authorization`, `x-forwarded-client-cert` added to default sensitive-keys list in `data_masks/redaction_config.yaml`.
2. ✅ `--https-body-size-cap` flag works end-to-end. Bodies truncated at the BPF layer; full length preserved in metadata.
3. ✅ `--privacy-mode=strict` drops all bodies, keeps only method + path + status + allowlisted headers.
4. ✅ Per-namespace / per-service opt-out via `decrypt: false` in discovery config.
5. ✅ Tokenization mode: `--redaction-style=hash` replaces matched values with `sha256(value)[:16]` instead of `***REDACTED***`.
6. ✅ Redaction-coverage telemetry: count of redactions per rule, exposed via the existing telemetry pipeline.
7. ✅ `--privacy-mode=dry-run` mode: capture + redact + log stats; do NOT upload to backend.
8. ✅ Customer-facing docs delivered: `docs/https-data-flow.md`, `docs/security-permissions.md`, `docs/redaction-defaults.md`.

Plus:

9. External regression suite: a corpus of 200+ synthetic HTTP requests/responses containing known sensitive patterns. Run through the redactor; assert 100% of known patterns are redacted, ≤ 0.1% false-positive rate on a separate "safe" corpus.

## Prerequisites — read these first

In the agent repo:
- `docs/https-capture-design.md` §7 (the entire privacy section)
- `data_masks/redaction_config.yaml` — current default rules
- `data_masks/redactor.go` — redaction engine
- `data_masks/user_redaction_config.go` — customer overrides
- `data_masks/redaction_test.go` — existing test patterns

In OBI:
- `bpf/common/large_buffers.h` — buffer-cap design (already mirrored)
- `pkg/config/ebpf_tracer.go::EBPFBufferSizes` — per-protocol size config

Reference industry approaches:
- Datadog APM redaction docs (public)
- New Relic redaction (Pixie's `src/stirling/source_connectors/socket_tracer/redaction/`)

## Tasks (in order)

### 1. Extend default sensitive-keys list

Edit `data_masks/redaction_config.yaml`. Add:

```yaml
sensitive_keys:
  - authorization
  - cookie
  - www-authenticate
  - proxy-authenticate
  - grpc-authorization
  - x-forwarded-client-cert
  - x-forwarded-authorization
  - x-amz-content-sha256       # not strictly secret but often paired
  - x-api-secret
  - x-shared-secret
  - x-internal-token
  # Note: 'proxy-authorization' is already in the list.
```

Add tests in `data_masks/redaction_test.go` proving each new key triggers redaction in headers, JSON keys, and form fields.

### 2. Body-size cap as redaction concern

Already wired at BPF layer in Phase 1/2. Now make it explicit in the redactor:

- Add `MaxBodyBytes` field to `data_masks.RedactionOptions`.
- In `redactor.go`, when a body exceeds the cap, truncate to `MaxBodyBytes` and emit a synthetic field `{"_truncated": true, "_original_length": N}`.
- Backend understands this metadata for accurate display.

CLI flag: `--https-body-size-cap` (already declared in Phase 2). Wire it to `RedactionOptions.MaxBodyBytes` at apidump startup.

### 3. Privacy mode presets

New file `data_masks/privacy_mode.go`:

```go
type PrivacyMode string
const (
    PrivacyStandard PrivacyMode = "standard"
    PrivacyStrict   PrivacyMode = "strict"
    PrivacyDryRun   PrivacyMode = "dry-run"
)

type PrivacyModeConfig struct {
    Mode              PrivacyMode
    DropBodies        bool
    HeaderAllowlist   []string  // empty = redact-aware default
    UploadEnabled     bool
}

func (m PrivacyMode) Config() PrivacyModeConfig { ... }
```

| Mode | DropBodies | HeaderAllowlist | UploadEnabled |
|---|:---:|---|:---:|
| `standard` | false | (empty — all headers except redacted) | true |
| `strict` | **true** | `["content-type", "content-length", "user-agent"]` only | true |
| `dry-run` | false | (same as standard) | **false** |

In `dry-run`, the agent does everything except the final upload. Instead it writes a redaction report to `/var/log/postman-insights/dry-run-<timestamp>.json` with anonymized samples.

CLI flag: `--privacy-mode` (already declared in Phase 2). Wire to the mode selection at apidump startup.

### 4. Per-namespace opt-out

Extend the discovery YAML schema (in `cmd/internal/kube/daemonset/` templates):

```yaml
discovery:
  namespaces:
    - name: app-prod
      decrypt: true
    - name: payments-prod
      decrypt: false       # eBPF probes will not attach; HTTPS stays opaque
    - name: legacy
      decrypt: true
      privacyMode: strict  # per-namespace override
```

Update `integrations/kube_apis/` to parse and surface these fields. Update `ebpf/discovery/kube.go` (created in Phase 2) to respect `decrypt: false` by skipping uprobe attach for matching pods.

Test by deploying a workload in a `decrypt: false` namespace and verifying its HTTPS traffic is **not** in the captured stream, while a `decrypt: true` workload IS captured.

### 5. Tokenization mode

New file `data_masks/tokenization.go`:

```go
type RedactionStyle string
const (
    StyleRedact RedactionStyle = "redact"   // replace with ***REDACTED***
    StyleHash   RedactionStyle = "hash"     // replace with sha256(value)[:16]
)

func applyStyle(value string, style RedactionStyle) string {
    switch style {
    case StyleHash:
        h := sha256.Sum256([]byte(value))
        return "REDACTED:" + hex.EncodeToString(h[:8])
    default:
        return "***REDACTED***"
    }
}
```

Plumb through `redactor.go`. CLI flag: `--redaction-style=redact|hash` (default `redact`).

The point of hash mode: customers can correlate "is this the same user across two requests?" without seeing the user's actual identifier.

### 6. Redaction-coverage telemetry

Each redaction rule (sensitive key match, regex match, body truncation) gets a counter:

```go
type RedactionCoverage struct {
    SensitiveKeyHits     map[string]uint64  // key name → count
    SensitiveValueHits   map[string]uint64  // regex pattern name → count
    UserRuleHits         map[string]uint64  // customer-supplied rule → count
    BodyTruncations      uint64
    TotalRequestsScanned uint64
}
```

Emit hourly via existing telemetry. Surface in the Postman Insights UI as a per-service dashboard.

This is what customers' security teams will demand as proof that redaction is firing on real data.

### 7. Dry-run reporter

When `--privacy-mode=dry-run` is active:

1. Capture + redact normally.
2. Skip the backend upload step entirely.
3. Every 60s, write a JSON report:
   ```json
   {
     "window_start": "2026-05-12T10:00:00Z",
     "window_end":   "2026-05-12T10:01:00Z",
     "requests_scanned": 4823,
     "redactions": {
       "header.authorization": 4823,
       "header.cookie":        4823,
       "regex.aws_key":          12,
       "regex.stripe_sk":         2,
       "user.customer_pattern_1": 304
     },
     "body_truncations": 71,
     "samples": [
       { "method": "POST", "path": "/api/users",
         "redacted_request":  { ... },
         "redacted_response": { ... }
       }
     ]
   }
   ```
4. Samples are randomly selected (5 per window) AFTER redaction so customers can inspect.

This is the **single most important deliverable** for the customer demo. The script reads:

> "Run the agent in dry-run mode for 24 hours. Read the resulting redaction
> reports. If the redaction looks sufficient for your compliance posture,
> flip the switch to live mode by changing one config value."

### 8. Customer-facing security docs

Create three new docs:

**`docs/https-data-flow.md`** — sequence diagram:
```
Kernel uprobe fires
  → BPF copies up to N bytes to ringbuf
  → Agent reads ringbuf
  → Agent feeds bytes into akinet parser
  → Agent runs redactor over parsed structure
  → Agent batches + compresses
  → Agent uploads over TLS to api.postman.com
  → Backend stores encrypted at rest in <region>
```
At each step, list:
- What data exists at that point
- Who can see it (process, host, network, datacenter)
- What encryption applies

**`docs/security-permissions.md`** — exhaustive list:
- Linux capabilities required (BPF, PERFMON, NET_ADMIN — explain each)
- Syscalls hooked (uprobe targets + the kprobe on `sys_ioctl` for Java)
- Filesystem paths read (`/proc`, `/sys/kernel/debug`, `/sys/fs/bpf`)
- Kubernetes RBAC (list namespaces, watch pods, get pods)
- Network egress (api.postman.com:443 only)
- What the agent CANNOT do (write to traffic, modify packets, block syscalls — all read-only)

**`docs/redaction-defaults.md`** — for the customer's compliance officer:
- Full sensitive-keys list with rationale per key
- Full regex list with example matches
- How to add customer-specific patterns
- How to verify rules are firing (dry-run mode, telemetry dashboard)
- Compliance mappings (PCI DSS requirement N.M, HIPAA Safeguard X, GDPR Art. Y)

### 9. Regression test corpus

Create `data_masks/testdata/redaction-corpus/`:
- `sensitive-fixtures.json` — 200+ synthetic HTTP messages, each containing at least one known-sensitive pattern, labeled with which patterns it contains
- `safe-fixtures.json` — 200+ synthetic HTTP messages with no sensitive content
- `redaction_corpus_test.go` — load both fixtures, run through redactor, assert:
  - 100% of labeled sensitive patterns are redacted in `sensitive-fixtures`
  - ≤ 0.1% of `safe-fixtures` have any redaction (false-positive bound)

Run in CI on every PR. This is the regression net that prevents privacy regressions when redaction rules are edited.

## Common failure modes

1. **Case sensitivity in header redaction.** HTTP headers are case-insensitive but Go map keys aren't. Verify `Authorization`, `authorization`, `AUTHORIZATION` all redact.

2. **JSON body redaction missing nested fields.** A `password` inside `user.account.credentials.password` must be caught. Test deeply-nested fixtures.

3. **Form-encoded body redaction.** `application/x-www-form-urlencoded` body `password=secret&token=xyz` is different from JSON. Make sure the redactor handles both.

4. **gRPC binary headers.** gRPC headers ending in `-bin` are base64-encoded binary. Don't redact the encoding; decode then redact.

5. **Hash collision in tokenization.** SHA256 truncated to 8 bytes (16 hex chars) has small but nonzero collision probability across billions of values. Document this; offer 16-byte (32-hex) variant.

6. **Customer-supplied regex DoS.** A malicious or accidentally-quadratic regex pattern from `user_redaction_config.yaml` can hang the redactor. Wrap each match call with a deadline. Pixie has this exact bug in its history.

7. **Performance regression from added rules.** Adding 10+ new sensitive keys is a constant factor on every header scan. Benchmark before/after; expect 5-10% redaction-step slowdown. Acceptable.

## Validation

```sh
# 1. Default build clean.
go build ./...

# 2. New unit tests pass.
go test ./data_masks/...

# 3. Regression corpus.
go test -run TestRedactionCorpus ./data_masks/

# 4. End-to-end with --privacy-mode=dry-run.
sudo ./bin/postman-insights-agent apidump --enable-https-capture --privacy-mode=dry-run --duration 5m
ls /var/log/postman-insights/dry-run-*.json
# Verify reports look sensible. Verify NO upload happened.

# 5. --privacy-mode=strict drops bodies.
sudo ./bin/postman-insights-agent apidump --enable-https-capture --privacy-mode=strict --duration 1m
# Verify captured ParsedNetworkTraffic has no body field.

# 6. Per-namespace decrypt: false works.
kubectl apply -f docs/phases/phase-4-test-namespaces.yaml
# Generate traffic in both. Only decrypt: true namespace should appear in captures.

# 7. Tokenization.
echo '{"api_key":"sk_live_abc123"}' | ./bin/redact --style=hash
# Should print {"api_key":"REDACTED:a1b2c3..."} not "***REDACTED***"

# 8. Customer-facing docs render and read well.
```

## Handoff

Update:
- `ebpf/README.md` — Privacy hardening ✅
- `docs/https-capture-design.md` §7 — add "Phase 4 delivered" callout
- `docs/phases/phase-4-results.md` — corpus size, false-positive rate measured, performance delta

What's left for Phase 5:
- Java agent ships with its own redaction story (it produces the same bytes that flow through the eBPF ringbuf, so Phase 4's redactor is the only layer; no Java-specific redactor needed)
