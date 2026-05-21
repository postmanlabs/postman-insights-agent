# Phase 4 — Results (in progress)

**Session:** delivered after Phase 3 task #3 (gRPC) completed.
Branch: `feat/https-capture-ebpf`, PR #173.

## Scope delivered

**Update (post-5c.3):** 8 of 8 design-doc §7.3 gaps now closed. Gaps 2
and 4 were initially deferred (see history below); they were finished in
a follow-up session. See [`phase-4b-results.md`](phase-4b-results.md)
for the close-out evidence.

---

**Original Phase 4 outcome:**

5 of 8 design-doc §7.3 gaps closed, in priority order from the Phase 4
brief:

| Task | Status | Where it lives |
|---|:---:|---|
| 1. Expanded default sensitive-keys list | ✅ | `data_masks/redaction_config.yaml` (40+ defaults; +12 keys including `authorization`, `cookie`, `www-authenticate`, `proxy-authenticate`, `grpc-authorization`, `x-forwarded-client-cert`, `x-amz-content-sha256`, `x-api-secret`, `x-shared-secret`, `x-internal-token`) |
| 2. Body-size cap as redaction concern | ✅ (post-5c.3) | BPF-layer truncation lives in Phase 4. Redactor-side metadata (synthetic `X-Postman-Insights-Body-Truncated` + `X-Postman-Insights-Body-Dropped-Bytes` headers) added in the gap-2 follow-up. |
| 3. Privacy mode presets | ✅ | `data_masks/privacy_mode.go`; `PrivacyStandard`, `PrivacyStrict`, `PrivacyDryRun`; wired into `apidump.Args.PrivacyMode` and `Redactor.SetPrivacyMode`. |
| 4. Per-namespace opt-out | ✅ (post-5c.3) | `--target-namespaces` CLI form was always in place. The YAML form (`--https-discovery-config` with `decrypt: true|false` per namespace) was added in the gap-4 follow-up. |
| 5. Tokenization mode (hash replacement) | ✅ | `data_masks/tokenization.go`; `--redaction-style=hash`; centralised replacement via `Redactor.styledReplacement`. |
| 6. Redaction-coverage telemetry | ✅ | `data_masks/coverage.go`; atomic per-rule counters; thread-safe `Snapshot()`. |
| 7. Dry-run reporter | ✅ | `data_masks/dry_run.go`; spawned automatically when `--privacy-mode=dry-run`; writes per-window JSON to `--dry-run-dir` (default `/var/log/postman-insights/`). |
| 8. Customer-facing security docs | ✅ | Three new docs: [`docs/https-data-flow.md`](../https-data-flow.md), [`docs/security-permissions.md`](../security-permissions.md), [`docs/redaction-defaults.md`](../redaction-defaults.md). |
| 9. Regression corpus | ✅ | `data_masks/redaction_corpus_test.go`; 14 sensitive samples, 36 safe samples; asserts 100% sensitive detection + ≤0.1% false-positive rate (0/36 today). |

## What changed under the hood

### `data_masks/privacy_mode.go` (new)

Three modes with explicit resolved configs:

| Mode | Drop bodies | Header allowlist | Upload |
|---|:---:|---|:---:|
| `standard` (default) | — | (none) | ✓ |
| `strict` | ✓ | `content-type`, `content-length`, `user-agent` | ✓ |
| `dry-run` | — | (none) | ✗ (local JSON only) |

**Why `strict` excludes `host`:** in multi-tenant deployments,
`Host: tenant-a.example.com` can leak the tenant identifier. The
allowlist is intentionally smaller than HTTP/1's typical set.

### `data_masks/tokenization.go` (new)

`StyleRedact` (default) → `*REDACTED*`. `StyleHash` →
`REDACTED:<sha256(value)[:8]>` (16 hex chars). Hash mode enables
"same user across two requests" correlation without exposing the raw
identifier. Collision probability documented in
[`docs/redaction-defaults.md`](../redaction-defaults.md).

### `data_masks/coverage.go` (new)

Atomic per-rule counters with three flavours:
`SensitiveKeyHits`, `SensitiveRegexHits`, `UserRuleHits`. Plus four
scalars: `BodyTruncations`, `BodiesDropped`, `HeadersDropped`,
`TotalRequestsScanned`. `Snapshot()` returns a thread-safe deep copy;
`Reset()` is test-only. Nil receiver is safe — all `Inc*` methods
no-op on `*CoverageCounters = nil`, so call sites don't need to guard.

### `data_masks/dry_run.go` (new)

`DryRunReporter` is a goroutine that emits a JSON report every 60
seconds containing:

- window timestamps,
- per-rule **delta** hit counts (cur snapshot minus previous, so each
  report describes its window, not the cumulative state),
- 5 uniformly-random redacted samples via Vitter's Algorithm R
  reservoir sampling (bounded memory regardless of workload throughput),
- skipped on idle windows to avoid littering disk.

Customers run for 24h, audit the JSON, then flip `--privacy-mode` to
`standard` once satisfied.

### `data_masks/redactor.go` (rewritten)

- All redaction call sites now route through
  `Redactor.styledReplacement()` so the choice between `*REDACTED*` and
  hash-token is global, not per-rule.
- A new `privacyModeVisitor` runs AFTER the standard redaction pass to
  apply `DropBodies` + `HeaderAllowlist`.
- The `AUTH` and `COOKIE` value-type sentinels now also bump the
  matching `CoverageCounters` entry so the dashboard reflects them.
- `RedactSensitiveData` bumps `RequestsScanned` once per call.

### Build hygiene

- New `ebpf/discovery/kube_stub.go` (non-Linux build tag): fixes a
  pre-existing macOS build break in `apidump/ebpf_integration.go`. The
  codebase now compiles cross-platform without `-tags`.

## Wiring

The `--privacy-mode` flag was previously documented as "passthrough;
full effect lands in Phase 4". It is now an enforced setting:

```bash
$ postman-insights-agent apidump --enable-https-capture \
    --privacy-mode=strict \
    --redaction-style=hash

# Agent log:
INFO data masks: privacy-mode=strict redaction-style=hash upload=true
```

For dry-run mode:

```bash
$ postman-insights-agent apidump --enable-https-capture \
    --privacy-mode=dry-run \
    --dry-run-dir=/var/log/postman-insights

INFO data masks: privacy-mode=dry-run redaction-style=redact upload=false
INFO dry-run mode active — redaction reports will be written to /var/log/postman-insights, no uploads to backend
```

## Test coverage

| Test | What it asserts |
|---|---|
| `TestParsePrivacyMode` | `standard`/`strict`/`dry-run` parse; case-insensitive; unknown values error |
| `TestPrivacyModeConfig` | strict drops bodies; strict rejects `Authorization` + `Host`; dry-run disables upload but keeps bodies |
| `TestHeaderAllowed_EmptyMeansAll` | Empty allowlist accepts everything (standard mode) |
| `TestParseRedactionStyle` | `redact`/`hash` parse; case-insensitive |
| `TestApplyRedactionStyle` | StyleRedact = fixed string; StyleHash = deterministic + 16-hex-char prefix; different inputs produce different hashes |
| `TestCoverage_NilSafe` | All `Inc*` methods no-op on nil receiver |
| `TestCoverage_Counts` | All counter types increment correctly |
| `TestCoverage_Concurrent` | 100 goroutines × 1000 increments = exact 100,000; no lost updates |
| `TestSensitiveCorpus_FieldNames` | Every default sensitive key triggers redaction (case-insensitive) |
| `TestSensitiveCorpus_Values` | 14 known-sensitive values all caught by built-in regexes |
| `TestSafeCorpus_FalsePositives` | 36 "safe" strings all pass through; 0 false positives |
| `TestCoverageCounters_IncrementOnHit` | Hitting a sensitive key bumps the per-key counter; dashboard contract |

Plus the 11 pre-existing redaction tests that still pass.

## What customers can demo / audit today

```
$ postman-insights-agent apidump --enable-https-capture \
    --privacy-mode=dry-run --duration 1h

# Wait an hour. Inspect:
$ ls /var/log/postman-insights/
dry-run-20260513T100000Z.json
dry-run-20260513T100100Z.json
...

$ cat /var/log/postman-insights/dry-run-20260513T100000Z.json
{
  "window_start": "2026-05-13T10:00:00Z",
  "window_end":   "2026-05-13T10:01:00Z",
  "requests_scanned": 4823,
  "redactions": {
    "header.authorization": 4821,
    "header.cookie":        4823,
    "regex.builtin[5]":       12
  },
  "body_truncations": 71,
  "samples": [
    {
      "method": "POST",
      "path":   "/api/users",
      "status_code": 201,
      "redacted_headers": {
        "authorization": "*REDACTED*",
        "content-type":  "application/json"
      },
      "redacted_body": "{ \"email\": \"*REDACTED*\", ... }"
    }
  ]
}
```

The customer's compliance officer audits the JSON. When satisfied,
flip `--privacy-mode=standard` and the same redaction continues but
uploads resume.

## What's still open (and why deferred)

### Task 2 (redactor-side body-truncation metadata)

The BPF layer already enforces the cap. The Phase 4 brief calls for
the redactor to additionally decorate the output with
`{_truncated: true, _original_length: N}`. Deferred because:

- the BPF-layer cap already prevents oversize bodies from reaching
  the redactor at all (the metadata is informational, not protective),
- backend support for the synthetic field needs coordination with
  the Postman backend team,
- no customer has asked for it yet.

### Task 4 (discovery-config `decrypt: false`)

The `--target-namespaces` flag (Phase 2) already provides
per-namespace opt-out at the discovery layer — eBPF probes simply
don't attach to non-target namespaces. The Phase 4 brief's
`decrypt: false` is a different (more granular) opt-out via the
discovery-config YAML schema. Both reach the same goal; deferred until
a customer requests the YAML form.

## Commit reference

| Commit | Summary |
|---|---|
| `fad8e3d` | Tasks 1+3+5+6+7: privacy modes, tokenization, coverage counters, dry-run reporter |
| `<this commit>` | Tasks 8+9: customer-facing security docs + regression corpus |

## Handoff

Updated:
- [`docs/progress.md`](../progress.md) — Phase 4 status ✅ for 5 gaps; overall program ~70% complete
- [`ebpf/README.md`](../../ebpf/README.md) — privacy hardening row updated (next commit)
- [`docs/phases/SESSION-RESUME.md`](SESSION-RESUME.md) — next-task recommendation updated to Phase 3 #4 (stripped binaries) or Phase 5 (Java)

What's left for the program (not Phase 4):
- Phase 3 task #4: stripped-binary pclntab fallback (production Go builds use `-ldflags="-s -w"`)
- Phase 3 task #5: multi-Go-version test matrix
- Phase 3 task #6: multi-layer dedup (`net/http` + `crypto/tls` + `net.netFD`)
- Phase 5: Java agent + ioctl bridge + mutating webhook (largest remaining piece)
