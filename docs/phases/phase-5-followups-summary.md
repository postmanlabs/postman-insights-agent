# Follow-up backlog — closure summary

After Phase 5c.3c the program had five tracked follow-ups, none on the
launch-blocking path. This document records the closure of all five.

**Branch:** `feat/https-capture-ebpf` (rolling PR #173).

| # | Item | Commit | Notes |
| --- | --- | --- | --- |
| 1 | ByteBuddy 1.14.13 → 1.17.5 + Shadow plugin bump (closes runbook LIMIT-1) | `dede34c` | Agent now transforms classes on JDK 25. Verified end-to-end against `tomcat:10` (which ships JDK 25.0.3 LTS). JAR size: 4.77 MB → 9.87 MB. |
| 2 | `keytool` / `jar` / `javac` subprocess agent-attach skip (closes runbook LIMIT-2) | `bac822a` | New `Agent.shouldSkipForCliToolJVM()` detects 21 JDK CLI tools by `sun.java.command`. 20 JUnit tests cover positive matches, real-workload negatives, edge cases. `-Dpostman.agent.force=true` escape hatch. |
| 3 | JMH per-call microsecond benchmark | `17337a8` | New isolated subproject `java-agent/benchmarks/`. Measured per-call overhead: ~700 ns at 64 B, ~900 ns at 1 KB, ~3.9 µs at 16 KB. Well under 10 % of the SSL wrap cost. |
| 4 | Per-namespace `privacyMode` override (extends gap-4 YAML schema, **full enforcement**) | `5fe23be` | Schema + plumbing + redactor changes atomic. 21 new tests. Namespace plumbed from BPF event → witness → redactor via existing `ifaceTag` + new `BackendCollector.SetNamespaceResolver` callback. |
| 5 | CI smoke test for Helm chart | this commit | New `helm-smoke` CircleCI job: helm lint + render in both TLS modes + fail-fast on missing required values + safety-property grep (`failurePolicy: Ignore`, `sideEffects: None`, `timeoutSeconds: 5`). |

## Why item 5 is "smoke" rather than "full kind e2e"

Full kind cluster spin-up in CI is expensive: docker-in-docker, image
load, sleeping for pods to converge, etc. — easily 5+ minutes per PR.
Per `phase-5c3c-results.md` the full kind procedure is documented as a
manual operator workflow in `docs/webhook-runbook.md` instead.

The smoke test still catches the **majority** of chart breakage:
* Lint failures (most common contributor mistake).
* Template-render failures (Helm-template-syntax errors).
* Missing-required-value regressions.
* Drift from the safety properties (`failurePolicy: Ignore`,
  `sideEffects: None`, `timeoutSeconds: 5`) — a contributor flipping
  any of these to a less-safe value without rehearsed rollback will
  be blocked at PR time.

## Program status after this backlog

The HTTPS-capture-via-eBPF program reaches steady state:

* All 8 design doc §7.3 privacy gaps closed (Phase 4 + Phase 4b + Phase 4c).
* All Java + webhook track milestones shipped (Phase 5a, 5b.1–5b.3, 5c.1, 5c.2, 5c.3a–c).
* All five known follow-ups closed (Phases above).

What remains is genuinely out-of-scope work (rustls support, Node/Python
tier-3, full kind e2e in CI) — none blocking the original plan.

## CI job details

`helm-smoke` runs in parallel with the existing `build` job:

* **Runtime:** ~30 s (single `cimg/base:stable` container; helm tarball install).
* **Independent failure surface:** if `helm-smoke` fails, the Go build keeps running. Each job's logs are independently inspectable.
* **Artifacts:** rendered YAMLs (`helm-rendered-secret-mode.yaml`, `helm-rendered-cert-manager-mode.yaml`) saved to CircleCI artifacts for post-mortem when something does drift.

## What this commit DOES NOT change

* No new YAML files in the chart (the helm-smoke job re-renders the
  existing chart from scratch).
* No new Helm chart dependencies.
* No new runtime dependencies for the agent itself — `helm-smoke` is
  CI-only.

## Local validation before commit

Same checks the CI job runs, executed locally:

```
=== Step 1: helm lint ===
1 chart(s) linted, 0 chart(s) failed

=== Step 2: helm template (secret mode) + safety checks ===
  rendered      166 lines
  ✓ has kind: ServiceAccount
  ✓ has kind: Service
  ✓ has kind: Deployment
  ✓ has kind: MutatingWebhookConfiguration
  ✓ failurePolicy: Ignore
  ✓ sideEffects: None
  ✓ timeoutSeconds: 5

=== Step 3: helm template (cert-manager mode) + safety checks ===
  rendered      204 lines
  ✓ Certificate resource present
  ✓ inject-ca-from annotation present
  ✓ no inline caBundle (correct for cert-manager mode)

=== Step 4: fail-fast (missing required value) ===
  ✓ fail-fast on missing caBundle (expected behavior)
```

YAML structure validation:

```
  jobs: build helm-smoke
  workflow ci.jobs: build helm-smoke
  helm-smoke steps: 8
YAML valid
```
