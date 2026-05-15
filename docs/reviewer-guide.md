# Reviewer's guide — HTTPS capture via eBPF

**Audience:** engineers about to look at PR #174 and PR #173.
**Goal:** orient you in ~10 minutes so the big diffs don't feel like a wall of code.
**TL;DR:** there are two stacked PRs. #174 is the production-ready slice and should be reviewed first. #173 sits on top and includes Go support + privacy work + Java foundation; it's larger and has more "spike" code, so skim some parts and read others carefully — pointers below.

---

## What this whole thing is

A multi-phase program to capture decrypted HTTPS traffic via eBPF and
feed it into the existing `apidump` pipeline. **Full design lives in
[`https-capture-design.md`](https-capture-design.md)** (30 min read — do
this once; you won't need it again per-PR).

Five phases were planned. As of today the state is:

| Phase | What it does | Status | Lives in |
| --- | --- | :---: | --- |
| 1 | libssl spike — decrypted bytes reach `trace.Collector` | ✅ | PR #174 |
| 2 | Production integration into `apidump` + kind e2e | ✅ | PR #174 |
| 3 | Go support via DWARF + `crypto/tls` uprobes + HTTP/2 + gRPC | ✅ ~95% | PR #173 |
| 4 | Privacy & redaction (the 8 design-doc gaps) | ✅ 5/8 + dry-run | PR #173 |
| 5a | Java eBPF foundation — `sys_ioctl` kprobe + C harness | ✅ | PR #173 (local — not yet pushed at time of writing) |
| 5b/5c | Java agent + framework matrix + admission webhook | ❌ next sessions | future PRs |

Per-phase results docs exist for each green row above — they are the
**single most useful thing to read** before reviewing the code:

```
docs/phases/phase-1-results.md
docs/phases/phase-2-results.md
docs/phases/phase-3-results.md
docs/phases/phase-4-results.md
docs/phases/phase-5a-results.md
```

Each lists exit criteria, what passed, what didn't, and the evidence.

---

## How the PRs are stacked

```
main
  │
  ├─ PR #174 ─ feat/https-capture-ebpf-libssl  (17 commits, +8013/-33, 70 files)
  │            "the libssl path — Phases 1+2"
  │            ← REVIEW THIS FIRST. Ships independently.
  │
  └─ PR #173 ─ feat/https-capture-ebpf         (32 commits, +14193/-54, 110 files)
               "Phase 3 (Go) + Phase 4 (privacy) + Phase 5a"
               ← The first 17 commits are #174's.
                 GitHub will narrow this diff to the remaining 15-ish
                 commits once #174 merges.
```

So **the actual Phase 3+4+5a-only diff is +7657 LOC across 59 files** —
manageable once #174 is out of the way.

> ⚠️ **Branch drift to fix before review:** PR #174's branch has one
> commit (`12b0c55` — non-Linux stub for `KubeNamespaceResolver`) that
> isn't in PR #173's branch. Trivial cherry-pick; flag it but don't let
> it block review.

---

## Suggested review order

### 1. Read the design doc (30 min, one time)

[`docs/https-capture-design.md`](https-capture-design.md). Skip to §3
(architecture diagram) first, then §6 (sampling & rate caps), then §7
(privacy), then §9 (phased delivery). The rest is reference material.

### 2. Review PR #174 (libssl path — Phases 1+2)

**Why first:** smaller, more polished, has 6/6 exit criteria green
including a real kind-cluster end-to-end demo. It can merge to `main`
on its own; doing so makes PR #173 immediately smaller.

**Read carefully:**

| File | What it is | Why care |
| --- | --- | --- |
| `ebpf/programs/libssl.bpf.c` | The kernel-side uprobes on `SSL_read`/`SSL_write`/etc. | This is the only BPF C in #174. Verifier complexity, max event payload, telemetry counters all live here. |
| `ebpf/programs/event.h` | The shared C/Go ABI for `struct ssl_event` | Tiny, but **ABI-stable**. Any change must be mirrored in `ebpf/events/event.go`. |
| `ebpf/loader/loader_linux.go` | Loads BPF, exposes maps/programs to userspace | Reasonably standard cilium/ebpf usage. Note: rate-bucket refill semantics. |
| `ebpf/events/adapter.go` | Bytes → `akinet.ParsedNetworkTraffic` per (PID, SSLCtx, direction) flow | The "where do bytes meet the existing pipeline" hinge. |
| `ebpf/discovery/kube_linux.go` | CRI + cgroup-namespace-inode trick for K8s namespace filtering | Non-obvious. The README in there explains why `hostPID: true` alone is insufficient. |
| `ebpf/thermostat_linux.go` | CPU-budget feedback loop that throttles `max_capture_bytes` | New runtime control. Worth checking the hysteresis math. |
| `apidump/apidump.go` | `--enable-https-capture` flag wiring | Where the existing command grows the new mode. |

**Skim (no need to read line-by-line):**

* `ebpf/loader/libssl_arm64_bpfel.{go,o}` — bpf2go-generated, do not
  hand-edit. (amd64 generated in CI.)
* `test/kind/*.yaml` — kind-cluster e2e manifests. Look at
  `agent-daemonset.yaml` once to understand the deploy shape; skip the rest.
* All `*_test.go` — confirm coverage exists, don't read every assertion.

**Validation that already happened** (from `phase-1-results.md` +
`phase-2-results.md`):
* Local: real curl → real nginx → captured.
* Kind cluster: 3-namespace e2e (`team-py`, `team-node`, `team-srv`),
  DaemonSet deploy, namespace filtering working, BPF counters reported
  via telemetry.

**Estimated review time:** 90 min if you read the design doc first; 2-3
hours if you read everything carefully.

### 3. Review PR #173 (Phase 3 Go + Phase 4 privacy + Phase 5a Java foundation)

**Why second:** stacked on #174. Has more code, more spike-flavor
commands, and some intentionally-deferred items. Once #174 lands GitHub
will collapse this PR to the ~16 commits / +7657 LOC of net-new work.

**Read carefully (Phase 3 — Go support):**

| File | What it is | Why care |
| --- | --- | --- |
| `ebpf/programs/gotls.bpf.c` | Uprobes on `crypto/tls.(*Conn).Write` and RET-probing for `Read` | The non-obvious part: **Go uretprobes don't work** (runtime moves stacks). We attach a one-shot uprobe at every RET instruction. Disassembler trick. |
| `ebpf/goexec/` | DWARF/symtab inspector + pclntab fallback for stripped binaries | Hand-rolled because cilium/ebpf doesn't cover stripped Go. Has a real amd64 disassembler for RET-finding. |
| `ebpf/events/http2.go` | HTTP/2 frame decoder + HPACK | Go's `net/http` defaults to h2 over TLS. Without this, decoded h2 looks like binary noise. |
| `ebpf/events/http2_grpc*.go` (or equivalent in adapter) | gRPC length-prefixed framing parsed out of h2 DATA frames | Lets us identify gRPC methods on the wire without per-Go-version DWARF coupling. |

**Read carefully (Phase 4 — privacy):**

| File | What it is | Why care |
| --- | --- | --- |
| `data_masks/` (5/8 gaps land here) | Adds privacy modes (`strict` / `dry-run`), per-field tokenization, expanded redaction corpus | This is the path to "production-safe for finance/enterprise customers". The dry-run mode is what unblocks security review. |
| `docs/redaction-defaults.md` | The customer-facing redaction guarantees | One-time read; confirm we're comfortable with the contract. |

**Skim or skip:**

* `cmd/internal/apidump-gotls/` — hidden spike CLI for Phase 3
  validation, NOT a user-facing command. Skim the `init()` flags only.
* `cmd/internal/apidump-javatls/` — same shape as above, Phase 5a
  validation only. Skim only.
* `ebpf/programs/java_tls.bpf.c` — Phase 5a kernel side. **There is no
  Java agent yet** — this program is driven by a C harness in
  `test/java-tls-harness/`. Read the file header comment for context,
  skim the rest.
* `ebpf/loader/{gotls,javatls}_arm64_bpfel.{go,o}` — generated.
* `test/gomatrix/`, `test/java-tls-harness/` — test fixtures.
* All `phase-N-results.md` docs — recommended, but they're docs not code.

**Known limitations explicitly documented in this PR (NOT bugs to file):**

1. **Static-libssl Node 20 / Envoy** — Phase 3 task #4 closes this for
   Go; Node remains open (no `libssl.so` in `/proc/<pid>/maps`).
2. **Privacy gaps 6, 7, 8** — three of the eight design-doc privacy
   gaps remain. They are listed in `phase-4-results.md`; production
   gating still says "trial customers only."
3. **gRPC method names** — captured via wire-format parsing; richer
   message decoding deferred (would need per-Go-version grpc-package
   DWARF; the design doc explains why we said no for v1).
4. **Phase 5 Java** — only the kernel side and a C harness are in this
   PR. There is **no Java agent** yet. The wire format is frozen at
   OBI's 41-byte packed header so 5b's Java agent (next session) plugs
   in without changing anything here.

**Estimated review time:** 4-6 hours if reading carefully. With the
"skim spike CLIs and generated files" approach, 2-3 hours.

---

## What to verify before approving

For #174:
* [ ] BPF verifier complexity is documented (counters in `phase-1-results.md`).
* [ ] `make build` (without `insights_bpf` tag) still compiles on macOS / Linux.
* [ ] `make build-ebpf` builds in the dev container.
* [ ] `make test` passes (CI does this on every push).
* [ ] CRI / cgroup-namespace path is documented (the trick in
      `ebpf/discovery/kube_linux.go`).
* [ ] `--enable-https-capture` is opt-in and off by default.

For #173:
* [ ] Same compile / test gates as #174.
* [ ] `apidump-gotls` and `apidump-javatls` are `Hidden: true` and have
      help text marking them as spike commands.
* [ ] `data_masks` test coverage hasn't regressed.
* [ ] The three open privacy gaps (6/7/8) are documented in
      `phase-4-results.md` and not silently in-flight.

---

## Pitfalls I'd specifically warn reviewers about

1. **The "Go uretprobes don't work" insight** is buried in
   `gotls.bpf.c` and `goexec/` — if you ask "why this hand-rolled
   disassembler?" the answer is there. Don't try to "fix" it with
   ordinary uretprobes.
2. **HTTP/2 is Go's default over TLS** — if you see "captures look
   like binary garbage" in your local test, check that `events/http2.go`
   is in the pipeline. Documented but easy to forget.
3. **Cgroup paths inside containers show `0::/../..`** — this is NOT
   just a kind quirk; it's the default on K8s 1.24+ with containerd.
   The CRI + cgroup-namespace-inode bridge in
   `ebpf/discovery/kube_linux.go` is the fix. Replacing it with
   "just use cgroup paths" will break on real clusters.
4. **`bpf2go` outputs are host-arch only.** PRs ship `*_arm64_bpfel.*`;
   amd64 must be `go generate`d on a Linux/amd64 host. CI handles this;
   reviewers on Mac will see stale arm64 files only.
5. **The `--privacy-mode` flag is a passthrough until Phase 4's
   remaining 3 gaps land.** It's wired end-to-end but `strict` and
   `dry-run` don't yet enforce everything the design doc lists. See
   `phase-4-results.md` for the per-gap matrix.

---

## "But it's still a huge PR" — alternatives we considered

Documented in [`progress.md`](progress.md) "PR strategy" section:

* **Single PR for everything (the original plan).** Rejected once the
  diff crossed ~12k LOC.
* **One PR per phase.** Rejected because Phases 1+2 are tightly coupled
  (Phase 2 wires the adapter Phase 1 produces bytes for; splitting them
  risks Phase 2 guessing at byte formats).
* **Two stacked PRs (#174 + #173) — chosen.** Phases 1+2 ship
  independently in #174; everything else stacks behind it. This is
  where we are.
* **Three+ PRs (split #173 further).** On the table for Phase 5b/5c
  but not today — Phase 3 and Phase 4 are entangled enough (Phase 3's
  Go captures feed Phase 4's redactor) that splitting them now would
  add merge friction without reducing review surface much.

If after a first pass you still feel #173 is too large to review with
confidence, see [`merge-vs-review.md`](merge-vs-review.md) for the
"land on a long-lived branch and let folks test the binary" option.
