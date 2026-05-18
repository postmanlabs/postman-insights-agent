# Reviewer's guide — HTTPS capture via eBPF

**Audience:** engineers and the external eBPF consultant reviewing PR #173.
**Goal:** orient you in ~10 minutes so the big diff doesn't feel like a wall of code.
**TL;DR:** the rolling integration branch (`feat/https-capture-ebpf`, PR #173)
now contains Phases 1 through 5b — the complete program except for Phase 5c
(framework matrix + admission webhook, separate PR later). PR #174 still exists
but is a strict subset of PR #173 and is kept open for historical reference only.
Review happens on this single branch, not against `main`.

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

## Where the work lives

```
main
  │
  ├─ PR #174 ─ feat/https-capture-ebpf-libssl  (17 commits, +8013/-33, 70 files)
  │            "the libssl path — Phases 1+2"
  │            STATUS: open, but strict subset of PR #173. Can be closed.
  │
  └─ PR #173 ─ feat/https-capture-ebpf         (35+ commits, ~+18k/-54, ~140 files)
               "Phases 1–5b complete"
               ← REVIEW HERE. Single integration surface.
```

The branches are content-equivalent for everything in PR #174 — PR #173's
branch is a strict superset (it contains every Phase 1+2 change plus all the
later phases). There's nothing in PR #174 that isn't already in PR #173.

Reviewers don't need to context-switch between PRs. **All review activity
happens on PR #173 / the `feat/https-capture-ebpf` branch.**

---

## Suggested review order

### 1. Read the design doc (30 min, one time)

[`docs/https-capture-design.md`](https-capture-design.md). Skip to §3
(architecture diagram) first, then §6 (sampling & rate caps), then §7
(privacy), then §9 (phased delivery). The rest is reference material.

### 2. Skim the per-phase results docs (~30 min total)

Each phase has a results doc with what passed, what didn't, and the
evidence. Reading these first scopes the rest of the review:

* [`phase-1-results.md`](phases/phase-1-results.md) — libssl spike
* [`phase-2-results.md`](phases/phase-2-results.md) — production integration
* [`phase-3-results.md`](phases/phase-3-results.md) — Go support
* [`phase-4-results.md`](phases/phase-4-results.md) — privacy hardening
* [`phase-5a-results.md`](phases/phase-5a-results.md) — Java kernel foundation
* [`phase-5b1-results.md`](phases/phase-5b1-results.md) — Java JNI bridge
* [`phase-5b2-results.md`](phases/phase-5b2-results.md) — Java ByteBuddy advice
* [`phase-5b3-results.md`](phases/phase-5b3-results.md) — Java hardening

### 3. Review the eBPF core (consultant's primary focus)

**Why this matters:** these are the files an external eBPF consultant
should scrutinise most carefully — they're the program's load-bearing
architecture. Tests and Go scaffolding can be skimmed; this cannot.

**Read carefully (BPF C — the kernel side):**

| File | What it is | Why care |
| --- | --- | --- |
| `ebpf/programs/libssl.bpf.c` | Uprobes on `SSL_read`/`SSL_write`/etc. | Verifier complexity, max event payload, telemetry counters all live here. |
| `ebpf/programs/gotls.bpf.c` | Go `crypto/tls.(*Conn).Write` + Read RET probing | Non-obvious: Go uretprobes don't work (stack moves) — we attach at every RET instruction. |
| `ebpf/programs/java_tls.bpf.c` | `sys_ioctl` kprobe filtering on fd=0 + magic cmd | The Java bridge. Pairs with the JNI shim in `java-agent/`. |
| `ebpf/programs/event.h` | The shared C/Go ABI for `struct ssl_event` | Tiny, but **ABI-stable**. Any change must be mirrored in `ebpf/events/event.go`. |

**Read carefully (loaders, events, discovery):**

| File | Why care |
| --- | --- |
| `ebpf/loader/loader_linux.go` + `loader_gotls_linux.go` + `loader_javatls_linux.go` | cilium/ebpf usage. Rate-bucket refill semantics. Per-target attach handles. |
| `ebpf/events/adapter.go` | Bytes → `akinet.ParsedNetworkTraffic` per (PID, SSLCtx, direction) flow. The hinge. |
| `ebpf/events/http2.go` | HTTP/2 frame decoder + HPACK. Required because Go's `net/http` defaults to h2 over TLS. |
| `ebpf/goexec/` | Hand-rolled DWARF/symtab/pclntab inspector + amd64 disassembler. Cilium/ebpf can't handle stripped Go. |
| `ebpf/discovery/kube_linux.go` | CRI + cgroup-namespace-inode trick for K8s namespace filtering. Non-obvious. |
| `ebpf/thermostat_linux.go` | CPU-budget feedback loop. Throttles `max_capture_bytes` at runtime. Check the hysteresis math. |

**Read carefully (Java agent, Phase 5b):**

| File | Why care |
| --- | --- |
| `java-agent/src/main/java/.../Agent.java` | premain entry. Bootstrap CL append + `redefineModule`. Standard but subtle. |
| `java-agent/src/main/java/.../instrumentations/SSLEngineInst.java` | ByteBuddy advice on the 4-arg `wrap`/`unwrap`. `suppress = Throwable.class` discipline. |
| `java-agent/src/main/java/.../ebpf/NativeMemory.java` | Off-heap allocator + JNI loader + thread-local 64 KiB buffer. Handles double-load edge case. |
| `java-agent/build.gradle.kts` | The two-JAR split (bootstrap helpers separate from ByteBuddy) — explained in `phase-5b2-results.md`. |

**Read carefully (privacy, Phase 4):**

| File | Why care |
| --- | --- |
| `data_masks/privacy_mode.go` + `coverage.go` + `tokenization.go` + `dry_run.go` | The customer-facing privacy guarantees. Production gating until Phase 4 finishes. |
| `docs/redaction-defaults.md` + `docs/security-permissions.md` + `docs/https-data-flow.md` | Customer security docs — confirm we're comfortable with these contracts. |

**Skim (no need to read line-by-line):**

* `ebpf/loader/*_arm64_bpfel.{go,o}` — bpf2go-generated, do not hand-edit.
  CI re-runs `go generate` on amd64.
* `test/kind/*.yaml`, `test/gomatrix/*`, `test/java-tls-harness/*` — test
  fixtures and harnesses. Skim once to understand the validation shape.
* `cmd/internal/{apidump-ebpf,apidump-gotls,apidump-javatls}/` — hidden
  spike subcommands, NOT user-facing. Skim flag lists only.
* All `*_test.go` — confirm coverage exists, don't read every assertion.
* All generated / shaded code under `com/postman/insights/agent/shaded/`.

**Estimated review time for the eBPF core:** 90 min skimming + reading
the results docs; 3–6 hours reading carefully.

### 4. Review the rest (Go, privacy, Java)

Once the BPF core is reviewed, the remaining areas are application-level
Go code, Java agent code, and tests. Coverage is high and patterns are
standard — review at whatever depth feels useful given confidence in the
BPF core.

**Known limitations explicitly documented in this branch (NOT bugs to file):**

1. **Static-libssl Node 20 / Envoy** — Phase 3 task #4 closes this for
   Go; Node remains open (no `libssl.so` in `/proc/<pid>/maps`).
2. **Privacy gaps 6, 7, 8** — three of the eight design-doc privacy
   gaps remain. They are listed in `phase-4-results.md`; production
   gating still says "trial customers only."
3. **gRPC method names** — captured via wire-format parsing; richer
   message decoding deferred (would need per-Go-version grpc-package
   DWARF; the design doc explains why we said no for v1).
4. **Java framework matrix** — only JDK 17 with `HttpsServer` is
   validated in Phase 5b. Spring Boot, gRPC-Java, Tomcat, Jetty, and
   JDK 8 / 11 / 21 are explicitly deferred to Phase 5c.
5. **Admission webhook** — not yet built. Phase 5c.

**Estimated total review time:** 4-8 hours for engineers; eBPF
consultant should plan 1-2 days for a thorough audit of the BPF
programs + loaders + events pipeline.

---

## What to verify before approving

* [ ] `make build` (without `insights_bpf` tag) compiles on macOS / Linux.
* [ ] `make build-ebpf` builds in the dev container.
* [ ] `make test` passes (CI does this on every push).
* [ ] BPF verifier complexity is documented (counters in `phase-1-results.md`
      and `phase-5a-results.md`).
* [ ] `--enable-https-capture` is opt-in and off by default.
* [ ] CRI / cgroup-namespace path is documented (`ebpf/discovery/kube_linux.go`).
* [ ] `apidump-{ebpf,gotls,javatls}` spike commands are all `Hidden: true`.
* [ ] `data_masks` test coverage hasn't regressed.
* [ ] The three open privacy gaps (6/7/8) are documented in
      `phase-4-results.md` and not silently in-flight.
* [ ] Java agent's `suppress = Throwable.class` discipline is enforced on
      every `@Advice.OnMethodExit` (`SSLEngineInst.java`).

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

## "But it's still a huge PR" — the unified-branch approach

We explored a multi-PR split (see [`merge-vs-review.md`](merge-vs-review.md)
for the history) but ultimately consolidated on a single review surface:
`feat/https-capture-ebpf` (PR #173). Rationale:

* An external eBPF consultant joins the review — they want one branch,
  not two stacked PRs.
* Per-phase results docs in `docs/phases/` already give reviewers a way
  to consume the work incrementally without needing GitHub PR splits.
* `main` stays untouched until Phase 5c is ready. Engineers and the
  consultant build + test off this branch directly; no merge pressure.

If you want to build and run the agent now:
```bash
git fetch origin
git checkout feat/https-capture-ebpf
make build-ebpf
# Optional: java-agent build (in the dev container)
cd java-agent && make -C src/main/c && gradle --no-daemon shadowJar
```
