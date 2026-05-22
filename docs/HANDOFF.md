# HTTPS-capture-via-eBPF — Engineer Handoff

**This is the single document the engineer taking over the work stream should
read first. It is intentionally long; everything you need to be productive in
this codebase is either here, or one link away.**

**Branch:** `feat/https-capture-ebpf`
**PR:** [#173](https://github.com/postmanlabs/postman-insights-agent/pull/173) (the single rolling PR — do NOT create sub-branches)
**Latest commit:** `ad177b3` (CI helm-smoke; closes the follow-up backlog)
**Status:** feature-complete at the original design-doc spec; in steady state.

---

## 0. Read these in order

1. **THIS document** (you're already here) — full context map.
2. [`https-capture-design.md`](https-capture-design.md) — the 12-section
   architecture / research doc. 30-min read. Every Phase-N session brief
   referenced it.
3. [`progress.md`](progress.md) — short status overview + program-wide
   PR structure.
4. [`phases/SESSION-RESUME.md`](phases/SESSION-RESUME.md) — the per-session
   resume notes including the verification rules that were learned the hard
   way. Read the "PRE-COMPACTION HANDOFF" section first.
5. [`phases/phase-5-followups-summary.md`](phases/phase-5-followups-summary.md)
   — the post-launch follow-up closure record.
6. [`webhook-runbook.md`](webhook-runbook.md) — the SRE doc for the
   mutating admission webhook.

After those six docs, you should know everything we know.

---

## 1. What's in this branch (the 30-second version)

| Phase | What it is | Status | Results doc |
|---|---|:---:|---|
| 1 | libssl uprobe spike (proof of concept) | ✅ | [phase-1-results](phases/phase-1-results.md) |
| 2 | Production integration in `apidump`; kind e2e | ✅ | [phase-2-results](phases/phase-2-results.md) |
| 3 | Go support via DWARF + crypto/tls uprobes | ✅ | [phase-3-results](phases/phase-3-results.md) |
| 4 | Privacy hardening — 6 of 8 §7.3 gaps | ✅ | [phase-4-results](phases/phase-4-results.md) |
| 4b | Close gaps 2 + 4 (body truncation metadata + per-namespace YAML) | ✅ | [phase-4b-results](phases/phase-4b-results.md) |
| 4c | Per-namespace `privacyMode` override (full enforcement) | ✅ | [phase-4c-results](phases/phase-4c-results.md) |
| 5a | eBPF `sys_ioctl` kprobe + C harness | ✅ | [phase-5a-results](phases/phase-5a-results.md) |
| 5b.1 | Java→ioctl bridge spike | ✅ | [phase-5b1-results](phases/phase-5b1-results.md) |
| 5b.2 | ByteBuddy + `SSLEngineInst` | ✅ | [phase-5b2-results](phases/phase-5b2-results.md) |
| 5b.3 | Java agent hardening | ✅ | [phase-5b3-results](phases/phase-5b3-results.md) |
| 5c.1 | Spring Boot + Netty | ✅ | [phase-5c1-results](phases/phase-5c1-results.md) |
| 5c.2 | Tomcat + Jetty + gRPC + JDK 8/11/17/21 matrix | ✅ | [phase-5c2-results](phases/phase-5c2-results.md) |
| 5c.3a | K8s mutating admission webhook (Go code) | ✅ | [phase-5c3a-results](phases/phase-5c3a-results.md) |
| 5c.3b | Webhook end-to-end in kind cluster | ✅ | [phase-5c3b-results](phases/phase-5c3b-results.md) |
| 5c.3c | Helm chart + SRE runbook | ✅ | [phase-5c3c-results](phases/phase-5c3c-results.md) |
| follow-ups | 5 backlog items (ByteBuddy bump, CLI-tool skip, JMH, per-ns privacyMode, CI smoke) | ✅ | [phase-5-followups-summary](phases/phase-5-followups-summary.md) |

---

## 2. The PR — review and merge story

* **PR #173** is the single review surface. It contains everything from
  Phase 1 through the follow-ups: ~50 commits, large diff.
* **PR #174 is closed** (was a subset of #173 before we consolidated).
* The external eBPF consultant reviews #173. There is **no separate review
  for sub-phases.**
* If reviewers ask for the work to be split, that ship has sailed —
  splitting now would mean rewriting history. Better to provide the
  per-phase results docs as the per-phase narrative and let them review
  by reading those alongside the diff.

### Pre-review checklist (what to verify before asking for review)

```sh
# Mac build
go build ./...                                 # exit 0 expected

# Linux full suite (in dev container — see §4)
make build-ebpf                                # exit 0 expected
make test                                      # 14 ok / 0 fails

# Java agent build
cd java-agent && gradle --no-daemon clean shadowJar
ls build/libs/postman-java-agent.jar           # ~9.87 MB

# Helm chart still passes its own CI checks
docker run --rm -v $(pwd)/deployment/helm:/charts alpine/helm:3.14.0 \
    lint /charts/postman-insights-webhook      # 1 chart, 0 failed
```

All four are also automated:

* `make build` + `make test` run on every CircleCI build (job `build`).
* `helm lint` + render validation run on every CircleCI build (job `helm-smoke`).

### Likely reviewer feedback (informed guesses based on the work)

The external eBPF consultant is likely to ask about:

1. **CO-RE / kernel version compatibility.** We use libbpf's CO-RE pattern,
   regenerate `vmlinux.h` at deploy time per-cluster. See
   `test/kind/Dockerfile.agent` for the pattern.
2. **The `42 == answer` pattern for ioctl wire format on Java.** Why use
   ioctl + magic command number rather than perf-event mmap? Because OBI
   does, and it's the path of least resistance from a JVM (`Unsafe`
   off-heap memory + JNI). See [`phase-5b1-results.md`](phases/phase-5b1-results.md).
3. **The `failurePolicy: Ignore` default.** Reviewer may push for `Fail` for
   stronger guarantees. **Resist.** See `webhook-runbook.md` blast-radius
   section for why.
4. **Privacy: per-namespace overrides applying to pcap.** Pcap-sourced
   witnesses have no PID-encoded namespace, so they always use the global
   default. Documented in `discovery-mode.md`; mention proactively in PR
   description if you anticipate the question.
5. **GC behaviour of `Hooks.afterWrap2`.** Allocates one `byte[]` per call.
   Mitigation: BPF body-cap (default 1 KB) bounds allocation size. JMH
   numbers in [`java-agent/benchmarks/README.md`](../java-agent/benchmarks/README.md).

### Merge approach

When the reviewer signs off, the merge should be a **squash merge** of #173
into `main`. The commits in the branch are valuable as a narrative but
become noise in `main`'s history.

---

## 3. Repository tour — where each piece lives

```
postman-insights-agent/
├── main.go                                # Cobra root (trivial)
├── cmd/
│   ├── root.go                            # subcommand registration
│   └── internal/
│       ├── apidump/                       # main 'apidump' command + the new --https-* flags
│       ├── apidump-ebpf/                  # eBPF capture entry point (Linux only)
│       ├── apidump-gotls/                 # Go TLS capture entry point
│       ├── apidump-javatls/               # Java TLS capture entry point
│       ├── kube/                          # existing K8s subcommands (Workspace/Discovery onboarding)
│       └── kube-webhook/                  # NEW: the mutating admission webhook (Phase 5c.3a)
│           ├── cmd.go                     # Cobra command
│           ├── run.go                     # HTTPS server lifecycle + flag handling
│           ├── server.go                  # HTTPS server with /mutate + /healthz
│           ├── detect.go                  # Java workload detection (image regex + env + cmd)
│           ├── patch.go                   # JSON Patch construction (RFC 6902)
│           └── mutate.go                  # AdmissionReview decision logic
│
├── apidump/                               # Capture orchestration (what 'apidump' actually does)
│   ├── apidump.go                         # main pipeline (now ~1300 lines)
│   ├── ebpf_integration.go                # eBPF capture goroutine + KubeNamespaceResolver wiring
│   └── discovery_config.go                # NEW: YAML schema for per-namespace decrypt + privacyMode
│
├── ebpf/                                  # eBPF programs + loaders + adapters
│   ├── programs/                          # BPF C code (libssl, gotls, java_tls)
│   ├── loader/                            # bpf2go-generated wrappers
│   ├── events/                            # SSLEvent struct + Reader + Adapter (HTTP/1 + HTTP/2)
│   │   ├── adapter.go                     # Phase 1-2 core; now ALSO does truncation tagging
│   │   ├── truncation.go                  # NEW Phase 4b: synthetic-header injection
│   │   └── ...
│   └── discovery/                         # PID→namespace resolver
│
├── data_masks/                            # Privacy / redaction pipeline (Phase 4)
│   ├── privacy_mode.go                    # standard/strict/dry-run modes
│   ├── redactor.go                        # the actual redaction logic
│   ├── per_namespace_test.go              # NEW Phase 4c: lookup tests
│   └── ...
│
├── trace/                                 # Collector chain
│   ├── backend_collector.go               # Phase 1 hot path; NEW Phase 4c: SetNamespaceResolver
│   └── ...
│
├── java-agent/                            # Phase 5b — the Java agent (separate Gradle project)
│   ├── build.gradle.kts                   # ByteBuddy 1.17 + Shadow plugin
│   ├── src/main/java/com/postman/insights/agent/
│   │   ├── Agent.java                     # premain + CLI-tool-skip guard (Phase 5/follow-up 2)
│   │   ├── ebpf/                          # IoctlPacket, NativeMemory (JNI bridge)
│   │   ├── instrumentations/
│   │   │   ├── SSLEngineInst.java         # the workhorse — 5 method signatures hooked
│   │   │   └── JettySslEndPointInst.java  # Jetty 12 workaround
│   │   └── testdata/                      # HelloHttps + framework integration tests
│   ├── benchmarks/                        # NEW follow-up 3: JMH per-call benchmark
│   └── testdata/                          # Spring Boot / Tomcat / Jetty / gRPC fixtures
│
├── deployment/
│   └── helm/postman-insights-webhook/     # NEW Phase 5c.3c: production Helm chart
│       ├── Chart.yaml
│       ├── values.yaml                    # 130 lines, fully documented
│       ├── README.md                      # chart-level user docs
│       └── templates/                     # Deployment + Service + ServiceAccount + Webhook + Certificate
│
├── test/
│   └── kind/                              # kind cluster e2e infrastructure
│       ├── cluster.yaml
│       ├── Dockerfile.agent               # bundles BOTH Go agent AND Java agent JAR
│       ├── agent-daemonset.yaml           # libssl-path DaemonSet
│       ├── workloads.yaml                 # test pods
│       └── webhook/                       # Phase 5c.3b hand-rolled manifests (pre-Helm)
│           ├── README.md
│           ├── gen-tls-and-manifests.sh
│           ├── openssl.cnf
│           ├── webhook-deployment.yaml.tmpl
│           ├── webhook-config.yaml.tmpl
│           ├── capture-deployment.yaml
│           └── .gitignore                 # keys/certs NEVER committed
│
├── docs/
│   ├── https-capture-design.md            # ★ THE design doc
│   ├── HANDOFF.md                         # ★ THIS file
│   ├── progress.md                        # short status overview
│   ├── reviewer-guide.md                  # what reviewers should look at
│   ├── webhook-runbook.md                 # ★ SRE runbook
│   ├── discovery-mode.md                  # opt-in YAML schema + K8s onboarding
│   ├── https-data-flow.md                 # customer-facing data-flow diagram
│   ├── security-permissions.md            # customer-facing capability list
│   ├── redaction-defaults.md              # customer-facing redaction defaults
│   └── phases/                            # per-phase docs (read in order N → N-results)
│
└── .circleci/config.yml                   # build + helm-smoke jobs
```

---

## 4. Local development setup

### Dev container (Linux + libbpf + multi-JDK)

The whole eBPF + Java work happens inside a Docker container called
`pia-bpf-dev`. It has:

* JDK 17 at `/usr/lib/jvm/default-java` (default `java`).
* JDKs 8, 11, 21 at `/opt/jdks/jdk-{8,11,21}/`.
* Gradle 8.7.
* clang / libbpf-dev / bpftool.
* `mockgen` at `/go/bin/mockgen`.

To enter:

```sh
docker exec -it pia-bpf-dev bash -lc 'export PATH=/usr/local/go/bin:/go/bin:$PATH && cd /workspace && bash'
```

If the container isn't running: `docker start pia-bpf-dev`. If it doesn't
exist, see `build-scripts/Dockerfile.dev` to rebuild.

### Building (Mac host)

```sh
go build ./...                                 # builds for the host (no eBPF tag)
go test ./...                                  # runs tests that work cross-platform
make                                           # ditto, with the project's Makefile wrapping
```

### Building (Linux, with eBPF compiled in)

```sh
docker exec pia-bpf-dev bash -lc '
  export PATH=/usr/local/go/bin:/go/bin:$PATH
  cd /workspace
  make build-ebpf                              # go generate (bpf2go) + go build -tags insights_bpf
  make test                                    # full suite, includes data_masks corpus tests
'
```

### Java agent

```sh
cd java-agent
gradle --no-daemon clean shadowJar
# → build/libs/postman-java-agent.jar (~9.87 MB)
```

### Kind cluster (for webhook + DaemonSet e2e)

```sh
# Cluster name: pia-https-test
kind get clusters                              # should show pia-https-test
kubectl config use-context kind-pia-https-test

# If the cluster is gone:
kind create cluster --config test/kind/cluster.yaml --name pia-https-test
```

### The Phase 5c.3b webhook (hand-rolled manifests, dev only)

```sh
cd test/kind/webhook
./gen-tls-and-manifests.sh                     # regenerates dev TLS + manifests
kubectl apply -f webhook-deployment.yaml
kubectl wait --for=condition=available --timeout=60s deploy/postman-insights-webhook -n postman-insights
kubectl apply -f webhook-config.yaml
```

Rollback: `kubectl delete mutatingwebhookconfiguration postman-insights-webhook`.

### The Phase 5c.3c Helm chart (production-shaped)

See [`deployment/helm/postman-insights-webhook/README.md`](../deployment/helm/postman-insights-webhook/README.md)
for the full install / upgrade / rollback procedure.

---

## 5. Open work — what remains, in priority order

The original design-doc spec is **done**. What remains is genuine
out-of-scope work; none of it is launch-blocking.

### Priority 1 — observed bugs (none right now)

There are no known unfixed bugs. LIMIT-1 (ByteBuddy / JDK 25) and LIMIT-2
(keytool subprocess) from the webhook-runbook are both resolved.

### Priority 2 — capability extensions

| # | Item | Estimated cost | Why deferred |
|---|---|---|---|
| 1 | **Rustls uprobe support** | ~2 weeks | OBI + Datadog don't have mature Rustls support either. Per design §1.5, revisit v1.1. |
| 2 | **Node.js TLS support** | ~3-4 weeks | Different attach model (Node uses libuv + OpenSSL; the uprobe path works but the per-request correlation needs different bookkeeping). Tier-3 in design §4.2. |
| 3 | **Python TLS support** | ~3-4 weeks | Same shape as Node but more JIT diversity (CPython, PyPy). Tier-3. |
| 4 | **Multi-layer dedup** (`net/http` alongside `crypto/tls`) | ~2 days | Only needed when we add `net/http`-layer probes. Design lives in `phases/phase-3-dedup.md`. |
| 5 | **Throughput-mode JMH for multi-vCPU scaling** | ~half day | See `java-agent/benchmarks/README.md`. |
| 6 | **Full kind cluster e2e in CI** | ~1 day | Docker-in-docker is expensive (~5 min per PR). Manual procedure in `webhook-runbook.md` is the fallback. |
| 7 | **Body-truncation metadata: backend-side rendering** | ~depends on backend team | We emit `X-Postman-Insights-Body-Truncated` synthetic headers; backend needs to surface them in the UI. |

### Priority 3 — paper cuts

* `JettySslEndPointInst` is a Jetty-12-specific workaround. When upstream
  Jetty changes the `SslConnection$SslEndPoint.flush` signature again, this
  will need re-verification. Test: run the Jetty integration test in
  `java-agent/testdata/jetty-https/`.
* The ByteBuddy / Shadow plugin bump (follow-up 1) will need to be redone
  every ~12-18 months as new JDK class file versions ship. The pattern is
  in commit `dede34c`.
* `docs/merge-vs-review.md` was marked HISTORICAL post-merge consolidation.
  It can be deleted at some point.

---

## 6. Technical design — the cheat sheet

### The overall architecture (one paragraph)

The agent runs as a Linux process. For OpenSSL/BoringSSL it attaches
uprobes to `SSL_read` / `SSL_write` from libssl, copies plaintext bytes
into a BPF ringbuf, and a user-space goroutine reads them and feeds them
into the existing akinet HTTP parser. For Go's `crypto/tls`, it does
the same with DWARF-resolved offsets. For Java, the agent JAR uses
ByteBuddy to splice an `@Advice` callback around `SSLEngine.wrap/unwrap`;
the callback issues a fake `ioctl(0, 0x0b10b1, ...)` syscall whose only
purpose is to be observed by a `sys_ioctl` kprobe that routes the bytes
into the same ringbuf as the libssl path. Everything downstream is
shared.

### What OBI gave us, what we built ourselves

[OBI](https://github.com/grafana/beyla) (formerly Grafana Beyla, now part
of [OpenTelemetry eBPF Instrumentation](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation))
is our primary reference implementation. We **cloned it read-only** at
`../insights-ebpf-research/obi/` during development.

**Where OBI's design directly shaped ours:**

| What | Our implementation | OBI reference |
|---|---|---|
| libssl uprobe targets | `ebpf/programs/libssl.bpf.c` | OBI's `bpf/generictracer/openssl.c` |
| Go DWARF offset extraction | `ebpf/goexec/` | OBI's `pkg/internal/goexec/` |
| Java ioctl bridge | `ebpf/programs/java_tls.bpf.c` + `java-agent/src/main/java/com/postman/insights/agent/ebpf/IoctlPacket.java` | OBI's `bpf/generictracer/java_tls.c` + `IOCTLPacket.java` |
| Per-event wire format | 41-byte packed header matches OBI's IOCTLPacket layout exactly | OBI |
| CO-RE pattern + `vmlinux.h` regeneration | `test/kind/Dockerfile.agent` | OBI's CI image |

**Where we diverged from OBI:**

| What | We do | OBI does | Why |
|---|---|---|---|
| Output format | akinet `ParsedNetworkTraffic` (existing pcap-path output) | OpenTelemetry traces/spans | We're feeding an existing Postman backend, not Tempo/Jaeger. |
| Java agent attach | ByteBuddy + native ioctl | A pure-Java + ioctl approach is OBI's; we mirrored it | parity |
| Mutating admission webhook | Built from scratch (no OBI reference) | OBI doesn't have a webhook | OBI relies on a sidecar-injecting solution upstream |
| Per-namespace privacy mode | `--https-discovery-config` YAML | OBI uses OTel resource attributes | Customer-facing config style |
| Privacy redaction | `data_masks/` package, ~40 sensitive keys, regex patterns, hash tokenization, dry-run mode | OBI redacts at the OTel collector | We do it at the agent because we control the upload path |

**Other reference repos cloned read-only** during development:

* Datadog `system-probe` — for Go inspector patterns and CO-RE techniques.
* Pixie — for `crypto/tls.(*Conn).Read` RET-instruction probing (which
  works around Go's lack of regular function returns under inlining).
* eCapture — for libssl uprobe attachment patterns on dynamically-loaded
  libraries.

All are at `../insights-ebpf-research/` (sibling to this repo).

### Key implementation insights (hard-won during development)

These are the "I would have made this mistake too" warnings:

1. **Don't pkill -f java.** It matches your own shell. Use
   `pgrep -x java | xargs kill -9`. (Cost us two killed sessions before
   we wrote this down.)

2. **`HTTP 200` from curl ≠ agent captured.** Always check the actual
   capture events in `apidump-*` output. (Cost: 30 min of "why is JDK 8
   broken?" when nginx was responding instead of HelloHttps.)

3. **Every `apidump-*` command needs `--duration`.** Otherwise it runs
   as a daemon and the test hangs forever.

4. **JDK 8 has THREE Java-agent gotchas.** All documented in
   `phase-5c2-results.md`:
   - Bytecode version: agent JAR must compile to JDK 8 (Java 1.8) class
     file version even when the build JDK is newer.
   - JNI classloader visibility: the BOOTSTRAP classloader copy of
     `NativeMemory` must `<clinit>` first via `Class.forName(name, true, null)`
     before any application-loaded copy.
   - `ByteBuffer` covariant-return trap: `((Buffer) view).position(start)`
     cast in `Hooks.readBytes` — JDK 8's `ByteBuffer.position(int)` returns
     `Buffer`, not `ByteBuffer`. Without the cast, NoSuchMethodError at
     runtime on JDK 8 only.

5. **Jetty 12's `SslConnection$SslEndPoint.wrap` path has `consumed=0`
   for data.** The framework processes data internally and only emits a
   `flush` at the boundary. Hook `flush` instead — see
   `JettySslEndPointInst.java`.

6. **gRPC uses HTTP/2 HEADERS for both REQUEST and the trailers. This
   produces 2 REQ events per RPC** at the byte layer. Downstream dedup
   by stream-id is the right place to handle this, not the agent.

7. **The kprobe path uses `sys_ioctl` (a real syscall) rather than a
   tracepoint** because it lets the JVM emit events from inside a JNI
   call with zero protocol invention. The "magic command number"
   (`0x0b10b1`) is checked early in the kprobe; any other ioctl falls
   through.

8. **`failurePolicy: Ignore` is non-negotiable.** A misconfigured
   `MutatingWebhookConfiguration` with `failurePolicy: Fail` can break
   ALL pod creation cluster-wide. CI helm-smoke job explicitly greps
   for `failurePolicy: Ignore` and fails if anyone changes it.

---

## 7. Operations / production deployment

### For the Insights backend team

* Witnesses now arrive with **synthetic headers** when the BPF body cap
  truncated their payload:
  * `X-Postman-Insights-Body-Truncated: true`
  * `X-Postman-Insights-Body-Dropped-Bytes: <N>`
* These survive the redactor. Surface them in the UI if relevant; ignore
  them otherwise.

### For SREs deploying the agent

* Read [`webhook-runbook.md`](webhook-runbook.md) end-to-end.
* The two LIMITs in that doc (ByteBuddy / keytool) are both marked
  **RESOLVED**. The historical sections explain what to do if the same
  shape of bug ever recurs on a future JDK.

### For platform engineers consuming the Helm chart

* `deployment/helm/postman-insights-webhook/` is the chart.
* Two TLS modes: `secret` (BYO) or `cert-manager`.
* The chart's `failurePolicy: Ignore` is the safe default. **Don't change
  this without rehearsed rollback.**

---

## 8. Build / test invariants (don't break these)

* `make` (Mac or Linux) must succeed without `insights_bpf` tag.
* `make build-ebpf` (Linux) must succeed with `insights_bpf` tag.
* `make test` must show 14 packages, 0 fails.
* `helm lint deployment/helm/postman-insights-webhook` must report
  "0 chart(s) failed" with at most one INFO (about missing icon).
* Java agent JAR builds to `build/libs/postman-java-agent.jar`,
  Agent.class major version stays at 0x34 (= JDK 8).
* CircleCI `build` + `helm-smoke` jobs both pass.

---

## 9. People + access (fill in before you forward this doc)

| Role | Person | Notes |
|---|---|---|
| Outgoing engineer | _(me)_ | Today is the last day. |
| Incoming engineer | _(you)_ | This doc is for you. |
| External eBPF reviewer | _(consultant)_ | PR #173 is their review surface. |
| Insights backend team | | Needs the X-Postman-Insights-* synthetic header info. |
| Platform / SRE team | | Will install the Helm chart in real clusters. |

Access required:

* GitHub write on `postmanlabs/postman-insights-agent`.
* CircleCI for build logs.
* Docker Desktop + 8 GB RAM minimum for the dev container + kind cluster.
* Approximately 30 GB free disk for the eBPF research repos and JDK
  installations.

---

## 10. Quick reference — common commands

```sh
# Verify the branch is the right one and pushed
git status -sb
git log --oneline -5

# Run the unit-test suite (Mac, no eBPF)
go test -count=1 -timeout 60s ./...

# Run the Linux test suite with eBPF compiled in
docker exec pia-bpf-dev bash -lc '
  export PATH=/usr/local/go/bin:/go/bin:$PATH
  cd /workspace
  make test
'

# Java agent build
docker exec pia-bpf-dev bash -lc 'cd /workspace/java-agent && gradle --no-daemon clean shadowJar'

# Java agent benchmarks
docker exec pia-bpf-dev bash -lc '
  export JAVA_HOME=/opt/jdks/jdk-21
  cd /workspace/java-agent/benchmarks
  gradle --no-daemon jmh
'

# Helm chart lint + render
docker run --rm -v $(pwd)/deployment/helm:/charts alpine/helm:3.14.0 \
    lint /charts/postman-insights-webhook

docker run --rm -v $(pwd)/deployment/helm:/charts alpine/helm:3.14.0 \
    template release /charts/postman-insights-webhook \
    --namespace postman-insights \
    --set image.tag=ci-smoke \
    --set tls.secret.caBundle=BASE64CAHERE

# Kind cluster — webhook teardown (the ONE rollback command)
kubectl delete mutatingwebhookconfiguration postman-insights-webhook
```

---

## 11. If something breaks

* **Build broken on Mac:** check the host Go version. We use 1.23/1.24.
  Code references `optionals.Optional` from `akita-libs` which is at a
  pinned version in `go.mod`.
* **Build broken in dev container:** rebuild via `build-scripts/Dockerfile.dev`.
* **Java agent build fails with "Unsupported class file major version 68":**
  the Shadow plugin is the wrong version. See commit `dede34c` — we use
  `com.gradleup.shadow:8.3.6`.
* **Webhook installed but pods aren't being mutated:** check the
  namespace label (`postman.dev/insights=enabled`) and the webhook pod
  logs. See `webhook-runbook.md` "Pods aren't being mutated" section.
* **Pod creation hangs / blocked:** RUN THE ROLLBACK IMMEDIATELY:
  `kubectl delete mutatingwebhookconfiguration postman-insights-webhook`.

---

## 12. Final checklist for the outgoing engineer (me)

Before transferring this work stream, I confirm:

- [x] Branch `feat/https-capture-ebpf` is at commit `ad177b3`, pushed to origin.
- [x] PR #173 is the single review surface; #174 is closed.
- [x] All 5 follow-up backlog items are committed and pushed.
- [x] `docs/progress.md` is up to date.
- [x] `docs/phases/SESSION-RESUME.md` has the latest phase table.
- [x] `docs/webhook-runbook.md` LIMIT-1 and LIMIT-2 are both marked RESOLVED.
- [x] `docs/HANDOFF.md` (this file) exists at the path the new engineer
      will be told to read.
- [x] CI is green on the latest commit (build + helm-smoke).
- [x] No private keys / secrets in any committed file (paranoia check
      ran on every commit).

If any of these flips to ❌, something regressed between the last commit
and the moment you're reading this. Fix it before merging.

— end of handoff —
