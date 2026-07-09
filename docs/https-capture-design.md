# HTTPS Capture for the Postman Insights Agent — Design & Research

**Status:** Draft for review
**Authors:** Postman Insights Agent team
**Last updated:** 2026-05
**Branch:** `feat/https-capture-ebpf`

---

## 1. Executive summary

The Postman Insights Agent today captures **HTTP traffic only**, using classic BPF + libpcap. The vast majority of production inter-service traffic is **HTTPS**, which is invisible to the agent. This document describes how we add HTTPS capture using **eBPF**, with full coverage of the major language runtimes (C/C++, Go, Node.js, Python, Ruby, Rust, Java).

**Approach (one sentence):** Attach eBPF uprobes to userspace TLS libraries at the point where data is plaintext (just before encryption / just after decryption), copy bounded buffers to userspace, and feed them into the agent's existing HTTP parsing pipeline. For Java — which has no native TLS — use a small Java agent that bytecode-instruments `SSLEngine` and ships plaintext via an `ioctl()` syscall that an eBPF kprobe intercepts.

**Reference implementation:** [OpenTelemetry eBPF Instrumentation (OBI)](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation), formerly known as Grafana Beyla. Apache-2.0 licensed. We vendor or fork its BPF C code rather than write our own.

**Customer-facing positioning:** Same eBPF posture as Datadog system-probe, OBI/Beyla, Cilium, and Falco. Linux 5.8+ (RHEL 8 4.18+ exception). `CAP_BPF` + `CAP_PERFMON`. DaemonSet only. No sidecars. No app code changes.

**Scope of this doc:** Linux only. macOS dev is deprioritized.

---

## 2. Why classic BPF cannot see HTTPS

The current pipeline (`pcap/` → `learn/parse_http.go` → `trace/`) attaches a classic BPF filter via `pcap.SetBPFFilter` and receives wire packets. For HTTPS, those packets are TLS records — encrypted application data. No filter rewrite changes that.

The existing `tls_conn_tracker/` package observes only the **TLS handshake** (SNI, ALPN, cipher suite). It is **explicitly not decryption**. `apidump/summary.go:298` already prints:

> "This may mean you are trying to capture HTTPS traffic, which is currently unsupported."

To see plaintext we must intercept the data **before encryption** (writer side) or **after decryption** (reader side). That is fundamentally a **userspace** interception problem — kernel networking sees only ciphertext.

---

## 3. Survey of prior art

We reviewed four open-source implementations in depth (clones live at `/Users/swamy.hiremath@postman.com/playground/insights-ebpf-research/`):

| Project | License | Approach | Notes |
|---|---|---|---|
| **OBI** (OpenTelemetry eBPF Instrumentation) | Apache-2.0 | libssl uprobes + Go-runtime uprobes + Java agent + ioctl bridge | Currently active development. Linux 5.8+. CO-RE/libbpf. **Recommended reference.** |
| **Grafana Beyla** | Apache-2.0 | Thin wrapper around OBI; donated to OpenTelemetry | All real work happens upstream in OBI now. |
| **Pixie** (CNCF, New Relic) | Apache-2.0 | BCC-based (Python runtime compile) libssl uprobes + kprobes on sendmsg/recvmsg | Older approach, fragile, requires kernel headers at runtime. Don't copy directly. Has richer protocol parsers. |
| **Datadog system-probe (USM)** | Apache-2.0 | libssl uprobes + Go uprobes via DWARF inspector | Mature Go-offset inspector (~2000 LOC). No Java unification — Java goes through `dd-trace-java` separately. |
| **ecapture** | Apache-2.0 | Pure TLS plaintext capture via uprobes | No HTTP correlation. Useful reference for symbol resolution in stripped/static binaries. |

### Why OBI is our reference

1. **Active development** — Beyla maintainers work upstream on OBI full-time.
2. **CO-RE/libbpf** — modern eBPF style. Works across kernels without recompilation.
3. **Unified pipeline** — native TLS, Go TLS, and Java TLS all flow through a single event format.
4. **Java solved elegantly** — the `ioctl()` bridge is genuinely novel and we should copy it.
5. **License compatible** — Apache-2.0 allows vendoring into our codebase.

---

## 4. Approach by language runtime

### 4.1 C / C++ / Python / Ruby / PHP / Node.js (with system OpenSSL)

**Strategy:** Uprobes on libssl/libcrypto exported symbols.

Probe set (from OBI `bpf/generictracer/libssl.c`):

| Function | Entry probe | Return probe | Purpose |
|---|---|---|---|
| `SSL_read` | ✅ captures `(ssl, buf, len)` | ✅ captures bytes-read | Server-side decrypt, sync API |
| `SSL_read_ex` | ✅ | ✅ | Newer variant, used by Node.js |
| `SSL_write` | ✅ | ✅ | Client/server encrypt entry |
| `SSL_write_ex` | ✅ | ✅ | Newer variant |
| `SSL_shutdown` | ✅ | — | Connection close, used for flushing |

**Discovery:** scan target containers' `/proc/<pid>/root/lib*/libssl.so.*`. For dynamically linked binaries, attach by symbol name. For statically-linked OpenSSL (Node, Envoy-static), scan the target binary's symbol table for `SSL_write`/`SSL_read` and attach by file offset.

**Coverage:** any process that links libssl, which is the dominant case for Python (`ssl`/`requests`), Ruby (`OpenSSL`), PHP (`openssl_*`), Node (when system OpenSSL is used).

### 4.2 Node.js (statically-linked BoringSSL)

Node.js commonly statically links BoringSSL inside the `node` binary. Function names exist in the symbol table even when stripped. OBI handles this via `bpf/generictracer/nodejs.c` + offset-based attach. We adopt the same approach.

### 4.3 Go (pure-Go TLS via `crypto/tls`)

This is the hardest case because Go does not use libssl. OBI probes Go at **three layers** simultaneously and dedupes in userspace:

| Layer | OBI file | What it probes |
|---|---|---|
| HTTP layer | `bpf/gotracer/go_nethttp.c` | `(*http.Transport).RoundTrip`, `(*conn).serve`, `readRequest`, `header.writeSubset`, HTTP/2 framer, gRPC stream handlers |
| TLS layer | `bpf/gotracer/go_net_tls.c` | `crypto/tls.(*Conn).Read`, `crypto/tls.(*Conn).Write` |
| Socket layer | `bpf/gotracer/go_net.c` | `net.(*netFD).Read`, `net.(*netFD).Write` |

To read Go function arguments and struct fields, the agent must know the **Go ABI register layout** and **struct field offsets**, both of which change across Go versions.

**Solution:** a DWARF-based runtime inspector that opens the target Go binary, parses its `.debug_info` section, and extracts field offsets for the structs it needs. OBI's implementation is `pkg/internal/goexec/structmembers.go` (736 LOC) + `configs/offsets/tracker_input.json`. Datadog's equivalent is `pkg/network/go/bininspect/` (~2000 LOC, more mature).

Required Go versions: **Go 1.17+** (per OBI's support matrix).

### 4.4 Rust (rustls)

Out of scope for v1. Rustls uprobe support is less mature in OBI/Datadog. Document as a known gap; revisit in v1.1.

### 4.5 Java / JVM — the `ioctl` bridge

JVM TLS (JSSE, Bouncy Castle, Netty's SslHandler, OpenJDK's `SSLEngine`) is implemented in pure Java. There are no stable native symbols to uprobe. Native crypto uprobes (ecapture's approach) are fragile and don't produce HTTP-layer plaintext.

**OBI's solution (which we adopt):**

1. Ship a tiny Java agent JAR (`postman-java-agent.jar`).
2. The JVM is launched with `-javaagent:/opt/postman/postman-java-agent.jar` (via `JAVA_TOOL_OPTIONS` env var, auto-injected by a Kubernetes mutating webhook).
3. The Java agent uses **ByteBuddy bytecode instrumentation** to intercept:
   - `javax.net.ssl.SSLEngine.wrap()` / `unwrap()` — covers Tomcat, Jetty, JDK HttpClient, gRPC-Java
   - `javax.net.ssl.SSLSocket` read/write streams — older blocking I/O
   - `io.netty.handler.ssl.SslHandler` — Spring Boot/WebFlux, Vert.x, gRPC-Java's Netty transport
4. On each intercepted call, the agent extracts plaintext bytes and calls **`ioctl(fd=0, cmd=0x0b10b1, buffer)`** — a syscall with a magic command ID that nothing else uses.
5. On the kernel side, our eBPF kprobe on `sys_ioctl` (OBI `bpf/generictracer/java_tls.c`) recognizes the magic cmd, extracts the buffer, and pushes the plaintext into the **same ring buffer used by libssl uprobes**.

**Why this is elegant:**
- All TLS plaintext (native + Java) flows through one event format.
- The Java agent is ~2000 LOC of Java doing only bytecode instrumentation — no HTTP parsing, no networking, no correlation logic. All of that stays in the eBPF/Go pipeline.
- Works on any JDK 8+, any JSSE provider, any JVM vendor.
- Same DaemonSet capability set — no extra privileges.

**Cost:**
- Mutating webhook for auto-injection (model: `obi/pkg/webhook/`).
- Customers must accept that the webhook will mutate Pod specs for namespaces with HTTPS capture enabled.
- JVM startup is marginally slower (ByteBuddy class transformation).

### 4.6 Coverage summary

| Language / Runtime | v1 | v1.1 | v2 |
|---|:---:|:---:|:---:|
| C / C++ (OpenSSL) | ✅ | | |
| Python | ✅ | | |
| Ruby | ✅ | | |
| Node.js (system OpenSSL) | ✅ | | |
| Node.js (static BoringSSL) | ✅ | | |
| PHP | ✅ | | |
| Go (1.17+) | | ✅ | |
| Rust (rustls) | | | ✅ |
| Java (JDK 8+) | | | ✅ |

---

## 5. Architecture

### 5.1 Current pipeline (HTTP only)

```
NIC ──libpcap──► gopacket ──TCP reassembly──► akinet parsers ──► trace.Collector ──► backend
                  (BPF filter)                (HTTPRequest,
                                               HTTPResponse,
                                               TLSClientHello,
                                               TLSServerHello)
```

Defined in `pcap/run.go::Collect`, `pcap/net_parse.go::NetworkTrafficParser`. The `trace.Collector` interface accepts `akinet.ParsedNetworkTraffic`.

### 5.2 Target pipeline (HTTP + HTTPS)

```
                       ┌──libpcap (existing)───────► gopacket ───┐
NIC ──┤                │                                          │
      │                ├──eBPF uprobe on libssl ──┐               │
      │                │                          │               │
      │                ├──eBPF uprobe on Go funcs─┤               ├─► akinet
      │                │                          ├─► ring buffer │   parsers ──► trace.Collector ──► backend
      │                ├──eBPF kprobe on ioctl ───┘               │   (reused)
      │                │      ▲                                   │
      │                │      │                                   │
      └─Java JVM───────┘      │                                   │
        +javaagent ──ioctl()──┘                                   │
        +ByteBuddy                                                 │
```

The **akinet parsers and the entire `trace.Collector` chain are reused** exactly as today. The eBPF subsystem produces the same `akinet.HTTPRequest` / `akinet.HTTPResponse` events that pcap produces. Downstream `data_masks/`, `trace/rate_limit.go`, `trace/backend_collector.go` work unchanged.

### 5.3 Package layout

New packages to be created (scaffolded in this branch):

```
ebpf/                              Top-level eBPF subsystem (new)
  loader/                          cilium/ebpf-based BPF program loader
    loader.go                      Open/load .bpf.o, attach probes, manage lifecycle
    btf.go                         BTF detection and kernel feature gating
    kernel.go                      Kernel-version detection (5.8+ check, RHEL exception)
  programs/                        BPF C source + compiled .o (vendored from OBI)
    libssl.bpf.c                   libssl uprobes (Phase 1)
    java_tls.bpf.c                 ioctl kprobe for Java (Phase 5)
    go_nethttp.bpf.c               Go HTTP/gRPC uprobes (Phase 3)
    go_tls.bpf.c                   Go crypto/tls uprobes (Phase 3)
    Makefile                       clang -target bpf -O2 ... compilation
  uprobes/                         Per-library uprobe attachment logic
    openssl.go                     Symbol resolution, dynamic + static libssl
    nodejs.go                      Statically-linked BoringSSL handling
    gotls.go                       Go binary inspection + offset injection (Phase 3)
  goexec/                          DWARF-based Go binary inspector (Phase 3)
    inspect.go                     Vendored/adapted from OBI pkg/internal/goexec
    structmembers.go
  events/                          Ring buffer reader, event → akinet adapter
    ringbuf.go                     cilium/ebpf RingbufReader
    stream.go                      (pid, fd, dir) → byte stream reassembly
    adapter.go                     Convert events to akinet.ParsedNetworkTraffic
  discovery/                       Process discovery — which PIDs to attach to
    proc.go                        /proc walking + inotify
    cri.go                         Reuses integrations/cri_apis
    kube.go                        Reuses integrations/kube_apis
  collect.go                       Top-level `ebpf.Collect(...)` entry point,
                                   parallels pcap.Collect() signature
java-agent/                        Java agent (Phase 5, separate Gradle build)
  src/main/java/...                ByteBuddy bytecode instrumentation
  build.gradle.kts
```

### 5.4 Integration with existing `apidump` command

In `apidump/apidump.go`, after the existing pcap collector setup, conditionally start an eBPF collector behind a flag:

```go
if args.EnableHTTPSCapture {
    go func() {
        if err := ebpf.Collect(
            a.backendSvc, traceTags, stop,
            args.HTTPSLibraries,           // []string: openssl, nodejs, gotls, java
            args.HTTPSBodySizeCap,         // int: default 4KB
            args.HTTPSTargetNamespaces,    // []string
            collector,                      // SAME collector chain as pcap
            apidumpTelemetry,
        ); err != nil {
            errChan <- interfaceError{interfaceName: "ebpf", err: err}
        }
    }()
}
```

When eBPF is enabled, **exclude port 443 from the pcap cBPF filter** (`apidump/net.go::createBPFFilters`) to avoid double-counting handshakes. Keep `tls_conn_tracker` running for handshake metadata if customers want it.

### 5.5 New CLI flags (on `apidump` and `kube run`)

| Flag | Default | Description |
|---|---|---|
| `--enable-https-capture` | `false` | Master switch for eBPF HTTPS capture |
| `--https-libraries` | `openssl` | Comma-separated subset of `openssl,nodejs,gotls,java` |
| `--https-target-namespaces` | (all) | Comma-separated K8s namespace allow-list |
| `--https-body-size-cap` | `4096` | Per-request body capture cap in bytes |
| `--https-capture-mode` | `headers` | `headers` (no body), `truncated` (body up to cap), `full` (body up to 64KB cap) |
| `--privacy-mode` | `standard` | `standard`, `strict` (drop bodies entirely), `dry-run` (capture+redact but don't upload) |

---

## 6. Sampling & buffering

The current agent has two distinct sampling mechanisms (`trace/rate_limit.go` epoch-based, `trace/collector.go::SamplingCollector` stream-hash based). Neither is appropriate for **kernel-side load shedding**, which is the new concern eBPF introduces.

### 6.1 What we measured in OBI

From `bpf/common/http_info.h` and `bpf/common/large_buffers.h`:

| Setting | Value | Meaning |
|---|---|---|
| `FULL_BUF_SIZE` | **256 bytes** | Default capture per event — enough for method+path+headers, truncates bodies |
| `k_large_buf_payload_max_size` | 16 KB | Max per ring-buffer chunk when "large buffers" enabled |
| `MaxCapturedPayloadBytes` | 64 KB | Hard ceiling per request per direction |
| `OTEL_EBPF_BPF_BUFFER_SIZE_HTTP` | **0 (disabled)** | Default body capture is OFF |
| Per-protocol caps | configurable | HTTP, MySQL, Postgres, Kafka independently |

**OBI's design philosophy: don't sample, truncate.** Bodies are off by default; when enabled they are aggressively capped. Throughput is regulated by *how many bytes per event* rather than *how many events*.

### 6.2 Our sampling stack

Layered, each layer reduces a different cost:

| Layer | Where | Reduces | Default |
|---|---|---|---|
| **1. Body truncation** | Kernel (eBPF) | Ring-buffer bandwidth, copy-to-user cost | 4 KB per request |
| **2. Per-PID rate cap** | Kernel (eBPF map: `pid → token_bucket`) | Per-process uprobe firing rate | 1000 req/s/PID |
| **3. Reservoir per (svc, route, status-class)** | Userspace (Go) | Backend bandwidth; preserves diverse samples | K=20 per epoch |
| **4. Existing `SharedRateLimit`** | Userspace (Go) | Final witness budget to backend | unchanged |
| **5. CPU thermostat** | Userspace (Go) | Host CPU impact | Throttle if agent >5% CPU |

Industry comparison:

| Agent | Approach |
|---|---|
| OBI/Beyla | Truncate only. No event-level sampling. |
| Datadog USM | Per-endpoint token bucket. |
| Pixie | Per-connection ringbuf with body caps; CPU thermostat. |
| AWS X-Ray | Reservoir sampling (1/sec per service + probabilistic). |

**Recommendation for v1:** ship layers 1, 2, and 5 (matches OBI default + Pixie thermostat). Layer 3 (reservoir) and Layer 4 reuse stay in place for the existing pipeline. Defer Layer 4's interaction with eBPF until we have load data.

### 6.3 Backpressure / overflow

- BPF ring buffer sized **2 MB per CPU** (OBI default).
- On overflow, kernel drops events silently. Userspace reads `bpf_ringbuf_query()` periodically and exports a `dropped_events_total` metric.
- If drops exceed 1% over a 60s window, automatically reduce layer-1 truncation by 50% and emit a warning telemetry event.

---

## 7. Privacy & redaction

This section is **mandatory pre-launch work**, not a "nice to have." Going from "we never see HTTPS" to "we see all HTTPS plaintext" makes the agent the gatekeeper for far more sensitive data than today.

### 7.1 The threat model change

**Today (HTTP only):** the agent sees primarily north-south HTTP traffic — typically less sensitive because production HTTP is usually edge-only and behind TLS.

**With HTTPS capture:** the agent sees **east-west service-to-service traffic**. This typically contains:

- Service-account JWTs (often with broad scopes).
- Internal mTLS identities passed in `X-Forwarded-Client-Cert` style headers.
- Internal admin endpoints not protected by the same auth as public ones.
- PII in microservice payloads that previously "stayed in the cluster."
- Secrets in `Authorization: Bearer …` headers between services.

### 7.2 Existing redaction (in `data_masks/`)

We already have:
- ✅ **30+ sensitive-key names**: `accessToken`, `api-key`, `password`, `set-cookie`, `proxy-authorization`, `x-amz-security-token`, `x-api-key`, etc. (see `data_masks/redaction_config.yaml`).
- ✅ **30+ value regexes** for known token shapes: PMAK, JWT, Stripe `sk_live_…`, Anthropic `sk-ant-…`, PEM blocks, AWS keys, etc.
- ✅ Customer-supplied regex overrides via `user_redaction_config.go`.

### 7.3 Gaps we MUST close before HTTPS launch

| # | Gap | Action |
|---|---|---|
| 1 | `Authorization` header is **not** in the default sensitive-keys list (only `proxy-authorization` is). | Add `authorization`, `cookie`, `www-authenticate`, `proxy-authenticate`, `grpc-authorization`, `x-forwarded-client-cert`. |
| 2 | No body-size cap as a redaction concept. | Add `--https-body-size-cap` flag (default 4 KB). Truncation at kernel + recording-truncated metadata. |
| 3 | No HIPAA/PCI preset. | Add `--privacy-mode=strict` (headers only, no bodies). |
| 4 | No per-namespace / per-service opt-out. | Extend discovery filters in `docs/discovery-mode.md`: `decrypt: false` per workload. |
| 5 | No tokenization (hash-replace) option. | Add config to replace matched values with `sha256(value)[:16]` instead of `***REDACTED***`. |
| 6 | No redaction-coverage telemetry. | Count redactions by rule; surface to customer dashboards for audit. |
| 7 | No dry-run mode. | Add `--privacy-mode=dry-run`: capture + redact, log stats, don't upload. Used for security review. |
| 8 | No documented data flow / threat model doc. | Write `docs/https-data-flow.md` for customer security reviews. |

### 7.4 Industry baseline (verified from source)

| Practice | OBI | Datadog USM | New Relic Pixie |
|---|:---:|:---:|:---:|
| Bodies off by default | ✅ | ✅ | ⚠️ (config) |
| Body size cap | ✅ 256B/64KB | ✅ 4 KB | ✅ 4 KB |
| Header allowlist (default deny Authorization/Cookie) | partial | ✅ | ✅ |
| Customer-supplied regex | ✅ | ✅ | ✅ |
| Per-route opt-out | ✅ | ✅ | ✅ |
| HIPAA preset | manual | ✅ | ✅ |
| Tokenization | — | ✅ | — |
| On-host redaction (before network egress) | ✅ | ✅ | ✅ |

Our v1 must match the "Datadog USM" column.

---

## 8. Security & permissions — customer story

### 8.1 What we ask for

DaemonSet pod spec additions:

```yaml
spec:
  hostPID: true
  containers:
  - name: postman-insights-agent
    securityContext:
      capabilities:
        add: [BPF, PERFMON, NET_ADMIN]      # CAP_BPF + CAP_PERFMON for Linux 5.8+
      # On older kernels (RHEL 8 4.18), fall back to:
      # add: [SYS_ADMIN, NET_ADMIN]
    volumeMounts:
    - { name: sys-kernel-debug, mountPath: /sys/kernel/debug }
    - { name: sys-fs-bpf, mountPath: /sys/fs/bpf }
    - { name: proc, mountPath: /host/proc, readOnly: true }
  volumes:
  - { name: sys-kernel-debug, hostPath: { path: /sys/kernel/debug } }
  - { name: sys-fs-bpf,       hostPath: { path: /sys/fs/bpf } }
  - { name: proc,             hostPath: { path: /proc } }
```

For Java auto-injection: an additional `MutatingWebhookConfiguration` that adds `JAVA_TOOL_OPTIONS=-javaagent:/opt/postman/postman-java-agent.jar` to Pods in opted-in namespaces.

### 8.2 Customer-facing positioning (use these exact talking points)

**Talking point 1 — Precedent.** Any organization running any of these in production has already authorized this exact privilege set:
- Cilium / Calico eBPF data plane
- Falco (CNCF runtime security)
- Datadog Agent (system-probe component)
- Sysdig, Aqua, Wiz runtime agents
- Pixie / New Relic Kubernetes integration
- Grafana Beyla
- OpenTelemetry eBPF Instrumentation (OBI)

The Postman Insights Agent asks for the **same posture** — not more.

**Talking point 2 — Compared alternatives are more invasive.** The alternatives to capture HTTPS traffic are:
1. Code instrumentation (SDK in every service) — requires every team to merge code, version skew, language fragmentation.
2. Service mesh sidecars (Istio, Linkerd) — adds latency, doubles container count, requires Pod-spec mutations per workload.
3. TLS termination at a proxy — changes traffic topology, breaks mTLS.
4. **eBPF DaemonSet — zero app changes, one DaemonSet, opt-in per namespace.**

**Talking point 3 — Hard security properties.** Specific, verifiable claims for security review:
- **Read-only by default.** We attach observability probes. We never modify syscalls, packets, or block traffic.
- **Kernel-verified.** All BPF programs are verified by the Linux kernel's BPF verifier before load (no unbounded loops, no arbitrary memory access, bounded stack, type-safe map access).
- **Auditable.** All `.bpf.c` source code is in this repository under `ebpf/programs/`. Customers can review and rebuild.
- **Per-namespace opt-in.** The DaemonSet's existing discovery filters (`docs/discovery-mode.md`) gate which namespaces are even considered for capture.
- **Dry-run mode.** `--privacy-mode=dry-run` loads probes and runs the full pipeline but writes nothing to the network. Lets security teams review captured-and-redacted data before enabling live capture.
- **Bodies off by default.** Without explicit configuration, no HTTPS request/response bodies leave the host.

### 8.3 The kernel-floor story

> "The Postman Insights Agent's HTTPS capture requires Linux 5.8 or newer for full functionality. RHEL 8, CentOS 8, Rocky Linux 8, and AlmaLinux 8 with their default kernels are supported via Red Hat's eBPF backports. This is the same baseline used by OpenTelemetry eBPF Instrumentation and Datadog's system-probe."

### 8.4 Pre-sales security review artifacts (deliverables)

1. **`docs/https-data-flow.md`** — sequence diagrams: kernel → agent → backend, listing every transformation.
2. **`docs/security-permissions.md`** — exhaustive list of capabilities, syscalls hooked, file paths read.
3. **`docs/redaction-defaults.md`** — full list of redacted headers and regex patterns with example matches.
4. **Reproducible dry-run demo** — one-command DaemonSet install in dry-run mode.

---

## 9. Phased delivery plan

Each phase is independently demoable.

### Phase 0 — Decisions locked (this document)

- ✅ Linux 5.8+ floor with RHEL 8 4.18 exception
- ✅ DaemonSet only (no sidecars)
- ✅ Tier-1 coverage: OpenSSL, statically-linked OpenSSL/BoringSSL, Node.js
- ✅ Tier-2 coverage (v1.1): Go
- ✅ Tier-3 coverage (v2): Java + Rust
- ✅ OBI as reference; Apache-2.0 vendoring permitted
- ✅ Bodies off by default; truncate-don't-sample philosophy
- ✅ Privacy gaps #1-#8 must close before launch

### Phase 1 — Spike: OpenSSL HTTPS → existing pipeline (timebox: 2 weeks)

**Goal:** end-to-end decrypted HTTP/1.1 from an OpenSSL process reaches `trace.Collector.Process()` as an `akinet.HTTPRequest`.

**Deliverables:**
- `ebpf/programs/libssl.bpf.c` — adapted from OBI `bpf/generictracer/libssl.c`.
- `ebpf/loader/` — minimal `cilium/ebpf` loader (open .bpf.o, attach uprobes, read ringbuf).
- `ebpf/events/adapter.go` — convert `(pid, fd, dir, bytes)` events into the existing `akinet.HTTPRequest`/`HTTPResponse` types by feeding them into the existing `akihttp` parsers.
- `cmd/internal/apidump-ebpf/` — standalone command (behind `//go:build linux && ebpf` build tag) for spike testing.

**Validation:**
- ✅ curl → nginx (HTTPS): see at least one decrypted request/response in `trace.Collector`.
- ✅ Python `requests` HTTPS GET: same.
- ✅ Node.js HTTPS GET: same.
- ✅ CPU overhead < 5% at 1000 RPS on a 4-core box.

**Exit criteria:** demoable HTTPS capture for the three workloads above. CPU within budget. Architectural confidence to commit to Phase 2.

### Phase 2 — Production integration (timebox: 3 weeks)

**Goal:** `--enable-https-capture` flag works on the real `apidump` command, with proper lifecycle, telemetry, and the DaemonSet manifest updated.

**Deliverables:**
- Full `ebpf/` package as described in §5.3, behind a Linux build tag.
- `ebpf.Collect()` integrated into `apidump/apidump.go` collector setup.
- BPF filter exclusion for port 443 when eBPF is active.
- New CLI flags (§5.5).
- Sampling layers 1, 2, 5 (§6.2).
- DaemonSet manifest updates for `CAP_BPF`, `CAP_PERFMON`, `hostPID`, volume mounts.
- Telemetry: probes-attached, events-received, bytes-captured, drops, CPU%.
- Process discovery via existing `integrations/cri_apis` + `integrations/kube_apis`.
- Self-tracing exclusion (skip the agent's own PID).

**Validation:**
- ✅ Single-binary install on a real test cluster.
- ✅ Captures HTTPS traffic from three microservices simultaneously.
- ✅ Graceful detach on pod exit, reattach on pod restart.
- ✅ Drops < 0.1% under steady-state load.

### Phase 3 — Go support via OBI gotracer (timebox: 4 weeks)

**Deliverables:**
- `ebpf/programs/go_nethttp.bpf.c`, `go_tls.bpf.c`, `go_net.bpf.c` — adapted from OBI `bpf/gotracer/`.
- `ebpf/goexec/` — DWARF inspector adapted from OBI `pkg/internal/goexec/`.
- `ebpf/uprobes/gotls.go` — Go binary detection + offset injection at probe load time.
- Userspace deduplication for events arriving from multiple probe layers on the same connection.

**Validation:**
- ✅ Go service using `net/http` (Gin, stdlib, echo): HTTPS captured.
- ✅ Go service using `google.golang.org/grpc` with TLS: captured.
- ✅ Works across Go 1.17 through current Go release.

### Phase 4 — Privacy & redaction parity (timebox: 2 weeks)

**Deliverables:**
- All 8 privacy gaps (§7.3) closed.
- `docs/https-data-flow.md`, `docs/security-permissions.md`, `docs/redaction-defaults.md`.
- `--privacy-mode=dry-run` mode working.
- Default sensitive-headers list extended.
- HIPAA preset implemented.

**Validation:**
- ✅ External security review against a known sensitive-data corpus.
- ✅ Dry-run mode produces a "would-have-captured" report for security review.

### Phase 5 — Java via agent + ioctl bridge (timebox: 6 weeks)

**Deliverables:**
- `java-agent/` — Gradle project building `postman-java-agent.jar`. Adapted from OBI `pkg/internal/java/agent/`.
- `ebpf/programs/java_tls.bpf.c` — adapted from OBI `bpf/generictracer/java_tls.c`.
- `cmd/internal/kube-webhook/` — mutating webhook adding `JAVA_TOOL_OPTIONS` to opted-in Pods.
- DaemonSet manifest updates for webhook registration.

**Validation:**
- ✅ Spring Boot HTTPS service: captured.
- ✅ gRPC-Java service: captured.
- ✅ Tomcat/Jetty serving HTTPS: captured.
- ✅ OpenJDK 8, 11, 17, 21 all work.

---

## 10. Open questions

These need decisions before / during implementation:

1. **Vendor vs. fork vs. depend on OBI.** OBI is Apache-2.0 so all three are legal. Vendoring (copying the `.bpf.c` files into our repo) gives us control but means we miss upstream fixes. Forking lets us track upstream. Depending (as a Go module) ties us to their release cadence. **Recommendation:** vendor the `.bpf.c` files (small, stable surface); depend on `cilium/ebpf` as a Go module (already widely used).
2. **Build pipeline for BPF objects.** Need `clang` + `llvm` in our build container. CO-RE requires `bpf2go` codegen. Update `Makefile` and `build-scripts/Dockerfile`.
3. **Telemetry from existing cluster deployments.** Do we have data on customer kernel versions? This decides whether the 5.8+ floor is acceptable or whether we need a 4.18 fallback path for non-RHEL.
4. **Per-customer eBPF object distribution.** Do we ship pre-compiled .bpf.o, or compile on agent startup? Pre-compiled is simpler; on-startup handles weird kernels better. OBI ships pre-compiled.
5. **Beyla → OBI migration timing.** OBI is still pre-1.0. If we vendor now, we accept some churn. Acceptable risk.
6. **Customer demo timing.** This document supports a single up-front demo. Phase 1 spike output is the next demo-worthy artifact (~2 weeks).

---

## 11. References (in cloned form at `/Users/swamy.hiremath@postman.com/playground/insights-ebpf-research/`)

| Repo | Path | Why we reference it |
|---|---|---|
| `obi/` | `bpf/generictracer/libssl.c` | Direct source for Phase 1 libssl uprobes |
| `obi/` | `bpf/generictracer/java_tls.c` | The ioctl bridge kernel side |
| `obi/` | `bpf/gotracer/*.c` | Go uprobe set (Phase 3) |
| `obi/` | `pkg/internal/goexec/` | DWARF offset inspector for Go binaries |
| `obi/` | `pkg/internal/java/agent/` | Java agent ByteBuddy instrumentation (Phase 5) |
| `obi/` | `pkg/internal/ebpf/generictracer/` | cilium/ebpf loader pattern in Go |
| `obi/` | `SUPPORT_MATRIX.md` | Kernel / language version baselines we adopt |
| `obi/` | `bpf/common/large_buffers.h` | Buffer-cap design |
| `datadog-agent/` | `pkg/network/go/bininspect/` | Mature reference for Go DWARF inspection |
| `datadog-agent/` | `pkg/network/usm/ebpf_ssl.go`, `ebpf_gotls.go` | cilium/ebpf usage patterns |
| `pixie/` | `src/stirling/source_connectors/socket_tracer/bcc_bpf/openssl_trace.c` | Historical reference (BCC-based, do NOT copy directly) |
| `ecapture/` | (various) | Reference for symbol resolution in stripped/static binaries |

---

## 12. Glossary

- **eBPF** — extended Berkeley Packet Filter. Linux kernel facility for running sandboxed programs attached to kernel/user events.
- **uprobe / uretprobe** — eBPF probe attached to a userspace function's entry / return.
- **kprobe** — eBPF probe attached to a kernel function.
- **CO-RE** — Compile Once, Run Everywhere. Modern eBPF pattern using BTF for kernel-version portability.
- **BTF** — BPF Type Format. Kernel-shipped type information enabling CO-RE.
- **libbpf** — userspace library for loading eBPF programs (the modern alternative to BCC).
- **cilium/ebpf** — Go-native eBPF loader, no cgo. What we use.
- **BCC** — older Python-based eBPF toolkit. Requires kernel headers at runtime. What Pixie uses; what we avoid.
- **ByteBuddy** — Java library for runtime bytecode generation/instrumentation. Used by the Java agent.
- **OBI** — OpenTelemetry eBPF Instrumentation. Our reference implementation.
