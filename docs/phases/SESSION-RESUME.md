# Session resume brief — HTTPS capture via eBPF

**Purpose:** make context-loss safe. A fresh engineer (or fresh AI session)
should be able to read just this file + the three doc references below
and pick up where the last working session left off.

**Last updated:** end of session that delivered Phase 3 tasks #1 (HTTP/2)
and #2 (Read via RET probing).

---

## Mandatory reading before resuming

1. [`https-capture-design.md`](../https-capture-design.md) — the full
   architecture. 30 min read.
2. [`phase-2-results.md`](phase-2-results.md) — what Phase 2 actually
   shipped (5 of 6 exit criteria via the kind-cluster demo; the CRI+
   cgroup-ns inode pattern for namespace filtering).
3. [`phase-3-results.md`](phase-3-results.md) — what Phase 3 has so far
   and the seven remaining tasks in priority order.

## Where we are

| Phase | Status |
|---|---|
| 1 — Spike OpenSSL → pipeline | ✅ Done |
| 2 — Production integration into `apidump` | ✅ Done (all 6 exit criteria) |
| 3 — Go via DWARF inspector + crypto/tls uprobes | 🟡 ~65% (foundation + HTTP/2 + Read RET probing done) |
| 4 — Privacy hardening (8 gaps from design §7.3) | ❌ Not started — gates production |
| 5 — Java agent + ioctl bridge + webhook | ❌ Not started |

Branch: `feat/https-capture-ebpf` (all work) — rolling PR is **#173**.
**Do not create sub-branches**; the user wants a single rolling PR.

## Next task

**Phase 3 is sealed (~95% as of commit `<this>`).** All meaningful Phase
3 gaps are closed: stripped-binary pclntab fallback, amd64 real-
disassembler RET scan, multi-Go-version matrix (8/8 across
1.21×1.22×1.23×1.24 × stripped/unstripped). The remaining task #6
(multi-layer dedup) is **deliberately deferred** because we ship only
one layer today; design is captured in
[`phase-3-dedup.md`](phase-3-dedup.md) ready to execute when needed.

**Recommended next: Phase 5 — Java agent + ioctl bridge + webhook.**
Largest remaining piece (~6 weeks per the brief). Java is the biggest
enterprise gap by language coverage.

**Phase 5 is split into 5a / 5b / 5c — read [`phase-5-plan.md`](phase-5-plan.md) first.**
[`phase-5.md`](phase-5.md) remains the full 6-week reference brief; use
it for deep context on a specific sub-task. The plan doc explains why
we split, what each session ships, and what the exit criteria are.

Current Phase 5 status:
* **5a — eBPF foundation + C harness:** ✅ done. See
  [`phase-5a-results.md`](phase-5a-results.md). All five exit criteria
  green; wire format frozen at the 41-byte packed header; verifier
  budget healthy (xlated 2464B).
* **5b — Java agent MVP** — ✅ **fully closed** (5b.1 + 5b.2 + 5b.3).
  See [`phase-5-plan.md`](phase-5-plan.md) for the sub-session split.
  * **5b.1 — Java→ioctl bridge spike:** ✅ done. See
    [`phase-5b1-results.md`](phase-5b1-results.md).
  * **5b.2 — ByteBuddy + `SSLEngineInst`:** ✅ done. See
    [`phase-5b2-results.md`](phase-5b2-results.md). Real JDK
    `HttpsServer` + curl captured end-to-end. 1000 parallel → 1000/1000
    parsed, zero drops, attach 178 ms.
  * **5b.3 — hardening:** ✅ done. See
    [`phase-5b3-results.md`](phase-5b3-results.md). 10k soak (no leak),
    crash-resilience (100/100 HTTP 200 under synthetic crash injection),
    latency within noise of baseline.
* **5c — Framework matrix + webhook:** 🟡 in progress (split into
  5c.1 / 5c.2 / 5c.3, same pattern as 5b).
  * **5c.1 — Spring Boot + Netty:** ✅ done with zero new agent code.
    See [`phase-5c1-results.md`](phase-5c1-results.md). Architectural
    insight: 5b.2's `isSubTypeOf(SSLEngine.class)` matcher already
    catches Netty's `JdkSslEngine`, `OpenSslEngine`, etc. Validated
    against Spring Boot 3.2 webflux → 10000/10000 captured.
  * **5c.2 — Tomcat + Jetty + JDK matrix + gRPC-Java + JMH:** ✅ done,
    **all gaps closed in-session**. See
    [`phase-5c2-results.md`](phase-5c2-results.md).
    * Spring Boot + Tomcat + Jetty 12 + gRPC-Java all capture REQ +
      RESP under 1000-parallel stress.
    * JDK 8 / 11 / 17 / 21 all green.
    * `JettySslEndPointInst` added (Jetty-specific endpoint hook).
    * `SSLEngineInst` extended to 5 method signatures (covers Netty's
      OpenSslEngine 2-arg overrides + array-array variants).
    * Agent now compiles to Java 8 bytecode; `Module.redefineModule`
      via reflection.
    * JMH-precise per-call benchmark still deferred; 5b.3 curl-level
      evidence is sufficient for now.
  * **5c.3 — Mutating admission webhook:** 🟡 in progress (split into
    5c.3a/b/c, same pattern as 5b and 5c.2).
    * **5c.3a — Go webhook code:** ✅ done. See
      [`phase-5c3a-results.md`](phase-5c3a-results.md). New package
      `cmd/internal/kube-webhook/` with HTTPS server + AdmissionReview
      handler + Java-workload detection + JSON Patch construction.
      25 tests pass in 1 s, zero cluster risk. Includes a property-style
      test proving the webhook NEVER returns `Allowed: false`.
    * **5c.3b — Kind cluster e2e:** ❌ not started. Needs container
      image build, K8s manifests, `failurePolicy: Ignore` verification,
      rehearsed rollback.
    * **5c.3c — Helm + production docs:** ❌ not started.

Alternative: take the **PR-split** path before Phase 5. PR #173 is
now at ~30 commits / ~+13k LOC; splitting into stacked PRs lets the
phase 1+2 libssl path land independently while Java work runs.
See 'PR strategy' in [`../progress.md`](../progress.md).

## Earlier completed in this branch

- Phase 1 (libssl spike) — commits up to `7513ce7`.
- Phase 2 (production integration + kind e2e) — commits up to `f2e2459`.
- Phase 3 foundation + HTTP/2 + Read RET probing + gRPC —
  commits `43b604b`, `34cf654`, `308d3ab`, `f8d3627`.
- Phase 4 (privacy hardening, 5/8 gaps) — commits `fad8e3d`, `6714ccd`.
- Phase 3 #4 (stripped binaries) + #7 (amd64 disassembler) + #5
  (multi-version matrix) — commits `8b7024f`, `<this>`.

What's already in place that helps:
- HTTP/2 frame decoder + HPACK in `ebpf/events/http2.go` already extracts
  HEADERS (with `:method`, `:path`, `:status`, `grpc-encoding`, etc.) and
  buffers DATA frame bodies per stream.
- For gRPC-over-HTTP/2, the DATA frame payload is `1-byte compressed flag
  + 4-byte big-endian length + N bytes protobuf message`.

What needs to be added:
1. In `h2State.handleData` (or `emitStream`), detect gRPC by checking
   `content-type: application/grpc*` on the stream's headers.
2. For gRPC streams, parse the length-prefixed framing of the buffered
   DATA bytes and emit one message per gRPC frame instead of one per
   stream.
3. For method name: `:path` on a gRPC request is already `/pkg.Service/Method`.
4. Optionally: probe `google.golang.org/grpc.(*Server).processUnaryRPC`
   (Go-side) for richer metadata. **But the wire-format-only path is
   sufficient for v1** and avoids per-Go-version grpc package version
   coupling.

Estimated effort: ~4-6 hours.

Acceptance: a tiny gRPC server + client in `/tmp/`, run the agent against
the client PID, see gRPC method names + (some representation of) message
sizes in the captured output. Update `docs/phases/phase-3-results.md` and
the PR description with the result.

## Dev environment (re-create commands)

### Mac side — Docker Desktop + dev container

The dev container is named `pia-bpf-dev`. Image: `pia-agent-ebpf:test`
plus `postman-insights-agent-bpf-dev:latest`.

```bash
cd ~/playground/postman-insights-agent
make dev-build              # builds dev image (one-time / on Dockerfile.dev change)
make dev-shell              # interactive Linux shell inside it
# inside: bpftool, clang 14, libbpf, libpcap, go 1.24, --pid=host
```

If the dev container was torn down:
```bash
./build-scripts/dev-container.sh up
```

### Inside the dev container

Test workload binaries (rebuild if missing):
```bash
# Go HTTPS server on :9443
cat > /tmp/gohttps.go <<'EOF' && go build -o /tmp/gohttps /tmp/gohttps.go
package main
import ("crypto/tls"; "fmt"; "net/http"; "time")
func main() {
  http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintln(w, "hello-from-go-server")
  })
  srv := &http.Server{Addr: ":9443", TLSConfig: &tls.Config{}}
  go func() { time.Sleep(60*time.Second); srv.Close() }()
  srv.ListenAndServeTLS("/etc/nginx-https/cert.pem", "/etc/nginx-https/key.pem")
}
EOF

# Go HTTPS client looping http.Get
cat > /tmp/goclient.go <<'EOF' && go build -o /tmp/goclient /tmp/goclient.go
package main
import ("crypto/tls"; "fmt"; "io"; "net/http"; "os"; "time")
func main() {
  url := os.Getenv("TARGET_URL"); if url == "" { url = "https://127.0.0.1:9443/" }
  cli := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
  for i := 0; i < 30; i++ {
    r, _ := cli.Get(url); b, _ := io.ReadAll(r.Body); r.Body.Close()
    fmt.Println("client", r.StatusCode, string(b)); time.Sleep(time.Second)
  }
}
EOF

# nginx HTTPS on :8443 (cert+conf already at /etc/nginx-https/)
apt-get install -y --no-install-recommends nginx openssl >/dev/null 2>&1
[ -f /etc/nginx-https/cert.pem ] || openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout /etc/nginx-https/key.pem -out /etc/nginx-https/cert.pem \
  -days 1 -subj "/CN=localhost" 2>/dev/null
# nginx config lives at /etc/nginx-https/server.conf — see phase-2-results.md

# Build the agent
cd /workspace
make build-ebpf            # = go generate + go build -tags insights_bpf
```

### Smoke tests

```bash
# Phase 1/2 libssl path (against nginx 8443)
sudo bin/postman-insights-agent apidump-ebpf --duration 10s
curl -sk https://127.0.0.1:8443/                     # in another shell
# Expect: REQ method=GET / RESP status=200

# Phase 3 gotls path (against /tmp/gohttps or /tmp/goclient)
/tmp/gohttps &
sudo bin/postman-insights-agent apidump-gotls --pid $! --duration 10s
curl -sk https://127.0.0.1:9443/                     # any client; h1 or h2
# Expect: RESP status=200 (HTTP/2 default works as of commit 34cf654)

/tmp/goclient &
sudo bin/postman-insights-agent apidump-gotls --pid $! --duration 12s
# Expect: alternating REQ + RESP at 1Hz (client-side via Read RETs, since 308d3ab)
```

## Kind cluster — Phase 2 e2e

Cluster name: `pia-https-test`. Single control-plane node. Has
`/proc` bind-mount as `/linuxkit-proc` (so DaemonSet pods get root-ns
PIDs via `/host/proc`).

```bash
# Tear down + rebuild from scratch
kind delete cluster --name pia-https-test
kind create cluster --config test/kind/cluster.yaml

# Build + load the agent image, deploy
docker build -f test/kind/Dockerfile.agent -t pia-agent-ebpf:test --provenance=false .
kind load docker-image pia-agent-ebpf:test --name pia-https-test
kubectl apply -f test/kind/agent-daemonset.yaml
kubectl apply -f test/kind/workloads.yaml

# Wait, then watch
sleep 60
kubectl -n postman-insights logs -f ds/postman-insights-agent
```

The DaemonSet manifest currently runs `apidump-ebpf` (libssl path) with
`--target-namespaces=team-py,team-srv`. The Go client/server e2e in
kind has **not** been wired into this manifest yet — that's a small
follow-up (build `/tmp/gohttps`-style binaries into a container image,
deploy as pods, attach the gotls spike to them).

## Gotchas / lessons learned (capture them before context evaporates)

1. **HTTP/2 is Go's default over TLS.** Without the HTTP/2 frame decoder
   (commit `34cf654`), Go HTTPS captures look like encrypted noise with
   plaintext at the end (HPACK-compressed HEADERS + DATA frames). We
   now handle h2; new contributors will likely re-discover this if they
   add another Go probe and forget to route through `http2.go`.

2. **Go uretprobes don't work.** The runtime can move goroutine stacks
   during execution, invalidating the saved LR/return address. Use
   `FindReturnOffsets` + entry-style uprobes at each RET (the "OBI
   trick"). See `ebpf/programs/gotls.bpf.c::uprobe_gotls_read_ret` and
   `ebpf/collect_gotls_linux.go::Attach`.

3. **Cgroup paths inside containers show `0::/../..`** — NOT just in kind,
   on real K8s too with cgroup-namespace isolation (default on K8s 1.24+
   containerd). The fix is **not** moving to the root cgroup ns. Use the
   CRI client to enumerate container init PIDs, then bridge PID namespaces
   via the **cgroup-namespace inode** (`/proc/<pid>/ns/cgroup` → `cgroup:[N]`).
   The inode is the same regardless of which namespace you read from.
   See `ebpf/discovery/kube_linux.go`.

4. **`tcp_tw_reuse=2` on Docker LinuxKit kernels** means sequential
   loopback curls can reuse the same ephemeral port. If you see "all
   captures show the same source port" on a loopback test, that's the
   kernel, not a bug. Real K8s nodes default `tcp_tw_reuse=0`.

5. **Kind has nested PID namespaces** (LinuxKit VM → kind node → pod).
   `hostPID: true` on the DaemonSet gives the *kind node's* PID
   namespace, not the LinuxKit root. We bind-mount `/proc` from the
   LinuxKit VM into the kind node as `/linuxkit-proc` (see
   `test/kind/cluster.yaml`'s `extraMounts`) and from there into the
   agent pod as `/host/proc`. On real K8s there's no nesting and
   `hostPID: true` is sufficient.

6. **Go register ABI is NOT System V C.** On amd64 with Go 1.17+, args
   go in `rax, rbx, rcx, rdi, rsi, r8, r9, r10, r11, r12`. The goroutine
   pointer is in `r14`. First return slot is in `rax`. On arm64, args
   in `x0..x7`, goroutine in `x28`, return in `x0`. Documented in
   `ebpf/programs/gotls.bpf.c::go_arg / goroutine_ptr / go_ret`.

7. **Symbol resolution vs offset-attach in cilium/ebpf**: `Uprobe(symbol,
   prog, opts)` with non-empty symbol uses ELF symbol-table lookup
   (works for Go's mangled names like `crypto/tls.(*Conn).Write`).
   `Uprobe("", prog, &UprobeOptions{Address: file_offset})` is
   absolute-file-offset attach — needed for RET probes since RETs aren't
   named symbols. Don't use `UprobeOptions.Offset` — that's a relative
   offset against a symbol's resolved address, not an absolute file offset.

8. **Statically-linked Node 20** has BoringSSL baked into the `node`
   binary; `/proc/<pid>/maps` shows no `libssl.so*`. Our `FindLibSSL`
   returns `ErrNotFound`. The fallback `FindStaticLibSSL` is a
   placeholder. Phase 3 task #4 closes this.

9. **kind load image churn**: `kind load docker-image NAME:TAG` may
   leave the OLD image present alongside the new one and pods can pull
   the wrong one. `docker exec <node> crictl rmi NAME:TAG` before
   reload, then verify with `crictl images | grep NAME`.

## Demo "what works today" (showable to customers)

- Phase 2: kind cluster → `kubectl logs ds/postman-insights-agent` →
  HTTPS captures from real pods with namespace filtering, IP resolution,
  thermostat firing.
- Phase 3: `apidump-gotls --pid <GO_PID>` against a Go HTTPS server OR
  client → bidirectional REQ/RESP at any of HTTP/1.1 / HTTP/2.

## Demo "what does NOT work today" (be upfront)

- Java HTTPS (Spring Boot, Netty, Tomcat, gRPC-Java) — Phase 5.
- Go gRPC method/message decoding — HTTP/2 frames captured but gRPC
  framing not yet parsed (Phase 3 task #3).
- Static-libssl Node.js, Envoy-static — Phase 3 task #4.
- Production-grade privacy: 7 of 8 design-doc privacy gaps open. The
  `--privacy-mode=strict` and `--privacy-mode=dry-run` flags are
  PASSTHROUGHS today. **Do not enable HTTPS capture for non-trial
  customers until Phase 4.**

## State of the test environment as of last commit

- Docker Desktop running, container `pia-bpf-dev` was up at session end.
- Kind cluster `pia-https-test` was up at session end.
- Workloads in kind: `team-py/client-py`, `team-node/client-node`,
  `team-srv/server`.
- All committed on `feat/https-capture-ebpf` at commit `308d3ab`
  (Phase 3 task #2).

If the dev container is gone: `make dev-build && make dev-shell`.
If the kind cluster is gone: see "Kind cluster" section above.

## Open questions / decisions deferred

1. **Should `--privacy-mode` start enforcing something?** Today it's a
   passthrough flag. Phase 4 needs to define what `strict` and
   `dry-run` actually do at the redaction layer.
2. **Cross-arch BPF objects in CI.** We ship `libssl_arm64_bpfel.{go,o}`
   only. amd64 generation needs a Linux/amd64 CI runner. Until then,
   amd64 deployments must `go generate` at build time.
3. **Adapter ↔ http2 ownership.** Currently the adapter routes HTTP/2
   bytes to a per-flow `h2State`. If we add net/http-layer probes
   later, we need to decide whether they also route through h2 or get
   their own path. Multi-layer dedup is task #6 of Phase 3.
4. **gRPC method tagging strategy.** Decode-from-wire (simple, no Go-
   version coupling) vs probe-grpc-package (richer, requires per-
   version DWARF). Recommendation: wire-only for v1, probe-based as a
   later optimization.
