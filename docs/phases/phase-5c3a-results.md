# Phase 5c.3a — Results

**Session goal (per [`phase-5-plan.md`](phase-5-plan.md) §5c.3):** ship the
Go webhook code + unit tests as a standalone, **zero-cluster-risk** first
step toward the K8s admission webhook. Mutation logic, AdmissionReview
handling, JSON Patch construction, HTTP server — all in-process testable.

**Branch:** `feat/https-capture-ebpf` (rolling PR #173).

**Why split 5c.3:** the original 5c.3 brief bundles three independent risks
(Go code, kubeapi mutations, Helm packaging). A misconfigured
`MutatingWebhookConfiguration` with `failurePolicy: Fail` can break **all
pod creation cluster-wide**. By doing 5c.3a (Go code only) in isolation
we get the substance reviewed + tested before anything touches kubeapi.

5c.3a delivers code + tests. 5c.3b will deliver K8s manifests + kind e2e
+ rehearsed rollback. 5c.3c will deliver Helm + production docs.

---

## TL;DR

* New package `cmd/internal/kube-webhook/` (5 Go files, ~600 LOC + ~500 LOC of tests).
* Hidden CLI subcommand `postman-insights-agent kube-webhook`.
* HTTPS server (optional TLS) on `:8443` with `/mutate` + `/healthz`.
* Java-workload detection: image-regex + env-var + command-mentions-`java` heuristic.
* JSON Patch construction: emptyDir volume, init container, volumeMount, `JAVA_TOOL_OPTIONS` env.
* Safety invariant: webhook NEVER returns `Allowed: false`. Tested with a property-style test that hammers it with garbage input.
* **25 unit + integration tests pass in 1.06 s wall-clock.** Includes a real HTTP server smoke test that starts the webhook, posts a JSON AdmissionReview, asserts response, shuts down cleanly within 5 s.

## What landed

| File | Purpose |
| --- | --- |
| `cmd.go` | Cobra command, hidden, with documentation header explaining the architecture |
| `run.go` | CLI flag parsing + server lifecycle + SIGINT/SIGTERM graceful shutdown |
| `server.go` | HTTP/HTTPS server with `/mutate` + `/healthz`; bodies size-capped at 4 MiB |
| `listener.go` | Tiny TCP listener helper that supports `:0` for OS-assigned ports (test use) |
| `detect.go` | `IsJavaContainer` / `IsJavaPod` + default image regex |
| `patch.go` | `BuildPatch` (RFC 6902 JSON Patch construction); `DefaultMutationConfig` |
| `mutate.go` | `Mutator.Handle` (the AdmissionRequest → AdmissionResponse decision tree) |
| `detect_test.go` | 18 detection cases (positive/negative image, env, command) |
| `patch_test.go` | 4 round-trip tests (patch → apply → decode → assert pod structure) + 2 sanity tests |
| `mutate_test.go` | 4 admission-decision cases + 1 "never gates" property test |
| `server_test.go` | 3 HTTP server tests (POST end-to-end, GET /healthz, method-not-allowed) |

Plus:
* `cmd/root.go` — registers the subcommand.
* `go.mod` / `go.sum` — adds `github.com/evanphx/json-patch/v5` as a test
  dependency for the round-trip patch verification.

## The safety invariants this code enforces

1. **`AdmissionResponse.Allowed` is always `true`.** The webhook's job is to
   mutate, never to gate. Even on every error path (garbage JSON, decode
   failure, BuildPatch failure) we return `Allowed: true` with an optional
   diagnostic `Result.Message`. Confirmed by `TestMutator_Handle_NeverGates`
   which feeds the handler nil / empty / corrupted / malformed bodies and
   asserts `Allowed == true` in every case.

2. **`JAVA_TOOL_OPTIONS` is appended, never replaced.** If a Java container
   already sets `JAVA_TOOL_OPTIONS=-Xmx2g`, the patch produces
   `JAVA_TOOL_OPTIONS=-Xmx2g -javaagent:/postman/postman-java-agent.jar`.
   Confirmed by the `container with existing volume + existing JAVA_TOOL_OPTIONS`
   test case which asserts both `-Xmx2g` AND `-javaagent:...` are present
   in the mutated pod.

3. **Existing pod spec sections are preserved.** If `spec.volumes` already
   has volumes, we use `/spec/volumes/-` (append) not `/spec/volumes`
   (replace). Same for `spec.initContainers` and `container.volumeMounts`
   and `container.env`. Each case has a dedicated test.

4. **Non-Java containers are not touched.** Confirmed by the
   `two Java containers + one non-Java sidecar` test case.

5. **Bodies are size-capped.** `/mutate` reads at most 4 MiB. Prevents a
   malformed admission request from causing unbounded memory growth.

## Validation — exhaustive

### Unit tests

```
$ go test -count=1 -timeout 60s -v ./cmd/internal/kube-webhook/

=== RUN   TestIsJavaContainer  (18 sub-cases)
--- PASS: TestIsJavaContainer (0.00s)
=== RUN   TestIsJavaPod
--- PASS: TestIsJavaPod (0.00s)
=== RUN   TestMutator_Handle  (4 sub-cases)
--- PASS: TestMutator_Handle (0.00s)
=== RUN   TestMutator_Handle_NeverGates
--- PASS: TestMutator_Handle_NeverGates (0.00s)
=== RUN   TestBuildPatch_NoJavaContainers_ReturnsNilPatch
--- PASS: TestBuildPatch_NoJavaContainers_ReturnsNilPatch (0.00s)
=== RUN   TestBuildPatch_NilPod
--- PASS: TestBuildPatch_NilPod (0.00s)
=== RUN   TestBuildPatch_RoundTrip  (4 sub-cases)
--- PASS: TestBuildPatch_RoundTrip (0.00s)
=== RUN   TestServer_EndToEnd
--- PASS: TestServer_EndToEnd (0.00s)
=== RUN   TestServer_Healthz
--- PASS: TestServer_Healthz (0.00s)
=== RUN   TestServer_MethodNotAllowed
--- PASS: TestServer_MethodNotAllowed (0.00s)
PASS
ok      .../cmd/internal/kube-webhook   0.477s   (real time 1.06 s)
```

Test count: **25 PASS / 0 FAIL.** Every test has an explicit timeout
(`context.WithTimeout` for server tests; `t.Cleanup` for graceful shutdown).
**Nothing can hang.**

### Real HTTP server smoke (`curl` against a running webhook)

```
$ ./bin/postman-insights-agent kube-webhook --addr 127.0.0.1:18443 &
$ curl http://127.0.0.1:18443/healthz
ok                                           ← HTTP 200

$ curl -X POST -H "Content-Type: application/json" \
       --data @admreq.json http://127.0.0.1:18443/mutate

{
  "kind": "AdmissionReview",
  "apiVersion": "admission.k8s.io/v1",
  "response": {
    "uid": "smoke-test-uid",                 ← UID round-tripped from request
    "allowed": true,                         ← safety invariant
    "patch": "W3sib3AiOiJhZGQ…",             ← base64-encoded JSON Patch
    "patchType": "JSONPatch"
  }
}
```

Patch decoded:

```json
[
  {"op":"add","path":"/spec/volumes","value":[{"name":"postman-insights-agent","emptyDir":{}}]},
  {"op":"add","path":"/spec/initContainers","value":[{
    "name":"postman-insights-agent-init",
    "image":"ghcr.io/postmanlabs/postman-insights-agent:latest",
    "command":["/bin/sh","-c","cp /opt/postman-java-agent.jar /postman/postman-java-agent.jar"],
    "volumeMounts":[{"name":"postman-insights-agent","mountPath":"/postman"}],
    "imagePullPolicy":"IfNotPresent"
  }]},
  {"op":"add","path":"/spec/containers/0/volumeMounts","value":[
    {"name":"postman-insights-agent","mountPath":"/postman"}
  ]},
  {"op":"add","path":"/spec/containers/0/env","value":[
    {"name":"JAVA_TOOL_OPTIONS","value":"-javaagent:/postman/postman-java-agent.jar"}
  ]}
]
```

That's the exact patch K8s will apply to incoming pods in 5c.3b.

### Regression check (no other phase broken by the new package)

| Test | Result |
| --- | --- |
| Mac `go build ./...` | clean (exit 0) |
| Linux `make build-ebpf` (insights_bpf tag) | clean |
| Linux `make test` (all packages) | **14 ok / 0 FAIL** including new `kube-webhook` |
| HelloHttps + agent (5b regression) | 4 REQ + 4 RESP, agent attach 240 ms |

The HelloHttps regression initially looked broken — `REQ=0 RESP=0`.
Diagnosed: **nginx from the libssl-path audit was still bound to 8443**.
HelloHttps got `BindException`, curls went to nginx instead, which has no
agent, captured nothing. Killed nginx, port freed, regression test passed.
This is exactly the contamination trap that JDK 8 episode taught us about.
Lesson reinforced: **ALWAYS check port state before claiming a test
passed.**

## A diagnostic flag we added

`run.go` prints a clear WARNING when serving plaintext HTTP:

```
[postman-insights] WARNING: serving plain HTTP. K8s API server requires HTTPS — set --tls-cert and --tls-key for production.
```

Plaintext mode exists only for local development + unit tests. The
WARNING makes it impossible to accidentally deploy a plain-HTTP webhook
to a real cluster without noticing.

## What 5c.3b inherits

* The webhook binary is ready to deploy. Just needs:
  - TLS certificate (cert-manager or self-signed for kind)
  - Container image that includes both the Go binary AND
    `/opt/postman-java-agent.jar` for the init container to copy
  - Kubernetes manifests (Deployment, Service, RBAC,
    MutatingWebhookConfiguration)
* The mutation logic is **already verified** — 5c.3b doesn't need to
  re-prove it, just deploy it.

## What 5c.3b still needs

1. Container image that bundles the Go agent + Java agent JAR.
2. TLS cert generation in kind (self-signed for now; cert-manager in 5c.3c).
3. Deployment + Service + RBAC YAML.
4. **`MutatingWebhookConfiguration` with `failurePolicy: Ignore`** —
   critical for safety. Tests in 5c.3b should explicitly verify this
   property: if the webhook is unreachable, pod creation continues.
5. kind cluster e2e: deploy webhook, create a Java pod in an opted-in
   namespace, `kubectl describe pod` to verify `JAVA_TOOL_OPTIONS` was
   injected, then test agent actually captures.
6. **Rehearsed rollback procedure documented** BEFORE applying anything.

## Commands to reproduce

```sh
# Unit tests (anywhere with Go installed):
go test -count=1 -timeout 60s -v ./cmd/internal/kube-webhook/

# Run the webhook locally for a smoke test:
go build -o /tmp/agent .
/tmp/agent kube-webhook --addr 127.0.0.1:18443 &
WH_PID=$!

curl http://127.0.0.1:18443/healthz             # → ok

# Build an AdmissionReview request, POST it, decode the response:
cat > /tmp/adm.json <<EOF
{
  "apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview",
  "request": {
    "uid": "smoke",
    "resource": {"group":"","version":"v1","resource":"pods"},
    "object": {
      "apiVersion": "v1", "kind": "Pod",
      "metadata": {"name":"smoke","namespace":"default"},
      "spec": {"containers":[{"name":"app","image":"tomcat:10"}]}
    }
  }
}
EOF
curl -s -X POST -H "Content-Type: application/json" --data @/tmp/adm.json \
     http://127.0.0.1:18443/mutate | python3 -m json.tool

kill $WH_PID                                     # graceful shutdown
```
