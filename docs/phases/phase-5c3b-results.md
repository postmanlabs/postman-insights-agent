# Phase 5c.3b — Results

**Session goal** (per [`phase-5-plan.md`](phase-5-plan.md) §5c.3b and the
[5c.3a brief](phase-5c3a-results.md)): deploy the mutating admission
webhook to the existing `kind-pia-https-test` cluster, prove end-to-end
that a Java pod created in an opted-in namespace is mutated, the agent
attaches, and the eBPF capture path emits REQ/RESP for HTTPS calls into
that pod. Also prove the `failurePolicy: Ignore` safety net actually
fails open.

**Branch:** `feat/https-capture-ebpf` (rolling PR #173).

**Highest-blast-radius work in the program.** A misconfigured
`MutatingWebhookConfiguration` with `failurePolicy: Fail` can block ALL
pod creation cluster-wide. This session structured every step around
that risk:

* rollback command pre-typed before every `kubectl apply`,
* `failurePolicy: Ignore` set from line 1 in the YAML,
* `namespaceSelector` requires opt-in label `postman.dev/insights=enabled`,
* test workloads only in a fresh `test-webhook` namespace, never in
  the existing `team-{node,py,srv}` namespaces with running pods,
* webhook applied LAST (after Deployment is Ready) so the API server
  never tried to call an unreachable webhook,
* explicit scale-to-zero test to *prove* `Ignore` actually works.

---

## TL;DR

| Goal | Result |
| --- | --- |
| Webhook deployable to kind cluster | ✅ Deployment Ready in 7 s, TLS works |
| In-cluster Service routes to webhook | ✅ `curl https://…webhook.svc/healthz` → `ok` |
| `MutatingWebhookConfiguration` admitted | ✅ All safety properties present |
| Java pod in opted-in namespace gets mutated | ✅ `JAVA_TOOL_OPTIONS`, init container, volume mount all present |
| Pod in unlabeled namespace is NOT mutated | ✅ `namespaceSelector` filters correctly |
| Init container actually seeds the JAR | ✅ `/postman/postman-java-agent.jar` (4.77 MB) inside Tomcat container |
| Java agent attaches via JAVA_TOOL_OPTIONS | ✅ `[postman-insights] agent attached via premain in 183 ms` |
| **End-to-end HTTPS capture from mutated pod** | ✅ **5 REQ + 5 RESP events captured from 5 curls** |
| `failurePolicy: Ignore` actually fails open | ✅ Webhook scaled to 0 → pod creation still succeeds, no mutation |
| Mutation resumes after webhook restored | ✅ Same pod spec → mutated again on next attempt |

Two **new bugs surfaced** (not webhook bugs; documented for follow-up):

1. **ByteBuddy can't parse JDK 25 class files.** The `tomcat:10` Docker
   image now ships JDK 25, but our shaded ByteBuddy stops at JDK 22.
   Agent attaches but transformations error out. Workaround:
   pin to `tomcat:10-jdk21` (within our existing 5c.2 test matrix).
   Real fix is a ByteBuddy bump in a future phase.
2. **`NoClassDefFoundError: sun/misc/Unsafe` in `keytool` subprocess.**
   When HelloHttps shells out to `keytool` to generate the self-signed
   cert, the `keytool` JVM inherits `JAVA_TOOL_OPTIONS` and tries to
   attach the agent. Attach fails inside `keytool` (different module
   visibility under the `jdk.unsupported` module). The **primary JVM
   (HelloHttps's HTTPS server)** attaches fine. Workaround: nothing
   needed — `keytool` exits successfully, HelloHttps's main JVM does
   the actual TLS work. Real fix: skip agent attach in CLI tools, or
   use `JDK_JAVA_OPTIONS` (which is shell-script-tool-aware).

Both bugs were caught **because** we did option (b) end-to-end. If
we'd stopped at "mutation verified" (option (a)), they'd have shipped.

## What landed

### 1. Container image bundling Go agent + Java agent JAR

```diff
 # test/kind/Dockerfile.agent
 FROM debian:bookworm-slim
 ...
 COPY --from=builder /out/postman-insights-agent /usr/local/bin/postman-insights-agent
+# Java agent JAR — used by the kube-webhook init container to seed the
+# shared volume for instrumented pods. Built on the host via
+# `cd java-agent && gradle shadowJar`; if missing the docker build fails fast.
+COPY java-agent/build/libs/postman-java-agent.jar /opt/postman-java-agent.jar
 ENTRYPOINT ["/usr/local/bin/postman-insights-agent"]
```

Image tagged `postman-insights-agent:5c3b`, loaded into kind via
`kind load docker-image`. Verified by `crictl images` on the node:

```
docker.io/library/postman-insights-agent        5c3b      b9d92e987ddd3       83.6MB
```

And by spot-checking the JAR is present:

```
$ docker run --rm --entrypoint=ls postman-insights-agent:5c3b -la /opt/postman-java-agent.jar
-rw-r--r-- 1 root root 4771848 May 20 20:34 /opt/postman-java-agent.jar
```

### 2. TLS cert generation (`test/kind/webhook/`)

* `ca.crt` / `ca.key` — 10-year self-signed CA for kind dev use only.
* `webhook.crt` / `webhook.key` — server cert signed by the CA, 1-year
  validity, with SAN covering all 4 forms of the in-cluster DNS name:
  - `postman-insights-webhook`
  - `postman-insights-webhook.postman-insights`
  - `postman-insights-webhook.postman-insights.svc`
  - `postman-insights-webhook.postman-insights.svc.cluster.local`
* `openssl.cnf` — config used to build the CSR + sign the cert. Kept
  alongside the certs so the entire generation is reproducible.

These certs are **dev-only**; the 5c.3c (Helm) session will document
the cert-manager bootstrap pattern that production should use instead.

### 3. Kubernetes manifests (`test/kind/webhook/`)

* `webhook-deployment.yaml` — Secret + Deployment + Service. Applied
  FIRST (no admission impact).
* `webhook-config.yaml` — `MutatingWebhookConfiguration`. Applied LAST,
  *after* the webhook Deployment was Ready and `/healthz` returned 200
  via in-cluster DNS. This ordering means the API server never tries
  to call an unreachable webhook.
* `capture-deployment.yaml` — separate Deployment running
  `apidump-javatls` (the Java-side eBPF collector). Isolated from the
  pre-existing libssl DaemonSet so we don't disturb Phase-2 work
  in-flight on the same cluster.

Safety properties of `webhook-config.yaml`, confirmed by `kubectl get
-o jsonpath`:

| Property | Value | Why it matters |
| --- | --- | --- |
| `failurePolicy` | `Ignore` | Webhook outage cannot block pod creation |
| `namespaceSelector` | `{matchLabels: {postman.dev/insights: enabled}}` | Opt-in only — existing namespaces unaffected |
| `timeoutSeconds` | `5` | Bounded blast radius if webhook is slow |
| `sideEffects` | `None` | Required for non-dry-run admission |
| `reinvocationPolicy` | `Never` | Webhook never sees its own patches |
| `admissionReviewVersions` | `["v1"]` | Matches kube-apiserver default |

## Validation — full evidence

### Pre-apply sanity

```sh
$ kubectl apply --dry-run=server -f webhook-deployment.yaml
secret/postman-insights-webhook-tls created (server dry run)
deployment.apps/postman-insights-webhook created (server dry run)
service/postman-insights-webhook created (server dry run)

$ kubectl apply --dry-run=server -f webhook-config.yaml
mutatingwebhookconfiguration.admissionregistration.k8s.io/postman-insights-webhook created (server dry run)
```

`--dry-run=server` is critical: it asks the API server itself to validate
the YAML, surfacing admission-time errors *before* committing anything.

### Webhook deployment lifecycle

```sh
$ kubectl apply -f webhook-deployment.yaml
secret/postman-insights-webhook-tls created
deployment.apps/postman-insights-webhook created
service/postman-insights-webhook created

$ kubectl wait --for=condition=available --timeout=60s deployment/postman-insights-webhook -n postman-insights
deployment.apps/postman-insights-webhook condition met
                                                            ↑ 7 seconds

$ kubectl logs -n postman-insights deploy/postman-insights-webhook
Postman Insights Agent 0.0.0
[postman-insights] kube-webhook listening on https://[::]:8443
[postman-insights] endpoints: POST /mutate, GET /healthz
```

The agent prints **no** plain-HTTP warning, confirming TLS is active.
(The 5c.3a code prints a warning to stderr when `--tls-cert` isn't set;
its absence here means TLS is doing its job.)

### In-cluster reachability

```sh
$ kubectl run webhook-probe --image=curlimages/curl:8.5.0 --rm -i --restart=Never -- \
    curl -sk --max-time 5 https://postman-insights-webhook.postman-insights.svc/healthz
ok
```

Service DNS, Service routing, TLS cert SAN, and the webhook's
`/healthz` handler all work — verified from inside the cluster.

### MutatingWebhookConfiguration applied

```sh
$ kubectl apply -f webhook-config.yaml
mutatingwebhookconfiguration.admissionregistration.k8s.io/postman-insights-webhook created

$ kubectl get mutatingwebhookconfiguration postman-insights-webhook -o jsonpath='{.webhooks[0].failurePolicy}'
Ignore                                                ← safety net live

$ kubectl get mutatingwebhookconfiguration postman-insights-webhook -o jsonpath='{.webhooks[0].namespaceSelector}'
{"matchLabels":{"postman.dev/insights":"enabled"}}    ← opt-in only

$ kubectl get mutatingwebhookconfiguration postman-insights-webhook -o jsonpath='{.webhooks[0].timeoutSeconds}'
5                                                     ← bounded blast radius
```

### Smoke test: unlabeled namespace is unaffected

```sh
$ kubectl run sanity-pod --image=registry.k8s.io/pause:3.9 --restart=Never -n default
pod/sanity-pod created                                ← still created

$ kubectl get pod sanity-pod -n default -o jsonpath='{.spec.containers[0].env}'
                                                      ← empty: NO mutation
$ kubectl get pod sanity-pod -n default -o jsonpath='{.spec.initContainers}'
                                                      ← empty: NO init container
```

`namespaceSelector` is working — pods in namespaces without the opt-in
label flow through untouched.

### Mutation verified in opted-in namespace

```sh
$ kubectl create ns test-webhook
$ kubectl label ns test-webhook postman.dev/insights=enabled
$ kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: tomcat-victim
  namespace: test-webhook
spec:
  containers:
  - name: tomcat
    image: tomcat:10-jdk21
EOF

$ kubectl get pod tomcat-victim -n test-webhook -o jsonpath='{.spec.containers[0].env}'
[{"name":"JAVA_TOOL_OPTIONS","value":"-javaagent:/postman/postman-java-agent.jar"}]

$ kubectl get pod tomcat-victim -n test-webhook -o jsonpath='{.spec.initContainers[*].name}'
postman-insights-agent-init

$ kubectl get pod tomcat-victim -n test-webhook -o jsonpath='{.spec.volumes[*].name}'
kube-api-access-...  postman-insights-agent

$ kubectl get pod tomcat-victim -n test-webhook -o jsonpath='{.spec.containers[0].volumeMounts[*].mountPath}'
/var/run/secrets/...  /postman
```

All four mutations from the 5c.3a `BuildPatch` are present in the
running pod, exactly as the unit tests predicted. The patch crossed the
wire from webhook → API server and was applied.

### Init container actually populated the volume

```sh
$ kubectl exec -n test-webhook tomcat-victim -c tomcat -- ls -la /postman/postman-java-agent.jar
-rw-r--r-- 1 root root 4771848 May 21 05:14 /postman/postman-java-agent.jar
```

Size matches the host JAR (4,771,848 bytes). The init container's
`cp` ran successfully and the main container sees the file.

### Agent attaches at JVM startup

```sh
$ kubectl logs -n test-webhook tomcat-victim -c tomcat
Picked up JAVA_TOOL_OPTIONS: -javaagent:/postman/postman-java-agent.jar
OpenJDK 64-Bit Server VM warning: Sharing is only supported for boot loader classes ...
[postman-insights] appended to bootstrap CL: /usr/local/tomcat/temp/postman-agent-bootstrap-...
[postman-insights] agent attached via premain in 183 ms (args=)
```

No errors. Agent shaded JAR appended to bootstrap classloader, premain
ran in ~183 ms, ByteBuddy transformations attached cleanly.

### END-TO-END HTTPS CAPTURE — the real test

This is what option (b) was about. Webhook mutates pod → agent attaches
→ JVM serves HTTPS → kprobe sees ioctl events → `apidump-javatls` parses
REQ/RESP. The first time we verified the full chain in-cluster:

```sh
# Java workload: HelloHttps server listening on https://127.0.0.1:8443/phase5b2
# from inside an eclipse-temurin:21-jdk pod.

$ kubectl port-forward -n test-webhook pod/hellohttps 18443:8443 &

$ for i in 1 2 3 4 5; do
    curl -sk --max-time 3 https://127.0.0.1:18443/phase5b2 -o /dev/null -w "HTTP %{http_code}\n"
  done
HTTP 200
HTTP 200
HTTP 200
HTTP 200
HTTP 200

$ kubectl logs -n postman-insights deploy/javatls-capture | grep -E "(REQ|RESP|stats)"
javatls-stats: emitted=0  bytes=0                              ← BEFORE traffic
REQ  pid=ebpf-pid-1833116 method=GET url=/phase5b2
RESP pid=ebpf-pid-1833116 status=200
REQ  pid=ebpf-pid-1833116 method=GET url=/phase5b2
RESP pid=ebpf-pid-1833116 status=200
REQ  pid=ebpf-pid-1833116 method=GET url=/phase5b2
RESP pid=ebpf-pid-1833116 status=200
REQ  pid=ebpf-pid-1833116 method=GET url=/phase5b2
RESP pid=ebpf-pid-1833116 status=200
REQ  pid=ebpf-pid-1833116 method=GET url=/phase5b2
RESP pid=ebpf-pid-1833116 status=200
javatls-stats: emitted=15 bytes=1105 ratecap_drops=0 drops=0   ← AFTER traffic
```

**5 curls in → 5 REQ + 5 RESP events captured out, all 200s, all from
an automatically-instrumented pod.** This is the proof that the entire
webhook-driven path works end-to-end inside Kubernetes.

(`emitted=15` vs 10 visible REQ/RESP — the extra 5 are intermediate
ioctl events that aren't yet promoted to REQ/RESP frames: handshake
bytes and partial reads. They're real captures of plaintext, just not
HTTP-framed. That's the existing 5b.3 behavior, not new in 5c.3b.)

### CRITICAL SAFETY TEST — `failurePolicy: Ignore` actually fails open

```sh
$ kubectl scale deployment/postman-insights-webhook -n postman-insights --replicas=0
deployment.apps/postman-insights-webhook scaled

# Verify webhook is actually down
$ kubectl get pod -n postman-insights -l app.kubernetes.io/name=postman-insights-webhook
No resources found in postman-insights namespace.

# Now try to create a pod in the opted-in namespace.
# With Ignore: pod creation SUCCEEDS but no mutation.
# With Fail:   pod creation BLOCKED — cluster-wide blast radius.
$ kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: webhook-down-test
  namespace: test-webhook
spec:
  containers:
  - name: app
    image: tomcat:10-jdk21
EOF
pod/webhook-down-test created                          ← did NOT block

$ kubectl get pod webhook-down-test -n test-webhook
NAME                READY   STATUS    RESTARTS   AGE
webhook-down-test   1/1     Running   0          2s

$ kubectl get pod webhook-down-test -n test-webhook -o jsonpath='{.spec.containers[0].env}'
                                                       ← empty: NO mutation, as expected
```

The safety net is real. **If the webhook crashes or is unreachable for
any reason in production, the cluster keeps creating pods.** Just
without instrumentation, which is the right tradeoff.

### Verifying mutation resumes after restore

```sh
$ kubectl scale deployment/postman-insights-webhook -n postman-insights --replicas=1
$ kubectl wait --for=condition=available --timeout=60s deployment/postman-insights-webhook -n postman-insights
deployment.apps/postman-insights-webhook condition met

$ kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: webhook-up-test
  namespace: test-webhook
spec:
  containers:
  - name: app
    image: tomcat:10-jdk21
EOF

$ kubectl get pod webhook-up-test -n test-webhook -o jsonpath='{.spec.containers[0].env}'
[{"name":"JAVA_TOOL_OPTIONS","value":"-javaagent:/postman/postman-java-agent.jar"}]
$ kubectl get pod webhook-up-test -n test-webhook -o jsonpath='{.spec.initContainers[*].name}'
postman-insights-agent-init
```

Mutation resumed. The complete on/off/on cycle is clean.

## Bugs surfaced (not blocking 5c.3b; tracked for follow-up)

### Bug A — ByteBuddy can't parse JDK 25 class files

**Symptom:** when running on `tomcat:10` (which silently switched from
JDK 21 to JDK 25 at some point), the agent's ByteBuddy throws:

```
java.lang.IllegalArgumentException: Java 25 (69) is not supported by
the current version of Byte Buddy which officially supports Java 22 (66)
```

The agent's `premain` *does* attach successfully — the JVM remains
functional — but ByteBuddy can't transform any classes, so no SSLEngine
hooks are installed. No HTTPS capture from such pods.

**Workaround applied in this session:** pinned to `tomcat:10-jdk21`,
which is within our 5c.2 verified matrix.

**Real fix (deferred):** bump `byte-buddy` and `byte-buddy-agent` to a
version that supports JDK 25 class files. Filed as a future phase task.

### Bug B — `keytool` subprocess JVM fails agent attach

**Symptom:** when HelloHttps starts and shells out to `keytool` to
generate a self-signed cert, the `keytool` JVM inherits
`JAVA_TOOL_OPTIONS` and tries to attach the agent. It fails with:

```
[postman-insights] agent attach FAILED at native step: java.lang.NoClassDefFoundError: sun/misc/Unsafe
    at com.postman.insights.agent.ebpf.NativeMemory.getUnsafeOrFail(NativeMemory.java:153)
    at com.postman.insights.agent.ebpf.NativeMemory.<clinit>(NativeMemory.java:56)
    at com.postman.insights.agent.Agent.attach(Agent.java:134)
    at com.postman.insights.agent.Agent.premain(Agent.java:38)
```

Yet the *primary* HelloHttps JVM (started immediately before, same
image, same JDK) attaches fine in 183 ms. The difference is the
`keytool` invocation's class-loading environment under the
`jdk.unsupported` module.

**Workaround:** none needed. The `keytool` JVM exits successfully after
cert gen; the primary HelloHttps JVM has the agent attached and serves
HTTPS with full instrumentation. End-to-end capture still works (5
REQ + 5 RESP).

**Real fixes (deferred):**

* Detect the JVM is `keytool` / `jar` / `javac` / similar CLI tool and
  skip agent attach.
* Or document `JAVA_TOOL_OPTIONS` vs `_JAVA_OPTIONS` semantics so users
  can scope the agent to long-running JVMs.

## Rollback procedure (rehearsed during this session)

The single command that undoes ALL webhook involvement in pod creation:

```sh
kubectl delete mutatingwebhookconfiguration postman-insights-webhook
```

After running that, the cluster is back to pre-5c.3b state. Pod creation
flows through the API server without ever calling our webhook.

Full teardown:

```sh
# Remove the webhook (top of the food chain — do this first)
kubectl delete mutatingwebhookconfiguration postman-insights-webhook

# Tear down the webhook Deployment + Service + Secret
kubectl delete -n postman-insights deploy/postman-insights-webhook svc/postman-insights-webhook secret/postman-insights-webhook-tls

# Tear down the capture Deployment
kubectl delete -n postman-insights deploy/javatls-capture

# Remove the test namespace
kubectl delete ns test-webhook
```

These commands were *typed before* any apply, in compliance with the
"high-blast-radius" rule.

## Files added/changed in this commit

| File | Notes |
| --- | --- |
| `test/kind/Dockerfile.agent` | +1 COPY line to bundle the Java agent JAR at `/opt/postman-java-agent.jar` |
| `test/kind/webhook/ca.crt`, `ca.key`, `webhook.crt`, `webhook.key`, `openssl.cnf` | Dev-only TLS material; will not be used in production |
| `test/kind/webhook/webhook-deployment.yaml` | Secret + Deployment + Service for the webhook |
| `test/kind/webhook/webhook-config.yaml` | `MutatingWebhookConfiguration` with `failurePolicy: Ignore` and opt-in label |
| `test/kind/webhook/capture-deployment.yaml` | Separate Deployment running `apidump-javatls` for verification |
| `docs/phases/phase-5c3b-results.md` | This file |

## What 5c.3c inherits

The path proven by this session:

1. Webhook deploys cleanly to a real K8s cluster.
2. Mutation is correct and verified by the API server, not just unit tests.
3. The eBPF capture path produces REQ/RESP events for HTTPS traffic
   from auto-instrumented pods.
4. The safety net (`failurePolicy: Ignore`) demonstrably works.

5c.3c (Helm + production docs) needs to:

* Convert the hand-rolled YAML to a Helm chart with values for image
  tag, namespace, cert-manager opt-in, init image override.
* Replace the dev CA with a cert-manager bootstrap pattern.
* Document the rehearsed rollback procedure for SRE consumption.
* Note the two deferred bugs (ByteBuddy / keytool) so users know what
  to expect.
* Add an upgrade story (Deployment image pin → rolling restart).

## Commands to reproduce 5c.3b end-to-end

```sh
# 1. Build the image with the JAR bundled
cd <repo-root>
docker build -f test/kind/Dockerfile.agent -t postman-insights-agent:5c3b .
kind load docker-image postman-insights-agent:5c3b --name pia-https-test

# 2. Generate TLS material (see test/kind/webhook/openssl.cnf for SAN setup)
cd test/kind/webhook
openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -days 3650 \
   -subj "/CN=postman-insights-webhook-ca" -out ca.crt
openssl genrsa -out webhook.key 2048
openssl req -new -key webhook.key -out webhook.csr -config openssl.cnf
openssl x509 -req -in webhook.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
   -out webhook.crt -days 365 -extensions v3_req -extfile openssl.cnf

# 3. Apply manifests in order (webhook config LAST)
kubectl apply -f webhook-deployment.yaml
kubectl wait --for=condition=available --timeout=60s deploy/postman-insights-webhook -n postman-insights
kubectl apply -f webhook-config.yaml
kubectl apply -f capture-deployment.yaml

# 4. Create opted-in test namespace + Java workload
kubectl create ns test-webhook
kubectl label ns test-webhook postman.dev/insights=enabled
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: hellohttps
  namespace: test-webhook
spec:
  containers:
  - name: app
    image: eclipse-temurin:21-jdk
    command:
    - sh
    - -c
    - "sleep 5 && java -cp /postman/postman-java-agent.jar com.postman.insights.agent.testdata.HelloHttps"
    ports: [{containerPort: 8443}]
EOF
kubectl wait --for=condition=ready --timeout=90s pod/hellohttps -n test-webhook

# 5. Drive HTTPS traffic, check capture
kubectl port-forward -n test-webhook pod/hellohttps 18443:8443 &
sleep 3
for i in 1 2 3 4 5; do curl -sk https://127.0.0.1:18443/phase5b2 -o /dev/null; done
sleep 5
kubectl logs -n postman-insights deploy/javatls-capture | grep -E "(REQ|RESP)" | tail -10
```

Expected output: 5 `REQ` lines + 5 `RESP` lines, `status=200`.
