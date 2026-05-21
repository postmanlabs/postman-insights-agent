# Phase 5c.3c — Results

**Session goal** (per [`phase-5-plan.md`](phase-5-plan.md) §5c.3c and the
[5c.3b brief](phase-5c3b-results.md)): convert the hand-rolled
`test/kind/webhook/*.yaml` from 5c.3b into a proper Helm chart with
cert-manager + BYO-Secret modes, write the SRE runbook, validate the
chart produces the same working end-to-end result as 5c.3b.

**Branch:** `feat/https-capture-ebpf` (rolling PR #173).

**Blast radius:** **low**. Pure packaging — Helm chart templating, plus
docs. The hard / scary work was in 5c.3a (code) and 5c.3b (cluster).
This session adds the production deployment story on top.

---

## TL;DR

| Goal | Result |
| --- | --- |
| Helm chart with documented values | ✅ `deployment/helm/postman-insights-webhook/` |
| Chart lints cleanly | ✅ `helm lint` → 1 chart, 0 failed |
| Renders correctly in both TLS modes | ✅ `secret` mode → 4 resources; `cert-manager` mode → 5 resources (adds `Certificate`) |
| Fails fast when required value missing | ✅ Missing `caBundle` → clear error at template time |
| Server-side dry-run accepts rendered YAML | ✅ kubectl accepts all 4 resources |
| Chart actually installs into kind | ✅ `helm install --wait` succeeds in <30 s |
| Helm-installed webhook produces SAME end-to-end result as 5c.3b | ✅ **5 REQ + 5 RESP captured from auto-instrumented Java pod**, identical stats line (`emitted=15 bytes=1105`) |
| Helm uninstall is clean | ✅ All chart resources gone; pre-existing Secrets untouched (as documented) |
| SRE runbook covering install / upgrade / rollback / troubleshooting | ✅ `docs/webhook-runbook.md` |
| Known limitations from 5c.3b documented | ✅ ByteBuddy JDK 25 + keytool subprocess covered in runbook |

## What landed

```
deployment/helm/postman-insights-webhook/
├── Chart.yaml                                       # name, version, kubeVersion
├── values.yaml                                      # fully documented values
├── README.md                                        # chart-level user docs
└── templates/
    ├── _helpers.tpl                                 # naming + image helpers
    ├── serviceaccount.yaml
    ├── deployment.yaml
    ├── service.yaml
    ├── certificate.yaml                             # cert-manager mode only
    ├── mutatingwebhookconfiguration.yaml            # CRITICAL: failurePolicy: Ignore
    └── NOTES.txt                                    # post-install instructions

docs/
└── webhook-runbook.md                               # SRE runbook (13 kB)
```

## TLS modes

Two options gated by `tls.mode`:

| `tls.mode` | What the chart creates | Cert rotation | Extra cluster deps |
| --- | --- | --- | --- |
| `secret` (default) | No TLS resources — you supply a pre-existing Secret | Manual | None |
| `cert-manager` | A `Certificate` resource; cert-manager creates/rotates the Secret | Automatic | cert-manager ≥ v1.5 |

In `cert-manager` mode the `MutatingWebhookConfiguration` is annotated with
`cert-manager.io/inject-ca-from`, so cert-manager populates the `caBundle`
automatically — eliminating the bootstrap chicken-and-egg problem.

## Validation — chain of evidence

### Lint

```
$ docker run --rm -v $PWD/deployment/helm:/charts alpine/helm:3.14.0 \
    lint /charts/postman-insights-webhook

[INFO] Missing required value: .Values.tls.secret.caBundle is required when tls.mode=secret
==> Linting /charts/postman-insights-webhook
[INFO] Chart.yaml: icon is recommended

1 chart(s) linted, 0 chart(s) failed
```

The `INFO` about missing `caBundle` is exactly what we want: lint runs
against bare defaults (no override), exposing that the chart enforces
"you MUST provide a caBundle if you're in secret mode". Production
charts that silently accept incomplete config are a footgun.

### Render — secret mode

```
$ helm template release-test ./postman-insights-webhook \
      --set image.tag=5c3b \
      --set tls.secret.caBundle=BASE64CAHERE

kind: ServiceAccount        ← Created
kind: Service               ← Created
kind: Deployment            ← Created
kind: MutatingWebhookConfiguration  ← Created (with inline caBundle)
                              ↑ NO Certificate resource — correct for secret mode
```

### Render — cert-manager mode

```
$ helm template release-test ./postman-insights-webhook \
      --set image.tag=5c3b \
      --set tls.mode=cert-manager \
      --set tls.certManager.issuerRef.name=my-issuer

kind: ServiceAccount        ← Created
kind: Service               ← Created
kind: Deployment            ← Created
kind: Certificate           ← Created (cert-manager mode adds this)
kind: MutatingWebhookConfiguration  ← Created (annotated for cert-manager injection)
```

### Render — failure path

```
$ helm template release-test ./postman-insights-webhook \
      --set image.tag=5c3b
      # no caBundle, secret mode is default

Error: execution error at (postman-insights-webhook/templates/mutatingwebhookconfiguration.yaml:27:17):
.Values.tls.secret.caBundle is required when tls.mode=secret
```

Fails fast at template time with a clear message — no broken
deployment ever reaches the cluster.

### Server-side dry-run

```
$ kubectl apply --dry-run=server -f /tmp/helm-final.yaml

serviceaccount/postman-insights-postman-insights-webhook created (server dry run)
service/postman-insights-postman-insights-webhook created (server dry run)
deployment.apps/postman-insights-postman-insights-webhook created (server dry run)
mutatingwebhookconfiguration.admissionregistration.k8s.io/postman-insights-postman-insights-webhook created (server dry run)
```

The API server itself validated the rendered YAML.

### Live install into kind

After tearing down 5c.3b's hand-rolled resources, installed the chart
with release name `postman-insights-webhook` (so resources have clean
names rather than `postman-insights-postman-insights-webhook`):

```
$ helm install postman-insights-webhook ./postman-insights-webhook \
    --namespace postman-insights \
    --set image.tag=5c3b \
    --set image.repository=postman-insights-agent \
    --set image.pullPolicy=IfNotPresent \
    --set replicaCount=1 \
    --set tls.secret.name=postman-insights-webhook-tls \
    --set-file tls.secret.caBundle=/host/cabundle.b64 \
    --wait --timeout 90s

NAME: postman-insights-webhook
LAST DEPLOYED: 2026-05-21 ...
NAMESPACE: postman-insights
STATUS: deployed
REVISION: 1

$ helm list -n postman-insights
NAME                         REVISION   STATUS      CHART                              APP VERSION
postman-insights-webhook     1          deployed    postman-insights-webhook-0.1.0     0.0.0

$ kubectl get all -n postman-insights -l app.kubernetes.io/instance=postman-insights-webhook
NAME                                            READY   STATUS    RESTARTS   AGE
pod/postman-insights-webhook-...                1/1     Running   0          24s

NAME                               TYPE        CLUSTER-IP     PORT(S)   AGE
service/postman-insights-webhook   ClusterIP   10.96.32.126   443/TCP   24s

NAME                                       READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/postman-insights-webhook   1/1     1            1           24s

$ kubectl get mutatingwebhookconfiguration postman-insights-webhook \
    -o jsonpath='{.webhooks[0].failurePolicy}{"\n"}{.webhooks[0].namespaceSelector}{"\n"}{.webhooks[0].timeoutSeconds}{"\n"}'
Ignore
{"matchLabels":{"postman.dev/insights":"enabled"}}
5
```

Identical safety properties to 5c.3b's hand-rolled YAML.

### End-to-end capture via Helm-deployed webhook

The proof of equivalence — run the same end-to-end test as 5c.3b:

```
$ kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: hellohttps
  namespace: test-webhook
spec:
  containers:
  - name: app
    image: eclipse-temurin:21-jdk
    command: [sh, -c, "sleep 5 && java -cp /postman/postman-java-agent.jar com.postman.insights.agent.testdata.HelloHttps"]
EOF

$ kubectl get pod hellohttps -n test-webhook -o jsonpath='{.spec.containers[0].env}'
[{"name":"JAVA_TOOL_OPTIONS","value":"-javaagent:/postman/postman-java-agent.jar"}]
$ kubectl get pod hellohttps -n test-webhook -o jsonpath='{.spec.initContainers[*].name}'
postman-insights-agent-init
                                              ← Helm-deployed webhook mutated correctly

$ for i in 1 2 3 4 5; do
    curl -sk --max-time 3 https://127.0.0.1:18443/phase5b2 -w "HTTP %{http_code}\n" -o /dev/null
  done
HTTP 200
HTTP 200
HTTP 200
HTTP 200
HTTP 200

$ kubectl logs -n postman-insights deploy/javatls-capture | grep -E "(REQ|RESP|stats)" | tail -15

javatls-stats: emitted=0  bytes=0                                ← BEFORE traffic
REQ  pid=ebpf-pid-1842638 method=GET url=/phase5b2
RESP pid=ebpf-pid-1842638 status=200
REQ  pid=ebpf-pid-1842638 method=GET url=/phase5b2
RESP pid=ebpf-pid-1842638 status=200
REQ  pid=ebpf-pid-1842638 method=GET url=/phase5b2
RESP pid=ebpf-pid-1842638 status=200
REQ  pid=ebpf-pid-1842638 method=GET url=/phase5b2
RESP pid=ebpf-pid-1842638 status=200
REQ  pid=ebpf-pid-1842638 method=GET url=/phase5b2
RESP pid=ebpf-pid-1842638 status=200
javatls-stats: emitted=15 ratecap_drops=0 read_fail=0 bytes=1105  ← AFTER traffic
```

**5 curls in → 5 REQ + 5 RESP captured out, all 200s. Identical stats
to 5c.3b** (`emitted=15`, `bytes=1105`). The Helm chart produces a
webhook that behaves identically to the hand-rolled YAML.

### Helm uninstall — rollback verification

```
$ helm uninstall postman-insights-webhook -n postman-insights
release "postman-insights-webhook" uninstalled

$ kubectl get all -n postman-insights -l app.kubernetes.io/instance=postman-insights-webhook
NAME                                            READY   STATUS        RESTARTS   AGE
pod/postman-insights-webhook-...                1/1     Terminating   0          76s
                                                       ↑ shutting down cleanly

$ kubectl get mutatingwebhookconfiguration postman-insights-webhook
Error from server (NotFound): ...
                                                       ↑ webhook config GONE

$ kubectl run rollback-test --image=registry.k8s.io/pause:3.9 --restart=Never -n default
pod/rollback-test created
$ kubectl get pod rollback-test -n default
NAME            READY   STATUS              RESTARTS   AGE
rollback-test   0/1     ContainerCreating   0          1s
                                                       ↑ cluster pod creation works
                                                         (no orphaned webhook)
```

Helm-driven teardown is clean and the cluster is in the same state as
pre-install.

## The SRE runbook

`docs/webhook-runbook.md` (13 kB) covers:

* Why the webhook exists + blast-radius framing
* Pre-install checklist
* Install procedure (both TLS modes)
* 5-step post-install verification
* Rollback procedures (emergency + routine)
* Upgrade procedure (image rebuild vs chart shape change)
* Cert rotation (cert-manager auto / Secret manual)
* Troubleshooting: pod-creation hangs, no mutation, healthz fails, TLS
  errors
* Three known limitations (ByteBuddy JDK 25, keytool subprocess, init
  container throughput)
* Observability — what the webhook exposes, what kube-apiserver
  metrics to scrape
* Disaster scenarios: crashlooping, cert expired, bad caBundle, bad
  patches

The runbook is structured so that an SRE who has never seen this
project before can:
1. Install it safely (pre-flight checklist).
2. Verify it works (5-step post-install).
3. Roll it back (one-command emergency rollback).

## Files added in this commit

| File | LOC | Purpose |
| --- | --- | --- |
| `deployment/helm/postman-insights-webhook/Chart.yaml` | 22 | Chart metadata |
| `deployment/helm/postman-insights-webhook/values.yaml` | 130 | Documented values |
| `deployment/helm/postman-insights-webhook/templates/_helpers.tpl` | 65 | Naming + image helpers |
| `deployment/helm/postman-insights-webhook/templates/serviceaccount.yaml` | 13 | SA |
| `deployment/helm/postman-insights-webhook/templates/service.yaml` | 16 | Service |
| `deployment/helm/postman-insights-webhook/templates/deployment.yaml` | 90 | Deployment |
| `deployment/helm/postman-insights-webhook/templates/certificate.yaml` | 28 | cert-manager Certificate |
| `deployment/helm/postman-insights-webhook/templates/mutatingwebhookconfiguration.yaml` | 47 | Webhook config |
| `deployment/helm/postman-insights-webhook/templates/NOTES.txt` | 45 | helm-install greeting |
| `deployment/helm/postman-insights-webhook/README.md` | 165 | Chart-level user docs |
| `docs/webhook-runbook.md` | 350 | SRE runbook |
| `docs/phases/phase-5c3c-results.md` | this | session writeup |

## What's next

5c.3 is now feature-complete:

* **5c.3a** — Go webhook code + 25 unit tests (zero cluster risk) ✅
* **5c.3b** — Kind cluster e2e (5 REQ + 5 RESP from auto-instrumented Java pod) ✅
* **5c.3c** — Helm chart + SRE runbook (Helm-deployed webhook produces identical e2e result) ✅

The HTTPS-capture-via-eBPF program's Java + webhook track is **done**.
Remaining work is in the deferred bug list (ByteBuddy JDK 25, keytool
subprocess) and in other workstreams (Privacy gaps 2 and 4, JMH
benchmark) — all tracked in `SESSION-RESUME.md`.

## Commands to reproduce 5c.3c end-to-end

```sh
# 1. Build image (already done in 5c.3b)
docker build -f test/kind/Dockerfile.agent -t postman-insights-agent:5c3b .
kind load docker-image postman-insights-agent:5c3b --name pia-https-test

# 2. Lint + render the chart (no host install required)
docker run --rm -v $PWD/deployment/helm:/charts alpine/helm:3.14.0 \
    lint /charts/postman-insights-webhook

# 3. Pre-create TLS Secret + compute CA bundle
cd test/kind/webhook && ./gen-tls-and-manifests.sh && cd ../../..
kubectl -n postman-insights create secret tls postman-insights-webhook-tls \
    --cert=test/kind/webhook/webhook.crt --key=test/kind/webhook/webhook.key
CA_B64=$(base64 < test/kind/webhook/ca.crt | tr -d '\n')
echo "$CA_B64" > /tmp/cabundle.b64

# 4. Helm install
docker run --rm \
    -v $PWD/deployment/helm:/charts \
    -v /tmp:/host \
    -v ~/.kube:/root/.kube \
    -e KUBECONFIG=/root/.kube/config \
    --network host \
    alpine/helm:3.14.0 \
    install postman-insights-webhook /charts/postman-insights-webhook \
    --namespace postman-insights \
    --set image.tag=5c3b \
    --set image.repository=postman-insights-agent \
    --set replicaCount=1 \
    --set tls.secret.name=postman-insights-webhook-tls \
    --set-file tls.secret.caBundle=/host/cabundle.b64 \
    --wait --timeout 90s

# 5. Run the end-to-end test from phase-5c3b-results.md.
# Expected: 5 curls → 5 REQ + 5 RESP captured.

# 6. Helm uninstall
docker run --rm \
    -v ~/.kube:/root/.kube -e KUBECONFIG=/root/.kube/config \
    --network host \
    alpine/helm:3.14.0 \
    uninstall postman-insights-webhook -n postman-insights
```
