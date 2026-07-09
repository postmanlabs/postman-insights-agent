# Postman Insights mutating admission webhook — SRE runbook

**Scope:** day-2 operations for the `postman-insights-webhook`
Kubernetes mutating admission webhook. This is the workflow document
that SREs use to install, upgrade, troubleshoot, and roll back the
webhook safely.

**Audience:** site reliability / platform engineers operating a real
production Kubernetes cluster.

**Last validated:** phase 5c.3c, against `kind` v1.35. See
[`docs/phases/phase-5c3c-results.md`](phases/phase-5c3c-results.md).

---

## Why the webhook exists

The Postman Insights agent captures HTTPS traffic via eBPF. For Java
workloads it needs a small Java agent (`-javaagent:postman-java-agent.jar`)
loaded into each instrumented JVM. Asking every service team to add a
flag is impractical, so this webhook injects it automatically at pod
creation time. Workloads opt in by labeling their namespace.

## Blast radius (read this first)

A misconfigured `MutatingWebhookConfiguration` is one of the few
mechanisms in Kubernetes that can break **cluster-wide pod creation**.
The defaults in our Helm chart are designed around that risk:

| Property | Default | Why |
| --- | --- | --- |
| `failurePolicy` | `Ignore` | Webhook outage CANNOT block pod creation |
| `timeoutSeconds` | `5` | Bounded latency contribution to pod creation |
| `namespaceSelector` | `postman.com/insights=enabled` | Opt-in only — existing namespaces are unaffected |
| `objectSelector` | empty | Can be tightened further per deployment |
| `sideEffects` | `None` | Required for non-dry-run admission |

**Never** change `failurePolicy: Ignore` to `failurePolicy: Fail`
without:
1. A rehearsed `kubectl delete mutatingwebhookconfiguration` runbook.
2. A second pair of eyes on the change.
3. A staging cluster where the new value has run for at least 24 h.

## Pre-install checklist

```sh
# 1. The chart is version-pinned to a specific agent image.
echo "image.tag must NOT be empty or 'latest'"

# 2. TLS material exists. Either:
#    (a) a Secret you've created with `kubectl create secret tls ...`, OR
#    (b) cert-manager v1.5+ is installed in the cluster
kubectl get crd | grep certificates.cert-manager.io

# 3. The target namespace exists.
kubectl get ns postman-insights || kubectl create ns postman-insights

# 4. You have cluster-admin (or at least `mutatingwebhookconfigurations` create)
kubectl auth can-i create mutatingwebhookconfigurations
```

## Install

### Mode 1: BYO Secret (no cert-manager required)

```sh
# Pre-create the Secret. Use a CA that the API server trusts (your
# corporate PKI), or a self-signed cert for non-production.
kubectl -n postman-insights create secret tls postman-insights-webhook-tls \
    --cert=path/to/webhook.crt \
    --key=path/to/webhook.key

# Compute the CA bundle (base64-encoded PEM)
CA_B64=$(base64 < path/to/ca-bundle.pem | tr -d '\n')

helm install postman-insights-webhook ./charts/postman-insights-webhook \
    --namespace postman-insights \
    --set image.tag=v0.X.Y \
    --set tls.mode=secret \
    --set tls.secret.name=postman-insights-webhook-tls \
    --set tls.secret.caBundle=$CA_B64
```

### Mode 2: cert-manager (recommended for production)

```sh
# Pre-req: ClusterIssuer (or Issuer in the namespace)
kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: selfsigned     # or your corporate ACME issuer
spec:
  selfSigned: {}
EOF

helm install postman-insights-webhook ./charts/postman-insights-webhook \
    --namespace postman-insights \
    --set image.tag=v0.X.Y \
    --set tls.mode=cert-manager \
    --set tls.certManager.issuerRef.kind=ClusterIssuer \
    --set tls.certManager.issuerRef.name=selfsigned
```

## Post-install verification (5 steps)

```sh
# 1. Webhook pods are Running
kubectl -n postman-insights get pod -l app.kubernetes.io/name=postman-insights-webhook
# Expected: N/N replicas in Running, 1/1 Ready

# 2. Healthz returns 200 via in-cluster DNS
kubectl run probe --rm -i --image=curlimages/curl:8.5.0 --restart=Never -- \
    curl -sk --max-time 5 https://postman-insights-webhook.postman-insights.svc/healthz
# Expected: "ok"

# 3. MutatingWebhookConfiguration has the right safety properties
kubectl get mutatingwebhookconfiguration postman-insights-webhook \
    -o jsonpath='{.webhooks[0].failurePolicy}{"\n"}{.webhooks[0].timeoutSeconds}{"\n"}'
# Expected: "Ignore" and "5"

# 4. Unlabeled namespaces are unaffected
kubectl run sanity --image=registry.k8s.io/pause:3.9 --restart=Never -n default
kubectl get pod sanity -n default -o jsonpath='{.spec.containers[0].env}'
# Expected: empty (no mutation)
kubectl delete pod sanity -n default

# 5. Labeled namespaces ARE mutated
kubectl label namespace default postman.com/insights=enabled --overwrite
kubectl run java-test --image=tomcat:10-jdk21 --restart=Never -n default
kubectl get pod java-test -n default -o jsonpath='{.spec.containers[0].env}'
# Expected: [{"name":"JAVA_TOOL_OPTIONS","value":"-javaagent:/postman/postman-java-agent.jar"}]
kubectl delete pod java-test -n default
kubectl label namespace default postman.com/insights-  # remove label
```

## Rollback

### Emergency: webhook is causing cluster-wide issues

ONE command stops ALL webhook involvement in pod creation cluster-wide:

```sh
kubectl delete mutatingwebhookconfiguration postman-insights-webhook
```

After this command, the API server stops calling the webhook. Existing
pods are unaffected. New pods are created without instrumentation.

This is **always safe** because:
* `failurePolicy: Ignore` means the API server already tolerates
  webhook outages; removing the config has the same effect.
* The webhook does not own/manage any cluster resources besides itself.

### Routine: removing the chart

```sh
helm uninstall postman-insights-webhook -n postman-insights
```

This removes everything the chart created: the Deployment, Service,
ServiceAccount, MutatingWebhookConfiguration, and (if `cert-manager`
mode) the Certificate. It does NOT remove pre-existing Secrets you
supplied or namespace labels you set.

## Upgrade

### Image rebuild only (most common)

```sh
helm upgrade postman-insights-webhook ./charts/postman-insights-webhook \
    --namespace postman-insights \
    --reuse-values \
    --set image.tag=v0.X.Z
```

Helm performs a rolling restart. Set `replicaCount: 2+` for zero-downtime
upgrades.

### Chart shape change

Always run `helm diff upgrade --dry-run` first if you have the helm-diff
plugin:

```sh
helm diff upgrade postman-insights-webhook ./charts/postman-insights-webhook \
    --namespace postman-insights \
    --reuse-values \
    -f new-values.yaml
```

If `helm diff` isn't installed, use `--dry-run --debug` on the regular
upgrade command.

### Cert rotation

* In `tls.mode=cert-manager`, cert-manager rotates automatically —
  `renewBefore: 720h` (30 days). The webhook Deployment doesn't need a
  restart; cert-manager updates the Secret in place.
* In `tls.mode=secret`, you rotate the cert yourself. After updating the
  Secret, restart the webhook pods so they pick up the new cert:
  `kubectl rollout restart -n postman-insights deploy/postman-insights-webhook`.

## Troubleshooting

### "Pod creation hangs / times out"

Look for the webhook in the API server's audit log or the pod's events:

```sh
kubectl describe pod <stuck-pod> -n <ns>   # check Events section
kubectl logs -n postman-insights -l app.kubernetes.io/name=postman-insights-webhook --tail=200
```

If the webhook is slow or unreachable, `failurePolicy: Ignore` means
the API server will proceed after `timeoutSeconds` (5 s by default).
That's a 5-second latency floor on every pod CREATE in
opted-in namespaces. If 5 s of latency is unacceptable for a particular
namespace, remove the opt-in label.

### "Pods aren't being mutated"

Walk the chain:

```sh
# 1. Is the namespace opted in?
kubectl get ns <ns> --show-labels | grep postman.com/insights=enabled

# 2. Does the pod's container image match the Java workload regex?
kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.containers[*].image}'
# Compare against .Values.mutation.javaImageRegex in your release.
# Quick check:
helm get values postman-insights-webhook -n postman-insights -a | grep javaImageRegex

# 3. Did the webhook receive the request?
kubectl logs -n postman-insights deploy/postman-insights-webhook | grep -i mutate

# 4. Are there admission errors?
kubectl get events -n <ns> --field-selector reason=FailedCreate
```

### "Healthz fails"

Common causes:
* TLS cert SAN doesn't match the Service DNS name. Inspect:
  `kubectl get secret -n postman-insights <secret> -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -text -noout | grep -A1 'Subject Alt'`
  Must include `postman-insights-webhook.postman-insights.svc`.
* CA bundle in `MutatingWebhookConfiguration` doesn't match the cert.
  If you're in `tls.mode=secret`, the `caBundle` in the chart values
  must be the CA that signed the cert in the Secret.

### "kube-apiserver complains about webhook"

```
failed calling webhook: Post "https://...": x509: certificate signed by unknown authority
```

Re-render the chart with the correct CA bundle:

```sh
helm upgrade postman-insights-webhook ./charts/postman-insights-webhook \
    --namespace postman-insights --reuse-values \
    --set tls.secret.caBundle=<new-b64>
```

## Known limitations

<<<<<<< HEAD
### LIMIT-1: ByteBuddy can't parse JDK 25 class files (RESOLVED)

**Status:** Resolved in commit `dede34c`. The shaded ByteBuddy was bumped
from 1.14.13 to 1.17.5 (which supports class file version 69 = JDK 25)
alongside a Shadow plugin migration (`johnrengelman.shadow` 8.1.1 →
`gradleup.shadow` 8.3.6). Verified end-to-end against `tomcat:10`
(JDK 25.0.3 LTS): agent attaches in ~230 ms with no ByteBuddy errors
and HTTPS-from-inside-container curls return 200.

The historical entry is kept below for context.

#### Historical: ByteBuddy can't parse JDK 25 class files
=======
### LIMIT-1: ByteBuddy can't parse JDK 25 class files
>>>>>>> 0014e33 (feat(kube-webhook): phase 5c.3c — Helm chart + SRE runbook)

Surfaced in phase 5c.3b. The shaded `byte-buddy` in the agent JAR
officially supports up to JDK 22 (class file version 66). JDK 25 (class
file 69) makes ByteBuddy throw:

```
Java 25 (69) is not supported by the current version of Byte Buddy
which officially supports Java 22 (66)
```

The agent's `premain` attaches successfully, but no transformations are
installed — instrumentation produces no events for that pod.

**Affected workloads:** any image silently bumped to JDK 25, including
`tomcat:10` as of mid-2025.

**Workaround:** pin to a JDK ≤ 21 base image. For Tomcat, use
`tomcat:10-jdk21`.

**Permanent fix:** bump `byte-buddy` and `byte-buddy-agent` versions in
the Java agent build. Tracked for a future agent release.

<<<<<<< HEAD
### LIMIT-2: `keytool` and `jar` subprocesses fail agent attach (RESOLVED)

**Status:** Resolved. `Agent.attach` now has an early-exit guard
`shouldSkipForCliToolJVM()` that detects short-lived JDK CLI tools
(`keytool`, `jarsigner`, `jar`, `javac`, `javadoc`, `jshell`, `jcmd`,
`jstack`, `jmap`, `jps`, `jstat`, `jinfo`, `jhsdb`, `jlink`, `jmod`,
`jdeps`, `jdeprscan`, `jpackage`, `jconsole`, `jdb`, `jrunscript`,
`jwebserver`) via `sun.java.command` and skips the agent attach
with a single-line note. The primary (long-running) JVM is unaffected.

Escape hatch: setting `-Dpostman.agent.force=true` bypasses the guard,
in case a caller really does want the agent in (say) `jshell`.

20 JUnit cases cover positive matches (wrapper-script + FQN forms),
real-workload negatives (Spring Boot, Tomcat, Kafka, generic JAR), and
edge cases (missing/empty `sun.java.command`, force-flag override,
path normalisation).

The historical entry is kept below for context.

#### Historical: `keytool` / `jar` / `javac` subprocesses fail agent attach
=======
### LIMIT-2: `keytool` and `jar` subprocesses fail agent attach
>>>>>>> 0014e33 (feat(kube-webhook): phase 5c.3c — Helm chart + SRE runbook)

Surfaced in phase 5c.3b. When an instrumented JVM shells out to
`keytool` (or `jar` / `javac`), the subprocess inherits
`JAVA_TOOL_OPTIONS` and tries to attach the agent. Attach fails with:

```
agent attach FAILED at native step: java.lang.NoClassDefFoundError: sun/misc/Unsafe
```

This is harmless: `keytool` is a short-lived CLI tool, exits normally,
and the parent JVM continues with the agent loaded fine. No end-user
impact — verified end-to-end in 5c.3c (5 REQ + 5 RESP captured from a
HelloHttps JVM that shelled out to `keytool` for cert generation).

**Permanent fix:** the agent should detect that it's running in a known
CLI tool process and skip attach. Tracked for a future agent release.

### LIMIT-3: One-pod-at-a-time during init

The init container performs a `cp` from `/opt/postman-java-agent.jar`
to the shared volume. For very high pod-create throughput (e.g., a CI
namespace creating hundreds of pods per second), this adds ~200 ms per
pod. For typical service deployments this is invisible. If it ever
becomes a hot path, alternatives are:
* Use an initContainerless approach with a hostPath volume,
* Use a DaemonSet that pre-populates a node-local volume,
* Or rebuild every application image with the JAR pre-installed.

## Observability

The webhook itself exposes only `/healthz`. The capture path
(`apidump-javatls` + the existing libssl DaemonSet) is where the data
flows; that's covered by the agent's own metrics.

For webhook observability:

```sh
# Logs
kubectl logs -n postman-insights deploy/postman-insights-webhook

# Request rate / errors via kube-apiserver metrics (if you scrape them)
# Look at: apiserver_admission_webhook_request_total
#          apiserver_admission_webhook_rejection_count
```

## Disaster scenarios

### Webhook image is wedged / kept crashlooping

`failurePolicy: Ignore` saves the cluster. New pods just won't be
instrumented. Investigate at leisure:

```sh
kubectl describe pod -n postman-insights -l app.kubernetes.io/name=postman-insights-webhook
kubectl logs -n postman-insights -l app.kubernetes.io/name=postman-insights-webhook --previous
```

### TLS cert expired

* `cert-manager` mode: should never happen (auto-rotates with 30-day
  buffer). If it does, force a renewal:
  `kubectl cert-manager renew <certificate-name> -n postman-insights`.
* `secret` mode: API server starts rejecting the webhook with a TLS
  handshake error. `failurePolicy: Ignore` saves you. Rotate the
  Secret and `kubectl rollout restart` the Deployment.

### Wrong `caBundle` after a helm upgrade

Same symptom as expired cert. Same fix (`helm upgrade` with the right
`tls.secret.caBundle` value).

### Webhook is generating bad patches

Theoretically impossible if `failurePolicy: Ignore` and the webhook is
honest (it never gates — the 5c.3a unit tests assert this). But if it
ever happens (e.g., a buggy patch breaks pod admission), run the
rollback command immediately:

```sh
kubectl delete mutatingwebhookconfiguration postman-insights-webhook
```

The cluster recovers within seconds.

## Change log for this runbook

| Date | Phase | Change |
| --- | --- | --- |
| 5c.3c | initial draft, validated against kind | new |
