# postman-insights-webhook (Helm chart)

Mutating admission webhook that auto-injects the Postman Insights Java
agent into pods in opted-in namespaces, so the existing capture
pipelines can collect HTTPS traffic without per-workload changes.

* **Chart version:** 0.1.0
* **App version:** matches the `postman-insights-agent` image tag you
  set in `image.tag`.
* **Kubernetes:** 1.22+ (we use `admissionregistration.k8s.io/v1`).

This chart was validated end-to-end on `kind` v1.35 in phase 5c.3c:
1 webhook pod, 1 capture pod, 5 curls in → 5 REQ + 5 RESP captured from
auto-instrumented `eclipse-temurin:21-jdk` Java pod. Evidence in
[`docs/phases/phase-5c3c-results.md`](../../../docs/phases/phase-5c3c-results.md).

---

## Quick start

```sh
helm install postman-insights-webhook ./charts/postman-insights-webhook \
  --namespace postman-insights --create-namespace \
  --set image.tag=<your-tag> \
  --set tls.secret.name=<your-existing-tls-secret> \
  --set-file tls.secret.caBundle=path/to/ca-bundle.b64
```

After install, opt-in any namespace:

```sh
kubectl label namespace <your-ns> postman.com/insights=enabled
```

Any new pod created in that namespace whose container image matches the
Java-workload regex (Tomcat / Jetty / Spring Boot / Temurin / etc.) will
have `JAVA_TOOL_OPTIONS`, an init container, and a shared volume injected
automatically.

## TLS modes

The webhook MUST serve HTTPS — the K8s API server refuses to call a
plain-HTTP webhook. This chart supports two ways to provide TLS material:

### Mode 1: `tls.mode=secret` (default, no extra deps)

You supply a pre-existing Kubernetes Secret containing `tls.crt` +
`tls.key`. Rotation is your responsibility.

```sh
# Generate a self-signed cert (production should use a real CA)
openssl req -x509 -newkey rsa:2048 -nodes -keyout webhook.key -out webhook.crt \
    -subj "/CN=postman-insights-webhook.postman-insights.svc" \
    -addext "subjectAltName=DNS:postman-insights-webhook.postman-insights.svc,DNS:postman-insights-webhook.postman-insights.svc.cluster.local" \
    -days 365

# Create the Secret
kubectl -n postman-insights create secret tls postman-insights-webhook-tls \
    --cert=webhook.crt --key=webhook.key

# Install with the Secret's name and the CA bundle inlined
CA_B64=$(base64 < webhook.crt | tr -d '\n')   # self-signed CA = own cert
helm install postman-insights-webhook ./charts/postman-insights-webhook \
    --namespace postman-insights \
    --set image.tag=<...> \
    --set tls.mode=secret \
    --set tls.secret.name=postman-insights-webhook-tls \
    --set tls.secret.caBundle=$CA_B64
```

### Mode 2: `tls.mode=cert-manager` (recommended for production)

Requires [cert-manager](https://cert-manager.io/) v1.5+ in the cluster.
The chart creates a `Certificate` resource and cert-manager populates the
Secret + auto-rotates it. The `MutatingWebhookConfiguration` is annotated
with `cert-manager.io/inject-ca-from` so cert-manager injects the CA
bundle automatically — no manual `caBundle` value needed.

```sh
# Pre-req: a cert-manager Issuer or ClusterIssuer (in any namespace) — the
# easiest one is a self-signed ClusterIssuer for an internal-only webhook:
kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: selfsigned
spec:
  selfSigned: {}
EOF

# Install
helm install postman-insights-webhook ./charts/postman-insights-webhook \
    --namespace postman-insights \
    --set image.tag=<...> \
    --set tls.mode=cert-manager \
    --set tls.certManager.issuerRef.kind=ClusterIssuer \
    --set tls.certManager.issuerRef.name=selfsigned
```

## Values reference

See [`values.yaml`](./values.yaml) — every value is documented inline.
The most important ones:

| Value | Default | Notes |
| --- | --- | --- |
| `image.tag` | `""` | **MUST set.** Pin to a specific tag, not `latest`. |
| `replicaCount` | `2` | HA. Webhook is on the pod-create hot path. |
| `tls.mode` | `secret` | One of `secret` or `cert-manager`. |
| `webhook.failurePolicy` | `Ignore` | **Do not change to `Fail`** without rehearsed rollback. |
| `webhook.timeoutSeconds` | `5` | Bounded blast radius if the webhook is slow. |
| `webhook.namespaceSelector` | `{matchLabels: {postman.com/insights: enabled}}` | Opt-in only. |
| `mutation.initImage` | `""` (inherits `image`) | Image containing `/opt/postman-java-agent.jar`. |
| `mutation.javaImageRegex` | (see values.yaml) | Override to widen/narrow Java workload detection. |

## Rollback

Single command undoes ALL webhook involvement in pod creation:

```sh
kubectl delete mutatingwebhookconfiguration <release-name>
```

Full uninstall:

```sh
helm uninstall <release-name> -n <namespace>
```

`helm uninstall` does NOT remove:
* Pre-existing Secrets you supplied via `tls.secret.name`.
* The `postman.com/insights=enabled` namespace labels.

## Operations

See [`docs/webhook-runbook.md`](../../../docs/webhook-runbook.md) for the
full SRE runbook: install procedure, upgrade procedure, rollback,
troubleshooting, known limitations.

## Known limitations

Documented in detail in `docs/webhook-runbook.md`:

* **ByteBuddy can't parse JDK 25 class files.** Workaround: avoid
  `tomcat:10` (which silently switched to JDK 25); pin to `tomcat:10-jdk21`.
* **`keytool`/`jar`/`javac` subprocesses fail agent attach.** No
  end-user impact — the primary long-running JVM still gets instrumented.

## Reproducing the validation

```sh
# Render
docker run --rm -v "$PWD/charts:/charts" alpine/helm:3.14.0 \
    template postman-insights-webhook /charts/postman-insights-webhook \
    --namespace postman-insights \
    --set image.tag=5c3b \
    --set tls.secret.caBundle=$(base64 < test/kind/webhook/ca.crt | tr -d '\n')

# Lint
docker run --rm -v "$PWD/charts:/charts" alpine/helm:3.14.0 \
    lint /charts/postman-insights-webhook
```
