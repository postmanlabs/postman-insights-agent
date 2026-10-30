# Kind Service Test Guide — HTTPS + gRPC

Practical reference for testing HTTPS capture of **Java**, **node-service** and **dotnet-service** in the Kind cluster `pia-https-test`.

All captured traffic appears in **one log stream**:

```bash
kubectl logs -n postman-insights daemonset/postman-insights-agent
```

The DaemonSet runs `kube run --enable-https-capture` (libssl uprobes, and Java through the Java agent).

---

## Prerequisites

- Kind cluster: `kind-pia-https-test` (`kubectl config use-context kind-pia-https-test`)
- Tools on your Mac: `kubectl`, `curl`, `grpcurl`
- Repo root:

```bash
cd /path/to/postman-insights-agent
export CACERT=test/kind/certs/hello-https-trust.pem
```

The Node.js and ASP.NET certs (`test/kind/certs/gen-java-service-certs.sh`) carry a **SAN** (`DNS:localhost,IP:127.0.0.1`) so **grpcurl** (Go TLS) accepts them. HTTPS curl works with or without SAN; gRPC from Mac requires it.

---

## Deploy (build + apply only — no full test traffic)

These scripts prepare the cluster. You still send HTTPS/gRPC traffic manually (below).

```bash
# Agent + Java services, with checks (needs POSTMAN_INSIGHTS_API_KEY)
./test/kind/deploy-java-service.sh

# Agent + Node
./test/kind/deploy-e2e-demo.sh

# ASP.NET (builds dotnet image every run)
./test/kind/deploy-dotnet-service.sh

# Skip image rebuild if nothing changed
./test/kind/deploy-e2e-demo.sh --skip-build
```

`deploy-java-service.sh` sends requests to each Java service and checks the agent's `ebpf-stats` lines; see its header.
`deploy-e2e-demo.sh` runs one in-cluster curl smoke test against **node** only. It does not test gRPC or dotnet.

---

## How to test (two terminals per service)

1. **Terminal 1** — `kubectl port-forward` (leave running)
2. **Terminal 2** — `curl` / `grpcurl`, then check DaemonSet logs
3. **Ctrl+C** port-forward before moving to the next service (ports 8443 and 8446 are reused)

### Unified log check (all runtimes)

```bash
kubectl logs -n postman-insights daemonset/postman-insights-agent --since=2m \
  | grep -E 'phase5|Greeter|REQ |RESP '
```

Follow live:

```bash
kubectl logs -n postman-insights daemonset/postman-insights-agent -f \
  | grep -E 'phase5|Greeter|REQ |RESP '
```

---

## 1. Java

`deploy-java-service.sh` deploys three Spring Boot and Netty services on port 8443 (HTTPS only, self-signed certificates generated in their images):

| Deployment | How the Java agent gets in |
|---|---|
| `java-service` | `-javaagent` at start (Tomcat, the JDK's `SSLEngine`) |
| `netty-service` | `-javaagent` at start (Netty's OpenSSL engine) |
| `java-service-attach` | none at start: the DaemonSet attaches it to the running JVM |

### Port-forward (Terminal 1)

```bash
kubectl port-forward -n test-apps deployment/java-service-attach 8443:8443
```

### HTTPS (Terminal 2)

```bash
curl -k 'https://localhost:8443/hello?name=mac'
curl -k https://localhost:8443/orders/42
```

| | |
|---|---|
| **Expected response** | `{"message":"hello mac"}` |
| **Check logs** | `kubectl logs -n postman-insights daemonset/postman-insights-agent --since=1m \| grep -E 'Java agent\|ebpf-stats'` |
| **Expected in logs** | `Java agent ... attached to JVM ...`, and `ebpf-stats` lines with `java_events` and the pod's `msgs` growing |

### Capture path

- **In the app pod:** the Postman Insights Java agent hooks `SSLEngine` and `SSLSocket` and writes each plaintext chunk as a frame to `/dev/null` at a magic offset.
- **On the node:** the DaemonSet's `java_tls` tracepoints read the frames into the same pipeline as libssl; see "Java capture" in [`docs/https-capture-design.md`](../../docs/https-capture-design.md).

---

## 2. Node (`node-service`)

### Port-forward (Terminal 1)

```bash
kubectl port-forward -n test-apps pod/node-service 8443:8443 8446:8446
```

### HTTPS (Terminal 2)

```bash
curl --cacert "$CACERT" https://localhost:8443/phase5b2
```

| | |
|---|---|
| **Expected response** | `hello-from-node-combined-server phase=5b2` |
| **Check logs** | `kubectl logs -n postman-insights daemonset/postman-insights-agent --since=1m \| grep -E 'phase5b2\|REQ \|RESP '` |

### gRPC (Terminal 2)

```bash
grpcurl -cacert "$CACERT" \
  -import-path test/kind/node-service/proto \
  -proto greeter.proto \
  -d '{"name":"mac-node"}' \
  localhost:8446 phase5c2.Greeter/SayHello
```

| | |
|---|---|
| **Expected response** | `{"message":"Hello mac-node"}` |
| **Check logs** | `kubectl logs -n postman-insights daemonset/postman-insights-agent --since=1m \| grep -E 'Greeter\|SayHello\|REQ \|RESP '` |

### Capture path

- **libssl uprobes** on `SSL_read` / `SSL_write` in the node process → DaemonSet logs REQ/RESP

### Optional: in-pod client

```bash
kubectl exec -n test-apps node-service -- node client.js 3
```

---

## 3. ASP.NET (`dotnet-service`)

Deploy node-service first if testing egress (dotnet calls node over HTTPS).

### Port-forward (Terminal 1)

```bash
kubectl port-forward -n test-apps deployment/dotnet-service 8443:8443 8446:8446
```

### HTTPS ingress (Terminal 2)

```bash
curl --cacert "$CACERT" https://localhost:8443/phase5b2
```

| | |
|---|---|
| **Expected response** | `hello-from-dotnet-combined-server phase=5b2` |
| **Check logs** | `kubectl logs -n postman-insights daemonset/postman-insights-agent --since=1m \| grep -E 'phase5b2\|REQ \|RESP '` |

### HTTPS egress — dotnet → node (Terminal 2)

```bash
curl --cacert "$CACERT" 'https://localhost:8443/phase5b2/call-external?q=demo'
```

| | |
|---|---|
| **Expected response** | `ok outbound HTTPS GET` plus node response body |
| **Check logs** | `kubectl logs -n postman-insights daemonset/postman-insights-agent --since=1m \| grep -E 'phase5b2\|call-external\|from=dotnet\|REQ \|RESP '` |
| **Expected in logs** | Ingress to dotnet **and** dotnet→node egress (`/phase5b2?from=dotnet&...`) |

### gRPC (Terminal 2)

```bash
grpcurl -cacert "$CACERT" \
  -import-path test/kind/dotnet-service/Protos \
  -proto greeter.proto \
  -d '{"name":"mac-dotnet"}' \
  localhost:8446 phase5c2.Greeter/SayHello
```

| | |
|---|---|
| **Expected response** | `{"message":"Hello mac-dotnet"}` |
| **Check logs** | `kubectl logs -n postman-insights daemonset/postman-insights-agent --since=1m \| grep -E 'Greeter\|SayHello\|REQ \|RESP '` |

### Capture path

- Same as Node: **libssl uprobes** on the dotnet process (OpenSSL on Linux)

---

## Recommended test order

1. **Java** - HTTPS (`deploy-java-service.sh` checks all three services)  
2. **Node** - HTTPS, then gRPC  
3. **ASP.NET** - HTTPS ingress, egress (`call-external`), then gRPC  

---

## Troubleshooting

| Symptom | What to try |
|---------|-------------|
| `address already in use` on 8443/8446 | Stop the previous `port-forward` (Ctrl+C) |
| `grpcurl: certificate relies on legacy Common Name` | Regenerate certs: `./test/kind/certs/gen-java-service-certs.sh --force` then redeploy (`deploy-e2e-demo.sh --skip-build`) |
| `curl: (60) SSL certificate problem` | Run from repo root; confirm `$CACERT` exists; use `https://localhost` |
| Empty grep on logs | Re-run curl/grpcurl; wait ~2s; use `--since=1m` or `-f` |
| No capture for Node/dotnet | `kubectl rollout restart -n postman-insights daemonset/postman-insights-agent`; wait 15s; ensure test-apps pods are Running |
| No capture for Java | Look for the JVM's `Java agent ...` line in the DaemonSet log (attached, skipped or failed, with the reason); `--https-libraries` must include `java` (the default) |
| dotnet egress fails | Ensure `node-service` is Running in `test-apps` |

### Verify cluster health

```bash
kubectl get pods -n postman-insights
kubectl get pods -n test-apps
kubectl get daemonset postman-insights-agent -n postman-insights \
  -o jsonpath='{.spec.template.spec.containers[0].args}{"\n"}'
```

Expected DaemonSet args include: `kube`, `run`, `--enable-https-capture`, `--discovery-mode`, `--include-namespaces=test-apps`.

### Regenerate certs (customer-style)

```bash
./test/kind/certs/gen-java-service-certs.sh --force
# Then redeploy services so ConfigMap + pods pick up new certs
./test/kind/deploy-e2e-demo.sh --skip-build
./test/kind/deploy-dotnet-service.sh
```

---

## Related docs

| Doc | Purpose |
|-----|---------|
| [`docs/https-capture-design.md`](../../docs/https-capture-design.md) | How HTTPS capture works, its limits and permissions |
| [`test/kind/deploy-java-service.sh`](deploy-java-service.sh) | Java services, with checks |
| [`test/kind/deploy-e2e-demo.sh`](deploy-e2e-demo.sh) | One-shot deploy (agent + Node) |
| [`test/kind/deploy-dotnet-service.sh`](deploy-dotnet-service.sh) | Dotnet deploy |
