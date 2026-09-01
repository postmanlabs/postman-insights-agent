# Kind Service Test Guide — HTTPS + gRPC

Practical reference for testing **java-service**, **node-service**, and **dotnet-service** in the Kind cluster `pia-https-test`.

All captured traffic (Java, Node, ASP.NET) appears in **one log stream**:

```bash
kubectl logs -n postman-insights daemonset/postman-insights-agent
```

The DaemonSet runs `apidump-ebpf --enable-javatls` (libssl uprobes + Java ioctl kprobe). There is no separate `javatls-capture` pod.

---

## Prerequisites

- Kind cluster: `kind-pia-https-test` (`kubectl config use-context kind-pia-https-test`)
- Tools on your Mac: `kubectl`, `curl`, `grpcurl`
- Repo root:

```bash
cd /path/to/postman-insights-agent
export CACERT=test/kind/certs/hello-https-trust.pem
```

Certs mirror the customer OpenSSL flow (`docs/nocheckin/glic.txt`) with one Kind addition: **SAN** (`DNS:localhost,IP:127.0.0.1`) so **grpcurl** (Go TLS) accepts the cert. HTTPS curl works with or without SAN; gRPC from Mac requires it.

---

## Deploy (build + apply only — no full test traffic)

These scripts prepare the cluster. You still send HTTPS/gRPC traffic manually (below).

```bash
# Agent + Java + Node
./test/kind/deploy-e2e-demo.sh

# ASP.NET (builds dotnet image every run)
./test/kind/deploy-dotnet-service.sh

# Skip image rebuild if nothing changed
./test/kind/deploy-e2e-demo.sh --skip-build
```

`deploy-e2e-demo.sh` runs one in-cluster curl smoke test against **node** only. It does not test Java, gRPC, or dotnet.

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

## 1. Java (`java-service`)

### Port-forward (Terminal 1)

```bash
kubectl port-forward -n test-apps pod/java-service 8443:8443 8446:8446
```

### HTTPS (Terminal 2)

```bash
curl --cacert "$CACERT" https://localhost:8443/phase5b2
```

| | |
|---|---|
| **Expected response** | `hello-from-combined-server phase=5b2` |
| **Check logs** | `kubectl logs -n postman-insights daemonset/postman-insights-agent --since=1m \| grep -E 'phase5b2\|REQ \|RESP '` |
| **Expected in logs** | `REQ ... url=/phase5b2` and `RESP ... status=200` |

### gRPC (Terminal 2 — same port-forward)

```bash
grpcurl -cacert "$CACERT" \
  -import-path java-agent/testdata/grpc-java/src/main/proto \
  -proto greeter.proto \
  -d '{"name":"mac-java"}' \
  localhost:8446 phase5c2.Greeter/SayHello
```

| | |
|---|---|
| **Expected response** | `{"message":"Hello mac-java"}` |
| **Check logs** | `kubectl logs -n postman-insights daemonset/postman-insights-agent --since=1m \| grep -E 'Greeter\|SayHello\|REQ \|RESP '` |

### Capture path

- **In app pod:** `postman-java-agent.jar` (ByteBuddy on `SSLEngine`) → `ioctl()` with plaintext
- **On node:** DaemonSet `java_tls` kprobe reads ioctl events → parses HTTP/gRPC → logs REQ/RESP

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

1. **Java** — HTTPS, then gRPC  
2. **Node** — HTTPS, then gRPC  
3. **ASP.NET** — HTTPS ingress, egress (`call-external`), then gRPC  

---

## Troubleshooting

| Symptom | What to try |
|---------|-------------|
| `address already in use` on 8443/8446 | Stop the previous `port-forward` (Ctrl+C) |
| `grpcurl: certificate relies on legacy Common Name` | Regenerate certs: `./test/kind/certs/gen-java-service-certs.sh --force` then redeploy (`deploy-e2e-demo.sh --skip-build`) |
| `curl: (60) SSL certificate problem` | Run from repo root; confirm `$CACERT` exists; use `https://localhost` |
| Empty grep on logs | Re-run curl/grpcurl; wait ~2s; use `--since=1m` or `-f` |
| No capture for Node/dotnet | `kubectl rollout restart -n postman-insights daemonset/postman-insights-agent`; wait 15s; ensure test-apps pods are Running |
| No capture for Java | Confirm java pod has `-javaagent`; DaemonSet args include `--enable-javatls` |
| dotnet egress fails | Ensure `node-service` is Running in `test-apps` |

### Verify cluster health

```bash
kubectl get pods -n postman-insights
kubectl get pods -n test-apps -l 'app in (java-service,node-service,dotnet-service)'
kubectl get daemonset postman-insights-agent -n postman-insights \
  -o jsonpath='{.spec.template.spec.containers[0].args}{"\n"}'
```

Expected DaemonSet args include: `apidump-ebpf`, `--enable-javatls`, `--target-namespaces=...test-apps`.

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
| [`docs/kind-e2e-demo-presentation.md`](../docs/kind-e2e-demo-presentation.md) | Architecture, stakeholder demo, production vs Kind |
| [`docs/loom-ebpf-demo-scripts.md`](../docs/loom-ebpf-demo-scripts.md) | Loom / video demo scripts |
| [`test/kind/certs/README.md`](certs/README.md) | TLS cert generation (`glic.txt` style) |
| [`test/kind/deploy-e2e-demo.sh`](deploy-e2e-demo.sh) | One-shot deploy (agent + java + node) |
| [`test/kind/deploy-dotnet-service.sh`](deploy-dotnet-service.sh) | Dotnet deploy |
