# Kind Service Test Guide: HTTPS and gRPC

Practical reference for testing HTTPS capture of **Java**, **node-service** and **dotnet-service** in the Kind cluster `pia-https-test`.

The DaemonSet runs `kube run --enable-https-capture` (libssl uprobes, and Java through the Java agent) and ships what it captures to Postman Insights, under the cluster `pia-kind-test`.
It does not log the requests themselves; its log shows what it attached to and, every 30 s, one `ebpf-stats: pod=<pod>` line per monitored pod, with the pod's own counters (`msgs` counts the HTTP messages captured for it), and one `ebpf-stats: node` line with what the node's pods share (the kernel's counters, `java_conn_*` among them):

```bash
kubectl logs -n postman-insights daemonset/postman-insights-agent
```

---

## Prerequisites

- Kind cluster: `kind-pia-https-test` (`kubectl config use-context kind-pia-https-test`)
- Tools on your Mac: `docker`, `kind`, `kubectl`, `curl`, `grpcurl`
- A Postman Insights API key: `export POSTMAN_INSIGHTS_API_KEY=...`
- Repo root:

```bash
cd /path/to/postman-insights-agent
export CACERT=test/kind/certs/hello-https-trust.pem
```

The Node.js and ASP.NET certs (`test/kind/certs/gen-java-service-certs.sh`) carry a **SAN** (`DNS:localhost,IP:127.0.0.1`) so **grpcurl** (Go TLS) accepts them. HTTPS curl works with or without SAN; gRPC from Mac requires it.

---

## Deploy and check

Each script builds the agent and its services' images, deploys them with the production DaemonSet (`agent-daemonset-prod.yaml`), sends HTTPS requests from the `test-clients` namespace, and checks the agent's `ebpf-stats` lines; it exits non-zero when a check fails.
They share their steps through `test/kind/lib.sh`.

```bash
./test/kind/deploy-java-service.sh    # Spring Boot and Netty, -javaagent and attach
./test/kind/deploy-node-service.sh    # Node.js on the shared libssl (--static: its own BoringSSL)
./test/kind/deploy-dotnet-service.sh  # ASP.NET Core; run after deploy-node-service.sh to check its outbound calls too

# Reuse the images already in kind
./test/kind/deploy-node-service.sh --skip-build
```

Then send more traffic by hand (below): gRPC, and requests from your Mac.

---

## How to test (two terminals per service)

1. **Terminal 1** - `kubectl port-forward` (leave running)
2. **Terminal 2** - `curl` / `grpcurl`, then check the pod's `ebpf-stats` line
3. **Ctrl+C** port-forward before moving to the next service (ports 8443 and 8446 are reused)

### Log check (all runtimes)

```bash
kubectl logs -n postman-insights daemonset/postman-insights-agent --since=2m \
  | grep -E 'attached libssl uprobes|Java agent|ebpf-stats'
```

After your requests, the next `ebpf-stats: pod=<pod>` line (within 30 s) shows the pod's `msgs` grown by two per request (the request and its response).

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
kubectl port-forward -n test-apps deployment/node-service 8443:8443 8446:8446
```

### HTTPS (Terminal 2)

```bash
curl --cacert "$CACERT" https://localhost:8443/phase5b2
```

| | |
|---|---|
| **Expected response** | `hello-from-node-combined-server phase=5b2` |
| **Check logs** | `kubectl logs -n postman-insights daemonset/postman-insights-agent --since=1m \| grep 'ebpf-stats: pod=node-service'` (`msgs` grows) |

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
| **Check logs** | `kubectl logs -n postman-insights daemonset/postman-insights-agent --since=1m \| grep 'ebpf-stats: pod=node-service'` (`msgs` grows) |

### Capture path

- **libssl uprobes** on `SSL_read` / `SSL_write` in the node process (`attached libssl uprobes pid=... probes=...` in the DaemonSet log).

### Optional: in-pod client

```bash
kubectl exec -n test-apps deployment/node-service -- node client.js 3
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
| **Check logs** | `kubectl logs -n postman-insights daemonset/postman-insights-agent --since=1m \| grep 'ebpf-stats: pod=dotnet-service'` (`msgs` grows) |

### HTTPS egress, dotnet to node (Terminal 2)

```bash
curl --cacert "$CACERT" 'https://localhost:8443/phase5b2/call-external?q=demo'
```

| | |
|---|---|
| **Expected response** | `ok outbound HTTPS GET` plus node response body |
| **Check logs** | `kubectl logs -n postman-insights daemonset/postman-insights-agent --since=1m \| grep -E 'ebpf-stats: pod=(dotnet\|node)-service'` |
| **Expected in logs** | dotnet-service's `msgs` grows by four per call (the inbound request and response, and its outbound ones to node-service), node-service's by two |

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
| **Check logs** | `kubectl logs -n postman-insights daemonset/postman-insights-agent --since=1m \| grep 'ebpf-stats: pod=dotnet-service'` (`msgs` grows) |

### Capture path

- Same as Node: **libssl uprobes** on the dotnet process (OpenSSL on Linux)

---

## Recommended test order

1. **Java** - `deploy-java-service.sh` (checks all three services)
2. **Node** - `deploy-node-service.sh`, then gRPC by hand
3. **ASP.NET** - `deploy-dotnet-service.sh` (inbound and, with node-service up, outbound HTTPS), then gRPC by hand

---

## Troubleshooting

| Symptom | What to try |
|---------|-------------|
| `address already in use` on 8443/8446 | Stop the previous `port-forward` (Ctrl+C) |
| `grpcurl: certificate relies on legacy Common Name` | Regenerate certs: `./test/kind/certs/gen-java-service-certs.sh --force` then redeploy (`deploy-node-service.sh --skip-build`) |
| `curl: (60) SSL certificate problem` | Run from repo root; confirm `$CACERT` exists; use `https://localhost` |
| `Discovery traffic TTL expired for service "test-apps/<name>"` in the DaemonSet log | In discovery mode the backend stops a service's capture when its discovery period ends: onboard the service in Postman (cluster `pia-kind-test`), or delete it there, then rerun its deploy script |
| `msgs` does not grow | The `ebpf-stats` lines come every 30 s: wait for the next one; use `--since=1m` or `-f` |
| No capture for Node/dotnet | Look for `attached libssl uprobes` for the pod's process in the DaemonSet log; the pod must belong to a Deployment (discovery mode skips standalone pods); rerun its deploy script |
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
./test/kind/deploy-node-service.sh --skip-build
./test/kind/deploy-dotnet-service.sh --skip-build
```

---

## Related docs

| Doc | Purpose |
|-----|---------|
| [`docs/https-capture-design.md`](../../docs/https-capture-design.md) | How HTTPS capture works, its limits and permissions |
| [`test/kind/deploy-java-service.sh`](deploy-java-service.sh) | Java services, with checks |
| [`test/kind/deploy-node-service.sh`](deploy-node-service.sh) | Node.js service, with checks |
| [`test/kind/deploy-dotnet-service.sh`](deploy-dotnet-service.sh) | ASP.NET Core service, with checks |
| [`test/kind/lib.sh`](lib.sh) | Steps the deploy scripts share |
