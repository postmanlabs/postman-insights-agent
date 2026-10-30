# ASP.NET Core HTTPS + gRPC test workload (Kind / local)

Models the **customer POC stack**: ASP.NET Core on Linux, **OpenSSL/libssl** via Kestrel, self-signed PEM certs, **8443** HTTPS + **8446** gRPC-TLS.

Capture path: `postman-insights-agent` DaemonSet → **libssl uprobes** (same as Node). No java-agent.

## Local (requires .NET 8 SDK)

```bash
./test/kind/run-dotnet-service-local.sh server   # terminal 1
./test/kind/run-dotnet-service-local.sh test     # terminal 2
```

## Kind

```bash
./test/kind/deploy-dotnet-service.sh
kubectl port-forward -n test-apps deployment/dotnet-service 8443:8443 8446:8446
```

From Mac:

```bash
CACERT=test/kind/certs/hello-https-trust.pem
curl --cacert "$CACERT" https://127.0.0.1:8443/phase5b2
grpcurl -cacert "$CACERT" \
  -import-path test/kind/dotnet-service/Protos -proto greeter.proto \
  -d '{"name":"demo"}' localhost:8446 phase5c2.Greeter/SayHello
```

In-pod client:

```bash
kubectl exec -n test-apps deploy/dotnet-service -- dotnet /app/client/DotnetClient.dll https://127.0.0.1 2
```

## eBPF capture check

`deploy-dotnet-service.sh` sends requests and checks the agent's `ebpf-stats` line for the pod (`msgs`, the HTTP messages captured).
By hand, after sending requests:

```bash
kubectl logs -n postman-insights daemonset/postman-insights-agent --since=2m \
  | grep -E 'attached libssl uprobes|ebpf-stats: pod=dotnet-service'
```

The agent does not log the requests themselves; the endpoints appear in Postman Insights under the cluster `pia-kind-test`.

Pod logs (app + kubectl timestamps):

```bash
kubectl logs -n test-apps deployment/dotnet-service --timestamps -f
```

Verify libssl in the container:

```bash
PID=$(kubectl exec -n test-apps dotnet-service -- sh -c 'pgrep -f DotnetService')
kubectl exec -n test-apps dotnet-service -- grep -E 'libssl|libcrypto' /proc/$PID/maps
```
