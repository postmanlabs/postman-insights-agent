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

```bash
kubectl rollout restart -n postman-insights daemonset/postman-insights-agent
kubectl wait -n test-apps --for=condition=Ready pod/dotnet-service --timeout=60s
sleep 15
kubectl logs -n postman-insights daemonset/postman-insights-agent --timestamps --since=2m \
  | grep -E 'phase5b2|Greeter|attached.*libssl|REQ |RESP '
```

Pod logs (app + kubectl timestamps):

```bash
kubectl logs -n test-apps deployment/dotnet-service --timestamps -f
```

Verify libssl in the container:

```bash
PID=$(kubectl exec -n test-apps dotnet-service -- sh -c 'pgrep -f DotnetService')
kubectl exec -n test-apps dotnet-service -- grep -E 'libssl|libcrypto' /proc/$PID/maps
```
