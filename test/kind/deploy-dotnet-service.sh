#!/usr/bin/env bash
# Build + deploy dotnet-service (ASP.NET HTTPS + gRPC) to kind.
#
# Local smoke (no kind):
#   ./test/kind/run-dotnet-service-local.sh server
#   ./test/kind/run-dotnet-service-local.sh test
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CERT_DIR="$REPO_ROOT/test/kind/certs"
IMAGE=pia-dotnet-service:test
CLUSTER=pia-https-test
NS=test-apps
CM=test-apps-tls

"$CERT_DIR/gen-java-service-certs.sh"

kubectl config use-context "kind-${CLUSTER}" 2>/dev/null || true

echo "==> Building ${IMAGE}"
docker build -f "$REPO_ROOT/test/kind/Dockerfile.dotnet-service" -t "$IMAGE" "$REPO_ROOT"

echo "==> Loading image into kind"
kind load docker-image "$IMAGE" --name "$CLUSTER"

kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -

kubectl create configmap "$CM" -n "$NS" \
  --from-file="$CERT_DIR/grpc-cert.pem" \
  --from-file="$CERT_DIR/grpc-key.pem" \
  --from-file="$CERT_DIR/hello-https-keystore.p12" \
  --from-file="$CERT_DIR/hello-https-trust.pem" \
  --dry-run=client -o yaml | kubectl apply -f -

# Remove legacy standalone Pod (pre-Deployment); apply Deployment.
kubectl delete pod -n "$NS" dotnet-service --ignore-not-found 2>/dev/null || true
kubectl apply -f "$REPO_ROOT/test/kind/node-service-service.yaml" 2>/dev/null || true
kubectl apply -f "$REPO_ROOT/test/kind/dotnet-service-workload.yaml"
kubectl rollout status -n "$NS" deployment/dotnet-service --timeout=180s

echo "==> Patching DaemonSet to capture test-apps (libssl path)"
kubectl patch daemonset postman-insights-agent -n postman-insights --type=json \
  -p='[{"op":"replace","path":"/spec/template/spec/containers/0/args/3","value":"--target-namespaces=team-py,team-srv,test-apps"}]' \
  2>/dev/null || echo "  (patch skipped — adjust --target-namespaces manually if needed)"

echo
echo "Pod ready. Trust PEM on Mac:"
echo "  $CERT_DIR/hello-https-trust.pem"
echo
echo "Terminal 1 — port-forward:"
echo "  kubectl port-forward -n $NS deployment/dotnet-service 8443:8443 8446:8446"
echo
echo "Terminal 2 — from Mac:"
echo "  CACERT=$CERT_DIR/hello-https-trust.pem"
echo "  curl --cacert \"\$CACERT\" https://127.0.0.1:8443/phase5b2"
echo "  curl --cacert \"\$CACERT\" 'https://127.0.0.1:8443/phase5b2/call-external?q=egress-demo'"
echo "  grpcurl -cacert \"\$CACERT\" -import-path test/kind/dotnet-service/Protos -proto greeter.proto \\"
echo "    -d '{\"name\":\"from-mac\"}' localhost:8446 phase5c2.Greeter/SayHello"
echo
echo "In-pod client:"
echo "  kubectl exec -n $NS deploy/dotnet-service -- dotnet /app/client/DotnetClient.dll https://127.0.0.1 2"
echo
echo "Capture (libssl eBPF — ingress + egress from dotnet pid):"
echo "  kubectl rollout restart -n postman-insights daemonset/postman-insights-agent"
echo "  sleep 15"
echo "  # ingress: curl /phase5b2 from Mac"
echo "  # egress: curl /phase5b2/call-external (dotnet → node-service HTTPS)"
echo "  kubectl logs -n postman-insights daemonset/postman-insights-agent --timestamps --since=2m | grep -E 'phase5b2|node-service|REQ |RESP '"
echo
echo "Requires node-service running: ./test/kind/deploy-node-service.sh"
