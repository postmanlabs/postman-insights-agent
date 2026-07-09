#!/usr/bin/env bash
# Part 2 — Build + deploy node-service (HTTPS + gRPC) to kind.
# Part 1 (local Mac): ./test/kind/run-node-service-local.sh server|test
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CERT_DIR="$REPO_ROOT/test/kind/certs"
IMAGE=pia-node-service:test
CLUSTER=pia-https-test
NS=test-apps
CM=test-apps-tls
USE_STATIC=false

for arg in "$@"; do
  case "$arg" in
    --static) USE_STATIC=true ;;
  esac
done

"$CERT_DIR/gen-java-service-certs.sh"

kubectl config use-context "kind-${CLUSTER}" 2>/dev/null || true

echo "==> Building ${IMAGE}"
if [[ "$USE_STATIC" == "true" ]]; then
  docker build -f "$REPO_ROOT/test/kind/Dockerfile.node-service" -t "$IMAGE" "$REPO_ROOT"
  WORKLOAD="$REPO_ROOT/test/kind/node-service-workload.yaml"
else
  docker build -f "$REPO_ROOT/test/kind/Dockerfile.node-service-dynamic" -t "$IMAGE" "$REPO_ROOT"
  WORKLOAD="$REPO_ROOT/test/kind/node-service-workload-dynamic.yaml"
fi

echo "==> Loading image into kind"
kind load docker-image "$IMAGE" --name "$CLUSTER"

kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -

kubectl create configmap "$CM" -n "$NS" \
  --from-file="$CERT_DIR/grpc-cert.pem" \
  --from-file="$CERT_DIR/grpc-key.pem" \
  --from-file="$CERT_DIR/hello-https-keystore.p12" \
  --from-file="$CERT_DIR/hello-https-trust.pem" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl delete pod -n "$NS" node-service --ignore-not-found
kubectl apply -f "$WORKLOAD"
kubectl apply -f "$REPO_ROOT/test/kind/node-service-service.yaml"

kubectl wait -n "$NS" --for=condition=Ready pod/node-service --timeout=180s

echo "==> Patching DaemonSet to capture test-apps (libssl path)"
kubectl patch daemonset postman-insights-agent -n postman-insights --type=json \
  -p='[{"op":"replace","path":"/spec/template/spec/containers/0/args/3","value":"--target-namespaces=team-py,team-srv,test-apps"}]' \
  2>/dev/null || echo "  (patch skipped — adjust --target-namespaces manually if needed)"

echo
echo "Pod ready. Trust PEM on Mac:"
echo "  $CERT_DIR/hello-https-trust.pem"
echo
echo "Terminal 1 — port-forward:"
echo "  kubectl port-forward -n $NS pod/node-service 8443:8443 8446:8446"
echo
echo "Terminal 2 — from Mac:"
echo "  CACERT=$CERT_DIR/hello-https-trust.pem"
echo "  curl --cacert \"\$CACERT\" https://127.0.0.1:8443/phase5b2"
echo "  grpcurl -cacert \"\$CACERT\" -import-path test/kind/node-service/proto -proto greeter.proto \\"
echo "    -d '{\"name\":\"from-mac\"}' localhost:8446 phase5c2.Greeter/SayHello"
echo
echo "Or inside pod:"
echo "  kubectl exec -n $NS node-service -- node client.js 3"
echo
echo "Capture (libssl eBPF — NOT javatls):"
echo "  kubectl logs -n postman-insights daemonset/postman-insights-agent -f"
