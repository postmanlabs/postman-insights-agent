#!/usr/bin/env bash
# Deploy the PRODUCTION DaemonSet path (kube run --enable-https-capture) to kind.
#
# This tests the real `kube run` code path, unlike deploy-e2e-demo.sh which uses
# the apidump-ebpf spike command. Both HTTP (pcap) and HTTPS (eBPF libssl) traffic
# are captured and shipped to the Postman Insights backend.
#
# Prerequisites: Docker Desktop, kind, kubectl, a Postman Insights API key.
#
# Usage:
#   export POSTMAN_INSIGHTS_API_KEY=your_key_here
#   ./test/kind/deploy-e2e-prod.sh              # full deploy (build + apply)
#   ./test/kind/deploy-e2e-prod.sh --skip-build # reuse existing images
#
# Captures appear in Postman Insights under the cluster "pia-kind-test".
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CERT_DIR="$REPO_ROOT/test/kind/certs"
CLUSTER=pia-https-test
AGENT_IMAGE=pia-agent-ebpf:test
NODE_IMAGE=pia-node-service:test
NS=test-apps
SKIP_BUILD=false

for arg in "$@"; do
  case "$arg" in
    --skip-build) SKIP_BUILD=true ;;
    -h|--help)
      sed -n '2,14p' "$0"
      exit 0
      ;;
    *) echo "unknown arg: $arg" >&2; exit 1 ;;
  esac
done

if [[ -z "${POSTMAN_INSIGHTS_API_KEY:-}" ]]; then
  echo "ERROR: POSTMAN_INSIGHTS_API_KEY must be set."
  echo "  export POSTMAN_INSIGHTS_API_KEY=your_key_here"
  exit 1
fi

kubectl config use-context "kind-${CLUSTER}" 2>/dev/null || {
  echo "==> Creating kind cluster ${CLUSTER}"
  kind create cluster --config "$REPO_ROOT/test/kind/cluster.yaml"
}

if [[ "$SKIP_BUILD" == "false" ]]; then
  echo "==> Building agent image ${AGENT_IMAGE} (with insights_bpf tag)"
  docker build -f "$REPO_ROOT/test/kind/Dockerfile.agent" -t "$AGENT_IMAGE" "$REPO_ROOT"

  echo "==> Building Node service image (dynamic libssl)"
  docker build -f "$REPO_ROOT/test/kind/Dockerfile.node-service-dynamic" -t "$NODE_IMAGE" "$REPO_ROOT"

  kind load docker-image "$AGENT_IMAGE" --name "$CLUSTER"
  kind load docker-image "$NODE_IMAGE" --name "$CLUSTER"
fi

"$CERT_DIR/gen-java-service-certs.sh"

echo "==> Creating postman-insights namespace and API key secret"
kubectl create namespace postman-insights --dry-run=client -o yaml | kubectl apply -f -
kubectl create secret generic postman-insights-creds \
  --namespace postman-insights \
  --from-literal=api-key="${POSTMAN_INSIGHTS_API_KEY}" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "==> Deploying production DaemonSet (kube run --enable-https-capture)"
kubectl apply -f "$REPO_ROOT/test/kind/agent-daemonset-prod.yaml"
kubectl rollout restart -n postman-insights daemonset/postman-insights-agent 2>/dev/null || true
kubectl rollout status -n postman-insights daemonset/postman-insights-agent --timeout=180s

echo "==> test-apps namespace + TLS ConfigMap"
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -
kubectl create configmap test-apps-tls -n "$NS" \
  --from-file="$CERT_DIR/grpc-cert.pem" \
  --from-file="$CERT_DIR/grpc-key.pem" \
  --from-file="$CERT_DIR/hello-https-keystore.p12" \
  --from-file="$CERT_DIR/hello-https-trust.pem" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "==> Node service pod (libssl — HTTPS capture target)"
kubectl delete pod -n "$NS" node-service --ignore-not-found
kubectl apply -f "$REPO_ROOT/test/kind/node-service-workload-dynamic.yaml"
kubectl apply -f "$REPO_ROOT/test/kind/node-service-service.yaml"
kubectl wait -n "$NS" --for=condition=Ready pod/node-service --timeout=180s

echo "==> Restarting DaemonSet so eBPF uprobes attach after test-apps pods are up"
kubectl rollout restart -n postman-insights daemonset/postman-insights-agent
kubectl rollout status -n postman-insights daemonset/postman-insights-agent --timeout=180s
sleep 15

echo "==> Smoke test: HTTPS to node-service"
POD_IP=$(kubectl get pod -n "$NS" node-service -o jsonpath='{.status.podIP}')
kubectl delete pod -n "$NS" e2e-curl-node --ignore-not-found 2>/dev/null || true
kubectl run e2e-curl-node --restart=Never -n "$NS" --image=curlimages/curl:latest --rm -i \
  -- curl -sk "https://${POD_IP}:8443/phase5b2" 2>/dev/null || true
sleep 5

echo
echo "==> Agent logs (checking HTTPS capture):"
if kubectl logs -n postman-insights daemonset/postman-insights-agent --since=2m 2>/dev/null \
    | grep -E 'phase5b2|ebpf.*start|https.*captur|HTTPS capture'; then
  echo "  OK: HTTPS capture active in production DaemonSet path"
else
  echo "  WARN: no HTTPS capture signal yet — agent may still be attaching probes."
  echo "  Re-check with:"
  echo "    kubectl logs -n postman-insights daemonset/postman-insights-agent --since=5m | grep -iE 'https|ebpf|phase5b2'"
fi

echo
echo "================================================"
echo "  Production DaemonSet deployed (kind-${CLUSTER})"
echo "================================================"
echo
kubectl get pods -n postman-insights
kubectl get pods -n "$NS"
echo
echo "Capture appears in Postman Insights under cluster 'pia-kind-test'."
echo
echo "Tail agent logs:"
echo "  kubectl logs -n postman-insights daemonset/postman-insights-agent -f"
echo
echo "Send HTTPS traffic:"
echo "  POD_IP=\$(kubectl get pod -n $NS node-service -o jsonpath='{.status.podIP}')"
echo "  kubectl run curl-test --restart=Never -n $NS --image=curlimages/curl:latest --rm -i \\"
echo "    -- curl -sk https://\${POD_IP}:8443/hello"
