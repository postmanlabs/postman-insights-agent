#!/usr/bin/env bash
# One-shot setup for the Kind HTTPS + gRPC e2e demo (Java + Node.js).
#
# Prerequisites: Docker Desktop, kind, kubectl, grpcurl (optional, for gRPC from Mac).
# Java 17 on the host is NOT required — JARs are built inside Docker.
#
# Usage:
#   ./test/kind/deploy-e2e-demo.sh              # full deploy (build + apply)
#   ./test/kind/deploy-e2e-demo.sh --skip-build # reuse existing images
#   ./test/kind/deploy-e2e-demo.sh --static-node  # node:20 BoringSSL (capture WIP in Kind)
#
# After deploy, see docs/kind-e2e-demo-presentation.md for demo script.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CERT_DIR="$REPO_ROOT/test/kind/certs"
CLUSTER=pia-https-test
AGENT_IMAGE=pia-agent-ebpf:test
NODE_IMAGE=pia-node-service:test
NS=test-apps
SKIP_BUILD=false
STATIC_NODE=false

for arg in "$@"; do
  case "$arg" in
    --skip-build) SKIP_BUILD=true ;;
    --static-node) STATIC_NODE=true ;;
    -h|--help)
      sed -n '2,12p' "$0"
      exit 0
      ;;
    *) echo "unknown arg: $arg" >&2; exit 1 ;;
  esac
done

kubectl config use-context "kind-${CLUSTER}" 2>/dev/null || {
  echo "==> Creating kind cluster ${CLUSTER}"
  kind create cluster --config "$REPO_ROOT/test/kind/cluster.yaml"
}

if [[ "$SKIP_BUILD" == "false" ]]; then
  echo "==> Building Java agent + grpc-java workload JARs"
  "$REPO_ROOT/test/kind/build-java-artifacts.sh"

  echo "==> Building agent image ${AGENT_IMAGE}"
  docker build -f "$REPO_ROOT/test/kind/Dockerfile.agent" -t "$AGENT_IMAGE" "$REPO_ROOT"

  if [[ "$STATIC_NODE" == "true" ]]; then
    echo "==> Building Node image (static BoringSSL — Kind capture WIP)"
    docker build -f "$REPO_ROOT/test/kind/Dockerfile.node-service" -t "$NODE_IMAGE" "$REPO_ROOT"
  else
    echo "==> Building Node image (dynamic libssl — recommended for demo)"
    docker build -f "$REPO_ROOT/test/kind/Dockerfile.node-service-dynamic" -t "$NODE_IMAGE" "$REPO_ROOT"
  fi

  kind load docker-image "$AGENT_IMAGE" --name "$CLUSTER"
  kind load docker-image "$NODE_IMAGE" --name "$CLUSTER"
fi

"$CERT_DIR/gen-java-service-certs.sh"

echo "==> Agent DaemonSet (libssl / Node capture path)"
kubectl apply -f "$REPO_ROOT/test/kind/agent-daemonset.yaml"
kubectl rollout restart -n postman-insights daemonset/postman-insights-agent 2>/dev/null || true
kubectl rollout status -n postman-insights daemonset/postman-insights-agent --timeout=180s

echo "==> Java TLS capture Deployment"
kubectl apply -f "$REPO_ROOT/test/kind/javatls-capture.yaml"
kubectl rollout restart -n postman-insights deploy/javatls-capture 2>/dev/null || true
kubectl rollout status -n postman-insights deploy/javatls-capture --timeout=120s

echo "==> test-apps namespace + TLS ConfigMap"
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -
kubectl create configmap test-apps-tls -n "$NS" \
  --from-file="$CERT_DIR/grpc-cert.pem" \
  --from-file="$CERT_DIR/grpc-key.pem" \
  --from-file="$CERT_DIR/hello-https-keystore.p12" \
  --from-file="$CERT_DIR/hello-https-trust.pem" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "==> Java service pod"
kubectl delete pod -n "$NS" java-service --ignore-not-found
kubectl apply -f "$REPO_ROOT/test/kind/java-service-workload.yaml"
kubectl wait -n "$NS" --for=condition=Ready pod/java-service --timeout=180s

echo "==> Node service pod"
kubectl delete pod -n "$NS" node-service --ignore-not-found
if [[ "$STATIC_NODE" == "true" ]]; then
  kubectl apply -f "$REPO_ROOT/test/kind/node-service-workload.yaml"
else
  kubectl apply -f "$REPO_ROOT/test/kind/node-service-workload-dynamic.yaml"
fi
kubectl apply -f "$REPO_ROOT/test/kind/node-service-service.yaml"
kubectl wait -n "$NS" --for=condition=Ready pod/node-service --timeout=180s

echo "==> Optional background workloads (team-py / team-srv)"
echo "    Skipped by default — they flood agent logs and trigger CPU thermostat."
echo "    To enable: kubectl apply -f test/kind/workloads.yaml"
# kubectl apply -f "$REPO_ROOT/test/kind/workloads.yaml" 2>/dev/null || true

echo "==> Restart DaemonSet so uprobes attach after test-apps pods are up"
kubectl rollout restart -n postman-insights daemonset/postman-insights-agent
kubectl rollout status -n postman-insights daemonset/postman-insights-agent --timeout=180s
sleep 15

echo "==> Smoke test: HTTPS to node-service"
POD_IP=$(kubectl get pod -n "$NS" node-service -o jsonpath='{.status.podIP}')
kubectl delete pod -n "$NS" e2e-curl-node --ignore-not-found 2>/dev/null || true
kubectl run e2e-curl-node --restart=Never -n "$NS" --image=curlimages/curl:latest --rm -i \
  -- curl -sk "https://${POD_IP}:8443/phase5b2" 2>/dev/null || true
sleep 3
echo
echo "==> Node capture (grep phase5b2 — NOT the node PID, NOT bare REQ):"
if kubectl logs -n postman-insights daemonset/postman-insights-agent --since=2m 2>/dev/null | grep -E 'phase5b2|Greeter'; then
  echo "  OK: node HTTPS capture visible in agent logs"
else
  echo "  WARN: no phase5b2 yet — wait 5s and re-run:"
  echo "    kubectl logs -n postman-insights daemonset/postman-insights-agent --since=2m | grep phase5b2"
fi
echo
echo "=============================================="
echo "  E2E demo cluster ready (kind-${CLUSTER})"
echo "=============================================="
echo
kubectl get pods -n postman-insights
kubectl get pods -n "$NS"
echo
echo "Trust PEM (Mac curl/grpcurl):"
echo "  $CERT_DIR/hello-https-trust.pem"
echo
echo "Check capture:"
echo "  Java:  kubectl logs -n postman-insights deploy/javatls-capture --since=2m | grep -E 'phase5|Greeter'"
echo "  Node:  kubectl logs -n postman-insights daemonset/postman-insights-agent --since=2m | grep phase5b2"
echo
echo "Full demo script: docs/kind-e2e-demo-presentation.md"
