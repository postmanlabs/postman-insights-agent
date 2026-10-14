#!/usr/bin/env bash
# End-to-end check of Java HTTPS capture in kind, through the production
# DaemonSet path (kube run --enable-https-capture, agent-daemonset-prod.yaml).
#
# Deploys a Spring Boot (Tomcat) HTTPS service that loads the Postman Java agent
# through -javaagent, sends it HTTPS requests, and checks the agent's
# ebpf-stats lines: Java frames reached the kernel programs and were parsed
# into HTTP messages. Captures also appear in Postman Insights under the
# cluster "pia-kind-test".
#
# Prerequisites: Docker Desktop, kind, kubectl, a Postman Insights API key.
#
# Usage:
#   export POSTMAN_INSIGHTS_API_KEY=your_key_here
#   ./test/kind/deploy-java-service.sh              # build images, deploy, check
#   ./test/kind/deploy-java-service.sh --skip-build # reuse the images in kind
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CLUSTER=pia-https-test
AGENT_IMAGE=pia-agent-ebpf:test
JAVA_IMAGE=pia-java-service:test
NS=test-apps
SKIP_BUILD=false
REQUESTS=3 # rounds of 3 requests each

for arg in "$@"; do
  case "$arg" in
    --skip-build) SKIP_BUILD=true ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) echo "unknown arg: $arg" >&2; exit 1 ;;
  esac
done

if [[ -z "${POSTMAN_INSIGHTS_API_KEY:-}" ]]; then
  echo "ERROR: POSTMAN_INSIGHTS_API_KEY must be set." >&2
  exit 1
fi

kubectl config use-context "kind-${CLUSTER}" >/dev/null 2>&1 || {
  echo "==> Creating kind cluster ${CLUSTER}"
  kind create cluster --config "$REPO_ROOT/test/kind/cluster.yaml"
}

if [[ "$SKIP_BUILD" == "false" ]]; then
  echo "==> Building agent image ${AGENT_IMAGE}"
  docker build -f "$REPO_ROOT/build-scripts/Dockerfile.ebpf" -t "$AGENT_IMAGE" "$REPO_ROOT"
  echo "==> Building Java service image ${JAVA_IMAGE}"
  docker build -f "$REPO_ROOT/test/kind/Dockerfile.java-service" -t "$JAVA_IMAGE" "$REPO_ROOT"
  kind load docker-image "$AGENT_IMAGE" --name "$CLUSTER"
  kind load docker-image "$JAVA_IMAGE" --name "$CLUSTER"
fi

echo "==> Java service pod"
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -
kubectl delete pod -n "$NS" java-service --ignore-not-found
kubectl apply -f "$REPO_ROOT/test/kind/java-service-workload.yaml"
kubectl wait -n "$NS" --for=condition=Ready pod/java-service --timeout=180s
POD_IP=$(kubectl get pod -n "$NS" java-service -o jsonpath='{.status.podIP}')
kubectl logs -n "$NS" java-service | grep 'postman-insights-agent' || true

echo "==> Agent DaemonSet (kube run --enable-https-capture, Java HTTPS capture on)"
kubectl create namespace postman-insights --dry-run=client -o yaml | kubectl apply -f -
kubectl create secret generic postman-insights-creds \
  --namespace postman-insights \
  --from-literal=api-key="${POSTMAN_INSIGHTS_API_KEY}" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f "$REPO_ROOT/test/kind/agent-daemonset-prod.yaml"
# Restart so the agent starts after the Java pod exists.
kubectl rollout restart -n postman-insights daemonset/postman-insights-agent
kubectl rollout status -n postman-insights daemonset/postman-insights-agent --timeout=180s
sleep 15

echo "==> Sending HTTPS requests to ${POD_IP}:8443"
kubectl delete pod -n "$NS" java-client --ignore-not-found >/dev/null
kubectl run java-client --restart=Never -n "$NS" --image=curlimages/curl:latest --rm -i --quiet -- sh -c "
  for i in \$(seq 1 ${REQUESTS}); do
    curl -sk https://${POD_IP}:8443/hello?name=kind-\$i; echo
    curl -sk https://${POD_IP}:8443/orders/42; echo
    curl -sk -X POST -H 'Content-Type: application/json' -d '{\"item\":\"book\",\"qty\":2}' https://${POD_IP}:8443/orders; echo
  done"

echo "==> Waiting for the next ebpf-stats lines (logged every 30s)"
sleep 40
LOGS=$(kubectl logs -n postman-insights daemonset/postman-insights-agent --since=5m)

fail=0
if grep -q 'ebpf: Java HTTPS capture enabled' <<<"$LOGS"; then
  echo "  PASS  Java programs loaded"
else
  echo "  FAIL  no 'Java HTTPS capture enabled' line"
  grep -E 'Java HTTPS capture' <<<"$LOGS" || true
  fail=1
fi
# Highest value of a key=value field across ebpf-stats lines.
max_field() { grep -o "ebpf-stats: .*" <<<"$LOGS" | grep -oE " $1=[0-9]+" | cut -d= -f2 | sort -n | tail -1; }
java_events=$(max_field java_events)
msgs=$(max_field msgs)
want=$((REQUESTS * 3 * 2)) # a request and a response per call
if [[ "${java_events:-0}" -ge "$want" ]]; then
  echo "  PASS  java_events=${java_events}"
else
  echo "  FAIL  java_events=${java_events:-none}, want at least ${want}"
  fail=1
fi
if [[ "${msgs:-0}" -ge "$want" ]]; then
  echo "  PASS  msgs=${msgs} (HTTP messages parsed for a monitored pod)"
else
  echo "  FAIL  msgs=${msgs:-none}, want at least ${want}"
  fail=1
fi

if [[ "$fail" -ne 0 ]]; then
  echo
  grep -E 'ebpf' <<<"$LOGS" | tail -20 || true
  exit 1
fi
echo "==> Java HTTPS capture works end to end; check Postman Insights cluster 'pia-kind-test' for the endpoints"
