#!/usr/bin/env bash
# End-to-end check of Java HTTPS capture in kind, through the production
# DaemonSet path (kube run --enable-https-capture, agent-daemonset-prod.yaml).
#
# Deploys three HTTPS services: Spring Boot on Tomcat (the JDK's SSLEngine)
# and plain Netty (its OpenSSL engine), which load the Postman Java agent
# through -javaagent, and the same Spring Boot service started without it,
# into which the Insights agent attaches the Java agent. Sends each HTTPS
# requests, and checks the agent's ebpf-stats lines: Java frames reached the
# kernel programs and were parsed into HTTP messages. Captures also appear in
# Postman Insights under the cluster "pia-kind-test".
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
NETTY_IMAGE=pia-netty-service:test
SERVICES="java-service netty-service java-service-attach"
NS=test-apps
# The client runs outside the monitored namespace, so the counters checked
# below count only the services' traffic, not the client's own (libssl).
CLIENT_NS=test-clients
SKIP_BUILD=false
REQUESTS=3 # rounds of 3 requests each
# The Java agent's log prefix, with the jar's old name and the current one.
JAVA_LOG='\[postman-insights(-java)?-agent\]'

for arg in "$@"; do
  case "$arg" in
    --skip-build) SKIP_BUILD=true ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
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
  echo "==> Building Java service images ${JAVA_IMAGE} and ${NETTY_IMAGE}"
  docker build -f "$REPO_ROOT/test/kind/Dockerfile.java-service" -t "$JAVA_IMAGE" "$REPO_ROOT"
  docker build -f "$REPO_ROOT/test/kind/Dockerfile.netty-service" -t "$NETTY_IMAGE" "$REPO_ROOT"
  kind load docker-image "$AGENT_IMAGE" "$JAVA_IMAGE" "$NETTY_IMAGE" --name "$CLUSTER"
fi

# The one pod of a service's Deployment (its strategy is Recreate).
pod_of() { kubectl get pod -n "$NS" -l "app=$1" -o jsonpath='{.items[0].metadata.name}'; }

# Deployments, not bare pods: discovery mode skips standalone pods.
echo "==> Java service deployments"
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -
POD_IPS=""
for svc in $SERVICES; do
  # A bare pod of that name, from an earlier version of this script.
  kubectl delete pod -n "$NS" "$svc" --ignore-not-found
  kubectl apply -f "$REPO_ROOT/test/kind/${svc}-workload.yaml"
  # A fresh JVM every run, so the Insights agent attaches to it anew.
  kubectl rollout restart -n "$NS" "deployment/$svc"
done
for svc in $SERVICES; do
  kubectl rollout status -n "$NS" "deployment/$svc" --timeout=180s
  POD_IPS="$POD_IPS $(kubectl get pod -n "$NS" -l "app=$svc" -o jsonpath='{.items[0].status.podIP}')"
done

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

# The Java agents stay dormant until the Insights agent discovers their JVMs
# and writes their control files; into java-service-attach it first attaches
# the agent.
echo "==> Waiting for the Java agents to start capturing"
for svc in $SERVICES; do
  # Discovery runs every 2 s, a JVM is attached once it has run for 5 s, and
  # the agent checks its control file every 5 s.
  capturing=false
  for _ in $(seq 1 45); do
    if kubectl logs -n "$NS" "deployment/$svc" | grep -Eq "${JAVA_LOG}"' capturing HTTPS traffic'; then
      capturing=true
      break
    fi
    sleep 1
  done
  kubectl logs -n "$NS" "deployment/$svc" | grep -E "${JAVA_LOG}" || true
  if [[ "$capturing" != true ]]; then
    echo "ERROR: the Java agent in ${svc} did not start capturing" >&2
    exit 1
  fi
done

echo "==> Sending HTTPS requests to${POD_IPS} (port 8443) from namespace ${CLIENT_NS}"
kubectl create namespace "$CLIENT_NS" --dry-run=client -o yaml | kubectl apply -f -
kubectl delete pod -n "$CLIENT_NS" java-client --ignore-not-found >/dev/null
# -f: an HTTP error fails curl, and -e makes that fail the pod and this script.
kubectl run java-client --restart=Never -n "$CLIENT_NS" --image=curlimages/curl:latest --rm -i --quiet -- sh -ec "
  for ip in ${POD_IPS}; do
    for i in \$(seq 1 ${REQUESTS}); do
      curl -fsSk https://\$ip:8443/hello?name=kind-\$i; echo
      curl -fsSk https://\$ip:8443/orders/42; echo
      curl -fsSk -X POST -H 'Content-Type: application/json' -d '{\"item\":\"book\",\"qty\":2}' https://\$ip:8443/orders; echo
    done
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
# Highest value of a key=value field across the ebpf-stats lines, of one pod
# when a second argument names it; empty when there is none, so the checks
# below report it instead of set -e aborting here. Each monitored pod logs its
# own line, starting with pod=<name>; the java_* fields are the node's.
max_field() {
  { grep -o "ebpf-stats: pod=${2:-[^ ]*} .*" <<<"$LOGS" | grep -oE " $1=[0-9]+" | cut -d= -f2 | sort -n | tail -1; } || true
}
services=$(wc -w <<<"$SERVICES")
per_service=$((REQUESTS * 3 * 2)) # a request and a response per call
java_events=$(max_field java_events)
want=$((services * per_service))
if [[ "${java_events:-0}" -ge "$want" ]]; then
  echo "  PASS  java_events=${java_events}"
else
  echo "  FAIL  java_events=${java_events:-none}, want at least ${want}"
  fail=1
fi
for svc in $SERVICES; do
  msgs=$(max_field msgs "$(pod_of "$svc")")
  if [[ "${msgs:-0}" -ge "$per_service" ]]; then
    echo "  PASS  ${svc}: msgs=${msgs} (HTTP messages parsed for the pod)"
  else
    echo "  FAIL  ${svc}: msgs=${msgs:-none}, want at least ${per_service}"
    fail=1
  fi
done

# The kernel ties each Java connection to its socket, so every message has
# its IP addresses and ports: no data frame went out without them, and no
# connection's thread read another socket before its frames.
for field in java_conn_unbound java_conn_mismatch; do
  v=$(max_field "$field")
  if [[ -n "$v" && "$v" -eq 0 ]]; then
    echo "  PASS  ${field}=0"
  else
    echo "  FAIL  ${field}=${v:-none}, want 0"
    fail=1
  fi
done

# Each service's Java agent reports itself through HEARTBEAT frames.
agents=$({ grep -oE 'ebpf: Java agent [^ ]+ in pid [0-9]+ is active' <<<"$LOGS" | grep -oE 'pid [0-9]+' | sort -u | wc -l; } || true)
if [[ "${agents// /}" -ge "$services" ]]; then
  echo "  PASS  ${agents// /} Java agents heard from, capturing"
else
  echo "  FAIL  ${agents// /} Java agents heard from capturing, want ${services}"
  fail=1
fi

if [[ "$fail" -ne 0 ]]; then
  echo
  grep -E 'ebpf' <<<"$LOGS" | tail -20 || true
  exit 1
fi
echo "==> Java HTTPS capture works end to end; check Postman Insights cluster 'pia-kind-test' for the endpoints"
