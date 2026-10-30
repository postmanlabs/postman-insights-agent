# shellcheck shell=bash
# Shared steps of the kind end-to-end scripts (deploy-*-service.sh), sourced
# by them; not run on its own. Each script deploys the production DaemonSet
# (kube run --enable-https-capture, agent-daemonset-prod.yaml) and its own
# services into the test-apps namespace, sends requests from the test-clients
# namespace, and checks the agent's ebpf-stats lines.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CERT_DIR="$REPO_ROOT/test/kind/certs"
CLUSTER=pia-https-test
AGENT_IMAGE=pia-agent-ebpf:test
NS=test-apps
# Clients run outside the monitored namespace, so the counters checked count
# only the services' traffic, not the clients' own.
CLIENT_NS=test-clients

require_api_key() {
  if [[ -z "${POSTMAN_INSIGHTS_API_KEY:-}" ]]; then
    echo "ERROR: POSTMAN_INSIGHTS_API_KEY must be set." >&2
    exit 1
  fi
}

# Switches kubectl to the kind cluster, creating the cluster if it does not
# exist, and adding its context to the kubeconfig if that has none.
use_cluster() {
  if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
    echo "==> Creating kind cluster ${CLUSTER}"
    kind create cluster --config "$REPO_ROOT/test/kind/cluster.yaml"
  fi
  kubectl config use-context "kind-${CLUSTER}" >/dev/null 2>&1 || kind export kubeconfig --name "$CLUSTER"
}

# Builds the agent image (with eBPF and Java capture) and loads it into kind.
build_agent() {
  echo "==> Building agent image ${AGENT_IMAGE}"
  docker build -f "$REPO_ROOT/build-scripts/Dockerfile.ebpf" -t "$AGENT_IMAGE" "$REPO_ROOT"
  kind load docker-image "$AGENT_IMAGE" --name "$CLUSTER"
}

# Deploys the production DaemonSet, restarted so that it starts after the
# services, and waits for it. Call it after the services are up.
deploy_agent() {
  echo "==> Agent DaemonSet (kube run --enable-https-capture)"
  kubectl create namespace postman-insights --dry-run=client -o yaml | kubectl apply -f -
  kubectl create secret generic postman-insights-creds \
    --namespace postman-insights \
    --from-literal=api-key="${POSTMAN_INSIGHTS_API_KEY}" \
    --dry-run=client -o yaml | kubectl apply -f -
  kubectl apply -f "$REPO_ROOT/test/kind/agent-daemonset-prod.yaml"
  kubectl rollout restart -n postman-insights daemonset/postman-insights-agent
  kubectl rollout status -n postman-insights daemonset/postman-insights-agent --timeout=180s
}

# Creates the test-apps namespace and the TLS ConfigMap the Node.js and
# ASP.NET services read their certificates from.
apply_tls_configmap() {
  "$CERT_DIR/gen-java-service-certs.sh"
  kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -
  kubectl create configmap test-apps-tls -n "$NS" \
    --from-file="$CERT_DIR/grpc-cert.pem" \
    --from-file="$CERT_DIR/grpc-key.pem" \
    --from-file="$CERT_DIR/hello-https-keystore.p12" \
    --from-file="$CERT_DIR/hello-https-trust.pem" \
    --dry-run=client -o yaml | kubectl apply -f -
}

# Applies a service's Deployment (test/kind/<name>-workload.yaml, or the
# file given) and restarts it, so a rebuilt image is used even when the
# Deployment itself did not change. Deployments, not bare pods: discovery
# mode skips standalone pods. Waits with wait_services.
deploy_service() {
  # A bare pod of that name, from an earlier version of these scripts.
  kubectl delete pod -n "$NS" "$1" --ignore-not-found
  kubectl apply -f "${2:-$REPO_ROOT/test/kind/$1-workload.yaml}"
  kubectl rollout restart -n "$NS" "deployment/$1"
}

wait_services() {
  local svc
  for svc in "$@"; do
    kubectl rollout status -n "$NS" "deployment/$svc" --timeout=180s
  done
}

# The one pod of a service's Deployment (its strategy is Recreate).
pod_of() { kubectl get pod -n "$NS" -l "app=$1" -o jsonpath='{.items[0].metadata.name}'; }
ip_of() { kubectl get pod -n "$NS" -l "app=$1" -o jsonpath='{.items[0].status.podIP}'; }

# Runs a shell script in a curl pod in the client namespace; -e in the script
# makes a failed request fail the pod and the caller.
run_client() {
  kubectl create namespace "$CLIENT_NS" --dry-run=client -o yaml | kubectl apply -f -
  kubectl delete pod -n "$CLIENT_NS" "$1" --ignore-not-found >/dev/null
  kubectl run "$1" --restart=Never -n "$CLIENT_NS" --image=curlimages/curl:latest --rm -i --quiet -- sh -ec "$2"
}

# Waits for the next ebpf-stats lines (logged every 30 s) and sets LOGS to
# the agent's recent log.
collect_logs() {
  echo "==> Waiting for the next ebpf-stats lines (logged every 30s)"
  sleep 40
  LOGS=$(kubectl logs -n postman-insights daemonset/postman-insights-agent --since=5m)
}

# Highest value of a key=value field across the ebpf-stats lines in LOGS, of
# one pod when a second argument names it; empty when there is none, so a
# check reports it instead of set -e aborting. Each monitored pod logs its own
# line, starting with pod=<name>. msgs, the HTTP messages captured, is the
# pod's own; probes, events, bytes and the java_* fields are the node's.
max_field() {
  { grep -o "ebpf-stats: pod=${2:-[^ ]*} .*" <<<"$LOGS" | grep -oE " $1=[0-9]+" | cut -d= -f2 | sort -n | tail -1; } || true
}

# Checks that a field of a service's pod's ebpf-stats lines reached at least
# a value. Prints PASS or FAIL and sets fail=1 on failure.
check_at_least() {
  local svc=$1 field=$2 pod=$3 want=$4 got
  got=$(max_field "$field" "$pod")
  if [[ "${got:-0}" -ge "$want" ]]; then
    echo "  PASS  ${svc}: ${field}=${got}"
    return
  fi
  echo "  FAIL  ${svc}: ${field}=${got:-none}, want at least ${want}"
  fail=1
  # In discovery mode the backend stops a service's capture once its
  # discovery period ends, until it is onboarded in Postman.
  if grep -q "Discovery traffic TTL expired for service \"${NS}/${svc}\"" <<<"$LOGS"; then
    echo "        the agent stopped capturing ${NS}/${svc}: its discovery period ended."
    echo "        Onboard the service in Postman (cluster pia-kind-test), or delete it there, then rerun."
  fi
}

# Exits 1, with the agent's recent eBPF log lines, if a check failed.
finish_checks() {
  if [[ "${fail:-0}" -ne 0 ]]; then
    echo
    grep -E 'ebpf' <<<"$LOGS" | tail -20 || true
    exit 1
  fi
}
