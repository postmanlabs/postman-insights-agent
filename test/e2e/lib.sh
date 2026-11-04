# shellcheck shell=bash
# Shared steps of the end-to-end scripts (deploy-*-service.sh), sourced by
# them; not run on its own. Each script deploys the production DaemonSet
# (kube run --enable-https-capture, agent-daemonset-prod.yaml) and its own
# services into the test-apps namespace, sends requests from the test-clients
# namespace, and checks the agent's ebpf-stats lines.
#
# Where they run, set in the environment:
#   POSTMAN_ENV               required: the Postman backend the agent sends
#                             to, BETA for tests (or PREVIEW, STAGE,
#                             PRODUCTION). An unset POSTMAN_ENV would make the
#                             agent use production, so the scripts refuse it.
#   POSTMAN_INSIGHTS_API_KEY  required: an API key for that backend.
#   KUBE_CONTEXT              the kubeconfig context of the cluster to test
#                             in; default kind-pia-https-test. A kind-<name>
#                             context whose kind cluster does not exist is
#                             created. The scripts pass it to every kubectl
#                             call and never change the current context.
#   INSIGHTS_CLUSTER_NAME     the cluster name the agent reports, under which
#                             the services appear in Postman; default
#                             pia-kind-test on kind, required elsewhere.
#   AGENT_IMAGE, and each     the image refs to deploy. On kind the scripts
#   script's service images   build them under these refs and load them into
#   (JAVA_IMAGE, ...)         the cluster (--skip-build reuses the loaded
#                             ones). On another cluster they build nothing:
#                             the refs must name images the nodes can pull,
#                             pushed beforehand.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CERT_DIR="$REPO_ROOT/test/e2e/certs"
DEFAULT_KIND_CLUSTER=pia-https-test
KUBE_CONTEXT="${KUBE_CONTEXT:-kind-${DEFAULT_KIND_CLUSTER}}"
# The kind cluster's name when KUBE_CONTEXT is a kind cluster (set by
# use_cluster), empty otherwise.
KIND_CLUSTER=""
AGENT_IMAGE="${AGENT_IMAGE:-pia-agent-ebpf:test}"
NS=test-apps
# Clients run outside the monitored namespace, so the counters checked count
# only the services' traffic, not the clients' own.
CLIENT_NS=test-clients

# Every kubectl call of the scripts goes to KUBE_CONTEXT.
kubectl() { command kubectl --context "$KUBE_CONTEXT" "$@"; }

# Checks the backend settings, so no run goes to production by accident.
require_backend() {
  if [[ -z "${POSTMAN_INSIGHTS_API_KEY:-}" ]]; then
    echo "ERROR: POSTMAN_INSIGHTS_API_KEY must be set." >&2
    exit 1
  fi
  POSTMAN_ENV="$(tr '[:lower:]' '[:upper:]' <<<"${POSTMAN_ENV:-}")"
  case "$POSTMAN_ENV" in
    BETA | PREVIEW | STAGE) ;;
    PRODUCTION)
      echo "WARNING: POSTMAN_ENV=PRODUCTION: the test services are registered in the production backend." >&2
      ;;
    "")
      echo "ERROR: POSTMAN_ENV must be set; tests use POSTMAN_ENV=BETA with a beta API key." >&2
      exit 1
      ;;
    *)
      # The agent would fall back to production for an unknown value.
      echo "ERROR: unknown POSTMAN_ENV=${POSTMAN_ENV}; use BETA, PREVIEW, STAGE or PRODUCTION." >&2
      exit 1
      ;;
  esac
}

# Finds the cluster of KUBE_CONTEXT, creating it when it is a kind cluster
# that does not exist, and sets KIND_CLUSTER and INSIGHTS_CLUSTER_NAME.
use_cluster() {
  if [[ "$KUBE_CONTEXT" == kind-* ]]; then
    KIND_CLUSTER="${KUBE_CONTEXT#kind-}"
    if ! kind get clusters 2>/dev/null | grep -qx "$KIND_CLUSTER"; then
      echo "==> Creating kind cluster ${KIND_CLUSTER}"
      kind create cluster --name "$KIND_CLUSTER" --config "$REPO_ROOT/test/e2e/kind/cluster.yaml"
    elif ! command kubectl config get-contexts -o name | grep -qxF "$KUBE_CONTEXT"; then
      kind export kubeconfig --name "$KIND_CLUSTER"
    fi
    INSIGHTS_CLUSTER_NAME="${INSIGHTS_CLUSTER_NAME:-pia-kind-test}"
  else
    if ! command kubectl config get-contexts -o name | grep -qxF "$KUBE_CONTEXT"; then
      echo "ERROR: no context ${KUBE_CONTEXT} in the kubeconfig." >&2
      exit 1
    fi
    if [[ -z "${INSIGHTS_CLUSTER_NAME:-}" ]]; then
      echo "ERROR: INSIGHTS_CLUSTER_NAME must be set outside kind: the cluster name the services appear under in Postman." >&2
      exit 1
    fi
  fi
  echo "==> Testing in context ${KUBE_CONTEXT}, against POSTMAN_ENV=${POSTMAN_ENV:-}, as cluster ${INSIGHTS_CLUSTER_NAME}"
  if [[ -z "$KIND_CLUSTER" ]]; then
    echo "==> Not a kind cluster: building nothing, the nodes pull the image refs given"
  fi
}

# Whether this run builds its images: on kind, unless the script got
# --skip-build (SKIP_BUILD=true).
building_images() { [[ -n "$KIND_CLUSTER" && "${SKIP_BUILD:-false}" == false ]]; }

# Builds an image from a Dockerfile, with the repository as the context.
build_image() {
  echo "==> Building $2 ($(basename "$(dirname "$1")")/$(basename "$1"))"
  docker build -f "$1" -t "$2" "$REPO_ROOT"
}

# Loads images built here into the kind cluster's nodes.
load_images() { kind load docker-image "$@" --name "$KIND_CLUSTER"; }

# Builds the agent image (with eBPF and Java capture) and loads it.
build_agent() {
  build_image "$REPO_ROOT/build-scripts/Dockerfile.ebpf" "$AGENT_IMAGE"
  load_images "$AGENT_IMAGE"
}

# Prints a manifest with its one container's image set to a ref, pulled as
# the cluster needs: never on kind (loaded there), always elsewhere (a ref
# pushed again under the same tag is not served stale from a node's cache).
render_manifest() {
  local file=$1 image=$2 policy=Always n
  [[ -n "$KIND_CLUSTER" ]] && policy=Never
  if ! [[ "$image" =~ ^[A-Za-z0-9][A-Za-z0-9._/:@-]*$ ]]; then
    echo "ERROR: not an image ref: ${image}" >&2
    exit 1
  fi
  if [[ -z "$KIND_CLUSTER" && "$image" != */* ]]; then
    echo "ERROR: ${image} is a local image name; outside kind, push it to a registry the nodes can pull from and pass that ref." >&2
    exit 1
  fi
  n=$(grep -cE '^[[:space:]]+image: ' "$file" || true)
  if [[ "$n" -ne 1 ]]; then
    echo "ERROR: ${file} has ${n} image lines, want 1." >&2
    exit 1
  fi
  sed -E \
    -e "s|^([[:space:]]+image: ).*|\1${image}|" \
    -e "s|^([[:space:]]+imagePullPolicy: ).*|\1${policy}|" \
    "$file"
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
  # The backend and the cluster name, read by the DaemonSet's environment.
  kubectl create configmap postman-insights-e2e \
    --namespace postman-insights \
    --from-literal=postman-env="${POSTMAN_ENV}" \
    --from-literal=cluster-name="${INSIGHTS_CLUSTER_NAME}" \
    --dry-run=client -o yaml | kubectl apply -f -
  render_manifest "$REPO_ROOT/test/e2e/agent-daemonset-prod.yaml" "$AGENT_IMAGE" | kubectl apply -f -
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

# Applies a service's Deployment (test/e2e/<name>-workload.yaml, or the
# file given third) with its image ref, and restarts it, so a rebuilt image
# is used even when the Deployment itself did not change. Deployments, not
# bare pods: discovery mode skips standalone pods. Waits with wait_services.
deploy_service() {
  # A bare pod of that name, from an earlier version of these scripts.
  kubectl delete pod -n "$NS" "$1" --ignore-not-found
  render_manifest "${3:-$REPO_ROOT/test/e2e/$1-workload.yaml}" "$2" | kubectl apply -f -
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
# the pod a second argument names, or of the node's lines without one; empty
# when there is none, so a check reports it instead of set -e aborting. Each
# monitored pod logs its own line, starting with pod=<name>, with its own
# probes, events, bytes, java_events and msgs; the node logs one line,
# starting with node, with what its pods share (the kernel counters,
# java_conn_* among them).
max_field() {
  local scope=node
  [[ -n "${2:-}" ]] && scope="pod=$2"
  { grep -o "ebpf-stats: ${scope} .*" <<<"$LOGS" | grep -oE " $1=[0-9]+" | cut -d= -f2 | sort -n | tail -1; } || true
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
    echo "        Onboard the service in Postman (POSTMAN_ENV=${POSTMAN_ENV}, cluster ${INSIGHTS_CLUSTER_NAME}),"
    echo "        or delete it there, then rerun."
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
