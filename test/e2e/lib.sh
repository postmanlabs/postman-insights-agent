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
AGENT_NS=postman-insights
# The label the scripts put on every namespace and cluster-scoped resource
# they create, and on the agent DaemonSet. teardown.sh removes only what
# carries it, and outside kind the scripts refuse to take over a resource
# without it.
E2E_LABEL=postman-insights-e2e

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

# Whether KUBE_CONTEXT names an existing cluster: sets KIND_CLUSTER for a
# kind-<name> context, and exports a kind cluster's context when the
# kubeconfig lacks it. Returns 1 for a kind cluster that does not exist;
# exits for any other context missing from the kubeconfig.
find_cluster() {
  if [[ "$KUBE_CONTEXT" == kind-* ]]; then
    KIND_CLUSTER="${KUBE_CONTEXT#kind-}"
    kind get clusters 2>/dev/null | grep -qx "$KIND_CLUSTER" || return 1
    if ! command kubectl config get-contexts -o name | grep -qxF "$KUBE_CONTEXT"; then
      kind_keeping_context export kubeconfig --name "$KIND_CLUSTER"
    fi
  elif ! command kubectl config get-contexts -o name | grep -qxF "$KUBE_CONTEXT"; then
    echo "ERROR: no context ${KUBE_CONTEXT} in the kubeconfig." >&2
    exit 1
  fi
}

# Runs a kind command that writes the kubeconfig (create cluster, export
# kubeconfig), then puts the current context back as it was, also when the
# command fails or is interrupted: kind makes the cluster's context the
# current one, and the scripts leave the current context alone.
kind_keeping_context() {
  local rc=0
  KIND_PREV_CONTEXT=$(command kubectl config current-context 2>/dev/null || true)
  trap 'restore_context; exit 130' INT TERM
  kind "$@" || rc=$?
  trap - INT TERM
  restore_context
  return "$rc"
}

# Makes KIND_PREV_CONTEXT the current context again, or none when it is empty.
restore_context() {
  if [[ -n "$KIND_PREV_CONTEXT" ]]; then
    command kubectl config use-context "$KIND_PREV_CONTEXT" >/dev/null
  else
    command kubectl config unset current-context >/dev/null
  fi
}

# Finds the cluster of KUBE_CONTEXT, creating it when it is a kind cluster
# that does not exist, sets KIND_CLUSTER and INSIGHTS_CLUSTER_NAME, and
# checks the cluster has room for the test (check_cluster_is_free).
use_cluster() {
  if ! find_cluster; then
    echo "==> Creating kind cluster ${KIND_CLUSTER}"
    kind_keeping_context create cluster --name "$KIND_CLUSTER" --config "$REPO_ROOT/test/e2e/kind/cluster.yaml"
  fi
  if [[ -n "$KIND_CLUSTER" ]]; then
    INSIGHTS_CLUSTER_NAME="${INSIGHTS_CLUSTER_NAME:-pia-kind-test}"
  elif [[ -z "${INSIGHTS_CLUSTER_NAME:-}" ]]; then
    echo "ERROR: INSIGHTS_CLUSTER_NAME must be set outside kind: the cluster name the services appear under in Postman." >&2
    exit 1
  fi
  echo "==> Testing in context ${KUBE_CONTEXT}, against POSTMAN_ENV=${POSTMAN_ENV:-}, as cluster ${INSIGHTS_CLUSTER_NAME}"
  if [[ -z "$KIND_CLUSTER" ]]; then
    echo "==> Not a kind cluster: building nothing, the nodes pull the image refs given"
  fi
  check_cluster_is_free
  stop_agent
}

# Sets OWNER to the E2E_LABEL label of a resource ("" when it has none), or
# returns 1 when the resource does not exist. Exits on any other error: a
# lookup that failed must not pass for a resource that does not exist.
read_owner() {
  local out
  if ! out=$(kubectl get "$@" --ignore-not-found -o "jsonpath={.metadata.name}|{.metadata.labels.${E2E_LABEL}}"); then
    echo "ERROR: could not read $* from the cluster; stopping rather than guess whether it exists." >&2
    exit 1
  fi
  [[ -n "$out" ]] || return 1
  OWNER=${out#*|}
}

# Stops the test's agent DaemonSet, if one runs, before the test services are
# deployed: an agent left by an earlier run may send to another backend (one
# from before the scripts set POSTMAN_ENV sends to production), and would
# register the new services there before deploy_agent switches it.
# deploy_agent starts it again, after the services.
stop_agent() {
  read_owner -n "$AGENT_NS" daemonset/postman-insights-agent || return 0
  echo "==> Stopping the agent of an earlier run until the services are up"
  kubectl delete daemonset -n "$AGENT_NS" postman-insights-agent --wait=true
  if [[ -n "$(kubectl get pods -n "$AGENT_NS" -l app=postman-insights-agent -o name)" ]]; then
    kubectl wait --for=delete pod -n "$AGENT_NS" -l app=postman-insights-agent --timeout=120s
  fi
}

# Refuses to run where the test would collide with something it did not
# create:
# - another Postman Insights agent DaemonSet (an image named
#   postman-insights-agent, or a container running `kube run`), since two
#   agents on a node would both capture the test services and both attach
#   Java agents to their JVMs;
# - outside kind, any of the resources the scripts create (the namespaces,
#   the agent's ClusterRole, ClusterRoleBinding and DaemonSet) existing
#   without the E2E_LABEL label: applying would take it over, and
#   teardown.sh would then delete it.
# On kind, unlabelled resources of the scripts' names are taken to be from
# an earlier version of the scripts, which did not label them.
check_cluster_is_free() {
  local daemonsets id label spec words others="" res foreign=""
  local kube_run=' (kube|k8s|kubernetes) run '
  daemonsets=$(kubectl get daemonsets --all-namespaces -o "jsonpath={range .items[*]}{.metadata.namespace}/{.metadata.name}|{.metadata.labels.${E2E_LABEL}}|{.spec.template.spec.containers[*].image} {.spec.template.spec.containers[*].command} {.spec.template.spec.containers[*].args}{\"\n\"}{end}")
  # Fields are split at "|", not a tab: read joins adjacent tabs, which
  # would shift the fields of a DaemonSet without the label.
  while IFS='|' read -r id label spec; do
    [[ -z "$id" ]] && continue
    if [[ "$id" == "${AGENT_NS}/postman-insights-agent" && ("$label" == true || -n "$KIND_CLUSTER") ]]; then
      continue
    fi
    # The containers' images, commands and arguments as one list of words, so
    # `kube run` is found also when split between command and arguments or
    # inside a shell string, and under kube's aliases (k8s, kubernetes).
    words=" $(tr '[],"' '    ' <<<"$spec" | tr -s ' ') "
    if [[ "$words" == *postman-insights-agent* || "$words" =~ $kube_run ]]; then
      others+=" ${id}"
    fi
  done <<<"$daemonsets"
  if [[ -n "$others" ]]; then
    echo "ERROR: another Postman Insights agent runs in this cluster:${others}." >&2
    echo "       Two agents on a node would both capture the test services. Remove it, or test in another cluster." >&2
    exit 1
  fi
  [[ -n "$KIND_CLUSTER" ]] && return
  for res in "namespace/${NS}" "namespace/${CLIENT_NS}" "namespace/${AGENT_NS}" \
    clusterrole/postman-insights-agent clusterrolebinding/postman-insights-agent; do
    if read_owner "$res" && [[ "$OWNER" != true ]]; then
      foreign+=" ${res}"
    fi
  done
  # The DaemonSet by its name, whatever it runs: applying would replace it.
  if read_owner -n "$AGENT_NS" daemonset/postman-insights-agent && [[ "$OWNER" != true ]]; then
    foreign+=" daemonset/postman-insights-agent (namespace ${AGENT_NS})"
  fi
  if [[ -n "$foreign" ]]; then
    echo "ERROR: these exist in the cluster but were not created by the end-to-end scripts (no ${E2E_LABEL}=true label):${foreign}." >&2
    echo "       The scripts would take them over, and teardown.sh would delete them. Test in another cluster." >&2
    exit 1
  fi
}

# Creates a namespace the scripts own, labelled with E2E_LABEL.
claim_namespace() {
  kubectl apply -f - <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: $1
  labels:
    ${E2E_LABEL}: "true"
EOF
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

# Deploys the production DaemonSet, so that it starts after the services, and
# waits for it. Call it after the services are up. use_cluster has stopped
# the agent of an earlier run, so the DaemonSet is created anew; one that
# exists anyway is restarted, which a DaemonSet just created must not be: its
# first pods would still be terminating beside their replacements.
deploy_agent() {
  local existed
  echo "==> Agent DaemonSet (kube run --enable-https-capture)"
  existed=$(kubectl get daemonset -n "$AGENT_NS" postman-insights-agent --ignore-not-found -o name)
  claim_namespace "$AGENT_NS"
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
  if [[ -n "$existed" ]]; then
    kubectl rollout restart -n "$AGENT_NS" daemonset/postman-insights-agent
  fi
  kubectl rollout status -n "$AGENT_NS" daemonset/postman-insights-agent --timeout=180s
}

# Creates the test-apps namespace and the TLS ConfigMap the Node.js and
# ASP.NET services read their certificates from.
apply_tls_configmap() {
  "$CERT_DIR/gen-java-service-certs.sh"
  claim_namespace "$NS"
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
  claim_namespace "$CLIENT_NS" >/dev/null
  kubectl delete pod -n "$CLIENT_NS" "$1" --ignore-not-found >/dev/null
  kubectl run "$1" --restart=Never -n "$CLIENT_NS" --image=curlimages/curl:latest --rm -i --quiet -- sh -ec "$2"
}

# Waits for the next ebpf-stats lines (logged every 30 s) and sets LOGS to
# the recent log of the agent pod on each node that runs a test service,
# each line ending in " [node=<node>]". Each node's agent logs only its own
# pods, so on a cluster of several nodes one agent pod's log is not enough.
collect_logs() {
  local nodes node agents
  echo "==> Waiting for the next ebpf-stats lines (logged every 30s)"
  sleep 40
  nodes=$(kubectl get pods -n "$NS" -o jsonpath='{range .items[*]}{.spec.nodeName}{"\n"}{end}' | sort -u)
  LOGS=""
  for node in $nodes; do
    # Newest first is not available, so oldest first and the last one: a
    # pod replaced by a rollout may still be terminating on the node.
    agents=$(kubectl get pods -n "$AGENT_NS" -l app=postman-insights-agent \
      --field-selector "spec.nodeName=${node}" --sort-by=.metadata.creationTimestamp \
      -o jsonpath='{.items[*].metadata.name}')
    if [[ -z "$agents" ]]; then
      echo "ERROR: no agent pod on node ${node}, which runs test services." >&2
      exit 1
    fi
    LOGS+=$(kubectl logs -n "$AGENT_NS" "${agents##* }" --since=5m | sed "s/\$/ [node=${node}]/")$'\n'
  done
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

# Sum over the nodes in LOGS of each node's highest value of a field of its
# node line (a node-wide counter, such as java_events, adds up across nodes);
# empty when no node line has it.
sum_node_field() {
  { grep -o "ebpf-stats: node .*" <<<"$LOGS" | awk -v f="$1" '
      {
        for (i = 1; i < NF; i++) {
          if (index($i, f "=") == 1) {
            v = substr($i, length(f) + 2) + 0
            if (!($NF in m) || v > m[$NF]) m[$NF] = v
            seen = 1
          }
        }
      }
      END { if (seen) { s = 0; for (n in m) s += m[n]; print s } }'; } || true
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
