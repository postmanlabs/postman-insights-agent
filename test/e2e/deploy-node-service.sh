#!/usr/bin/env bash
# End-to-end check of OpenSSL HTTPS capture of a Node.js service in a
# cluster (kind by default), through the production DaemonSet path (kube run
# --enable-https-capture, agent-daemonset-prod.yaml).
#
# Deploys node-service (HTTPS on 8443, gRPC-TLS on 8446) and the agent, sends
# HTTPS requests to it, and checks the agent's ebpf-stats line for its pod:
# the libssl uprobes captured its requests and responses, parsed into HTTP
# messages. Captures also appear in Postman Insights under the cluster
# INSIGHTS_CLUSTER_NAME (pia-kind-test). For gRPC and requests from your
# machine, see test/e2e/SERVICE-TEST-GUIDE.md.
#
# Prerequisites: docker, kubectl, and kind for a kind cluster; a Postman
# Insights API key for the backend POSTMAN_ENV names. See lib.sh for the
# settings (POSTMAN_ENV, KUBE_CONTEXT, INSIGHTS_CLUSTER_NAME).
#
# Usage:
#   export POSTMAN_ENV=BETA POSTMAN_INSIGHTS_API_KEY="$POSTMAN_API_KEY_BETA"
#   ./test/e2e/deploy-node-service.sh              # build images, deploy, check
#   ./test/e2e/deploy-node-service.sh --skip-build # reuse the images on the nodes
#   ./test/e2e/deploy-node-service.sh --static     # node's own static BoringSSL
set -euo pipefail

# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

NODE_IMAGE="${NODE_IMAGE:-pia-node-service:test}"
SKIP_BUILD=false
STATIC=false
REQUESTS=5

for arg in "$@"; do
  case "$arg" in
    --skip-build) SKIP_BUILD=true ;;
    --static) STATIC=true ;;
    -h|--help) sed -n '2,21p' "$0"; exit 0 ;;
    *) echo "unknown arg: $arg" >&2; exit 1 ;;
  esac
done

require_backend
use_cluster

if [[ "$STATIC" == "true" ]]; then
  DOCKERFILE="$REPO_ROOT/test/e2e/apps/node-service/Dockerfile"
  WORKLOAD="$REPO_ROOT/test/e2e/node-service-workload.yaml"
else
  DOCKERFILE="$REPO_ROOT/test/e2e/apps/node-service/Dockerfile.dynamic"
  WORKLOAD="$REPO_ROOT/test/e2e/node-service-workload-dynamic.yaml"
fi

if building_images; then
  build_agent
  build_image "$DOCKERFILE" "$NODE_IMAGE"
  load_images "$NODE_IMAGE"
fi

echo "==> node-service"
apply_tls_configmap
deploy_service node-service "$NODE_IMAGE" "$WORKLOAD"
# For in-cluster callers, such as dotnet-service's /phase5b2/call-external.
kubectl apply -f "$REPO_ROOT/test/e2e/node-service-service.yaml"
wait_services node-service

deploy_agent
# The agent attaches its uprobes once discovery finds the node process.
sleep 15

ip=$(ip_of node-service)
echo "==> Sending ${REQUESTS} HTTPS requests to ${ip}:8443 from namespace ${CLIENT_NS}"
run_client node-client "
  for i in \$(seq 1 ${REQUESTS}); do
    curl -fsSk 'https://${ip}:8443/phase5b2?from=kind&i='\$i
  done"

collect_logs
fail=0
pod=$(pod_of node-service)
check_at_least node-service msgs "$pod" $((REQUESTS * 2)) # a request and a response each
finish_checks
echo "==> Node.js HTTPS capture works end to end; check Postman Insights (POSTMAN_ENV=${POSTMAN_ENV}) cluster '${INSIGHTS_CLUSTER_NAME}' for the endpoints"
