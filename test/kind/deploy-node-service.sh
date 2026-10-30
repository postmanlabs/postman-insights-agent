#!/usr/bin/env bash
# End-to-end check of OpenSSL HTTPS capture of a Node.js service in kind,
# through the production DaemonSet path (kube run --enable-https-capture,
# agent-daemonset-prod.yaml).
#
# Deploys node-service (HTTPS on 8443, gRPC-TLS on 8446) and the agent, sends
# HTTPS requests to it, and checks the agent's ebpf-stats line for its pod:
# the libssl uprobes captured its requests and responses, parsed into HTTP
# messages. Captures also appear in Postman Insights under
# the cluster "pia-kind-test". For gRPC and requests from your machine, see
# test/kind/SERVICE-TEST-GUIDE.md.
#
# Prerequisites: Docker Desktop, kind, kubectl, a Postman Insights API key.
#
# Usage:
#   export POSTMAN_INSIGHTS_API_KEY=your_key_here
#   ./test/kind/deploy-node-service.sh              # build images, deploy, check
#   ./test/kind/deploy-node-service.sh --skip-build # reuse the images in kind
#   ./test/kind/deploy-node-service.sh --static     # node's own static BoringSSL
set -euo pipefail

# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

NODE_IMAGE=pia-node-service:test
SKIP_BUILD=false
STATIC=false
REQUESTS=5

for arg in "$@"; do
  case "$arg" in
    --skip-build) SKIP_BUILD=true ;;
    --static) STATIC=true ;;
    -h|--help) sed -n '2,19p' "$0"; exit 0 ;;
    *) echo "unknown arg: $arg" >&2; exit 1 ;;
  esac
done

require_api_key
use_cluster

if [[ "$STATIC" == "true" ]]; then
  DOCKERFILE="$REPO_ROOT/test/kind/Dockerfile.node-service"
  WORKLOAD="$REPO_ROOT/test/kind/node-service-workload.yaml"
else
  DOCKERFILE="$REPO_ROOT/test/kind/Dockerfile.node-service-dynamic"
  WORKLOAD="$REPO_ROOT/test/kind/node-service-workload-dynamic.yaml"
fi

if [[ "$SKIP_BUILD" == "false" ]]; then
  build_agent
  echo "==> Building ${NODE_IMAGE} ($(basename "$DOCKERFILE"))"
  docker build -f "$DOCKERFILE" -t "$NODE_IMAGE" "$REPO_ROOT"
  kind load docker-image "$NODE_IMAGE" --name "$CLUSTER"
fi

echo "==> node-service"
apply_tls_configmap
deploy_service node-service "$WORKLOAD"
# For in-cluster callers, such as dotnet-service's /phase5b2/call-external.
kubectl apply -f "$REPO_ROOT/test/kind/node-service-service.yaml"
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
echo "==> Node.js HTTPS capture works end to end; check Postman Insights cluster 'pia-kind-test' for the endpoints"
