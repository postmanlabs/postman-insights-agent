#!/usr/bin/env bash
# End-to-end check of OpenSSL HTTPS capture of an ASP.NET Core service in a
# cluster (kind by default), through the production DaemonSet path (kube run
# --enable-https-capture, agent-daemonset-prod.yaml).
#
# Deploys dotnet-service (HTTPS on 8443, gRPC-TLS on 8446) and the agent,
# sends HTTPS requests to it, and checks the agent's ebpf-stats line for its
# pod: the libssl uprobes captured its requests and responses, parsed into
# HTTP messages. When node-service runs (deploy it
# first with deploy-node-service.sh), it also calls /phase5b2/call-external,
# whose outbound HTTPS call to node-service is captured on the dotnet side
# too. Captures also appear in Postman Insights under the cluster
# INSIGHTS_CLUSTER_NAME (pia-kind-test). For gRPC and requests from your
# machine, see test/e2e/SERVICE-TEST-GUIDE.md.
#
# Prerequisites: docker, kubectl, and kind for a kind cluster; a Postman
# Insights API key for the backend POSTMAN_ENV names. See lib.sh for the
# settings (POSTMAN_ENV, KUBE_CONTEXT, INSIGHTS_CLUSTER_NAME).
#
# Usage:
#   export POSTMAN_ENV=BETA POSTMAN_INSIGHTS_API_KEY="$POSTMAN_API_KEY_BETA"
#   ./test/e2e/deploy-dotnet-service.sh              # build images, deploy, check
#   ./test/e2e/deploy-dotnet-service.sh --skip-build # reuse the images on the nodes
set -euo pipefail

# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

DOTNET_IMAGE="${DOTNET_IMAGE:-pia-dotnet-service:test}"
SKIP_BUILD=false
REQUESTS=5

for arg in "$@"; do
  case "$arg" in
    --skip-build) SKIP_BUILD=true ;;
    -h|--help) sed -n '2,23p' "$0"; exit 0 ;;
    *) echo "unknown arg: $arg" >&2; exit 1 ;;
  esac
done

require_backend
use_cluster

if building_images; then
  build_agent
  build_image "$REPO_ROOT/test/e2e/apps/dotnet-service/Dockerfile" "$DOTNET_IMAGE"
  load_images "$DOTNET_IMAGE"
fi

echo "==> dotnet-service"
apply_tls_configmap
deploy_service dotnet-service "$DOTNET_IMAGE"
wait_services dotnet-service

deploy_agent
# The agent attaches its uprobes once discovery finds the dotnet process.
sleep 15

ip=$(ip_of dotnet-service)
calls=0
if kubectl get deployment -n "$NS" node-service >/dev/null 2>&1; then
  calls=$REQUESTS
else
  echo "==> node-service is not deployed: skipping the outbound calls"
fi
echo "==> Sending ${REQUESTS} HTTPS requests and ${calls} outbound calls to ${ip}:8443 from namespace ${CLIENT_NS}"
run_client dotnet-client "
  for i in \$(seq 1 ${REQUESTS}); do
    curl -fsSk 'https://${ip}:8443/phase5b2?from=kind&i='\$i; echo
  done
  for i in \$(seq 1 ${calls}); do
    curl -fsSk 'https://${ip}:8443/phase5b2/call-external?q=kind-'\$i; echo
  done"

collect_logs
fail=0
pod=$(pod_of dotnet-service)
# A request and a response each, and for an outbound call also its own
# request to node-service and that response.
check_at_least dotnet-service msgs "$pod" $((REQUESTS * 2 + calls * 4))
finish_checks
echo "==> ASP.NET Core HTTPS capture works end to end; check Postman Insights (POSTMAN_ENV=${POSTMAN_ENV}) cluster '${INSIGHTS_CLUSTER_NAME}' for the endpoints"
