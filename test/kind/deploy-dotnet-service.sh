#!/usr/bin/env bash
# End-to-end check of OpenSSL HTTPS capture of an ASP.NET Core service in
# kind, through the production DaemonSet path (kube run
# --enable-https-capture, agent-daemonset-prod.yaml).
#
# Deploys dotnet-service (HTTPS on 8443, gRPC-TLS on 8446) and the agent,
# sends HTTPS requests to it, and checks the agent's ebpf-stats line for its
# pod: the libssl uprobes captured its requests and responses, parsed into
# HTTP messages. When node-service runs (deploy it
# first with deploy-node-service.sh), it also calls /phase5b2/call-external,
# whose outbound HTTPS call to node-service is captured on the dotnet side
# too. Captures also appear in Postman Insights under the cluster
# "pia-kind-test". For gRPC and requests from your machine, see
# test/kind/SERVICE-TEST-GUIDE.md.
#
# Prerequisites: Docker Desktop, kind, kubectl, a Postman Insights API key.
#
# Usage:
#   export POSTMAN_INSIGHTS_API_KEY=your_key_here
#   ./test/kind/deploy-dotnet-service.sh              # build images, deploy, check
#   ./test/kind/deploy-dotnet-service.sh --skip-build # reuse the images in kind
set -euo pipefail

# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

DOTNET_IMAGE=pia-dotnet-service:test
SKIP_BUILD=false
REQUESTS=5

for arg in "$@"; do
  case "$arg" in
    --skip-build) SKIP_BUILD=true ;;
    -h|--help) sed -n '2,21p' "$0"; exit 0 ;;
    *) echo "unknown arg: $arg" >&2; exit 1 ;;
  esac
done

require_api_key
use_cluster

if [[ "$SKIP_BUILD" == "false" ]]; then
  build_agent
  echo "==> Building ${DOTNET_IMAGE}"
  docker build -f "$REPO_ROOT/test/kind/Dockerfile.dotnet-service" -t "$DOTNET_IMAGE" "$REPO_ROOT"
  kind load docker-image "$DOTNET_IMAGE" --name "$CLUSTER"
fi

echo "==> dotnet-service"
apply_tls_configmap
deploy_service dotnet-service
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
echo "==> ASP.NET Core HTTPS capture works end to end; check Postman Insights cluster 'pia-kind-test' for the endpoints"
