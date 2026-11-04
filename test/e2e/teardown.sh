#!/usr/bin/env bash
# Removes what the end-to-end scripts (deploy-*-service.sh) deployed in a
# cluster: the namespaces test-apps, test-clients and postman-insights, with
# everything in them (the agent DaemonSet, the test services and clients),
# and the agent's ClusterRole and ClusterRoleBinding.
#
# It removes only resources with the postman-insights-e2e=true label, which
# the scripts put on each of them, so nothing else in a shared cluster is
# touched. Resources from before the scripts labelled them are left; on kind,
# deleting the cluster removes everything:
#   kind delete cluster --name pia-https-test
#
# Usage:
#   KUBE_CONTEXT=<context> ./test/e2e/teardown.sh   # default kind-pia-https-test
set -euo pipefail

# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

for arg in "$@"; do
  case "$arg" in
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "unknown arg: $arg" >&2; exit 1 ;;
  esac
done

if ! find_cluster; then
  echo "==> No kind cluster ${KIND_CLUSTER}: nothing to remove"
  exit 0
fi

selector="${E2E_LABEL}=true"
found=$(kubectl get namespaces,clusterroles,clusterrolebindings -l "$selector" -o name)
if [[ -z "$found" ]]; then
  echo "==> Nothing labelled ${selector} in context ${KUBE_CONTEXT}"
  exit 0
fi
echo "==> Removing from context ${KUBE_CONTEXT}:"
while read -r res; do echo "      ${res}"; done <<<"$found"
kubectl delete namespaces,clusterroles,clusterrolebindings -l "$selector" --wait=true
