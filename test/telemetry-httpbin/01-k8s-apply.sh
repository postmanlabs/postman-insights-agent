#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAMESPACE="telemetry-httpbin"

kubectl create namespace "$NAMESPACE" \
  --dry-run=client \
  -o yaml | kubectl apply -f -

kubectl create secret tls telemetry-httpbin-tls \
  --namespace "${NAMESPACE}" \
  --cert "${SCRIPT_DIR}/certs/tls.crt" \
  --key "${SCRIPT_DIR}/certs/tls.key" \
  --dry-run=client \
  -o yaml | kubectl apply -f -

echo "Applied secret telemetry-httpbin-tls in namespace ${NAMESPACE}"

kubectl apply -f $SCRIPT_DIR/k8s.yaml

echo "Applied telemetry httpbin workload manifests in namespace ${NAMESPACE}"
