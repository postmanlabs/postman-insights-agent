#!/bin/bash
# Phase 5c.3b — Regenerate dev TLS material and manifests for the kind e2e.
#
# This script is the entire "how to reproduce 5c.3b" recipe for the TLS bits.
# Private keys are NEVER committed to this public repo; this script regenerates
# them from scratch.
#
# Output files (all .gitignored):
#   ca.key, ca.crt, ca.srl       — dev-only self-signed CA
#   webhook.key, webhook.csr, webhook.crt — server cert signed by the CA
#   webhook-deployment.yaml       — generated from webhook-deployment.yaml.tmpl
#   webhook-config.yaml           — generated from webhook-config.yaml.tmpl
#
# Usage:
#   cd test/kind/webhook
#   ./gen-tls-and-manifests.sh
#   kubectl apply -f webhook-deployment.yaml
#   kubectl wait --for=condition=available --timeout=60s \
#       deployment/postman-insights-webhook -n postman-insights
#   kubectl apply -f webhook-config.yaml
#
# THE certs are dev-only. Production should use cert-manager (see 5c.3c).

set -euo pipefail

cd "$(dirname "$0")"

# ----- CA -----
if [ ! -f ca.key ] || [ ! -f ca.crt ]; then
  echo "[gen-tls] generating dev CA..."
  openssl genrsa -out ca.key 2048 2>/dev/null
  openssl req -x509 -new -nodes -key ca.key -days 3650 \
    -subj "/CN=postman-insights-webhook-ca" -out ca.crt 2>/dev/null
else
  echo "[gen-tls] reusing existing CA (delete ca.key + ca.crt to regenerate)"
fi

# ----- Server cert -----
echo "[gen-tls] generating webhook server cert..."
openssl genrsa -out webhook.key 2048 2>/dev/null
openssl req -new -key webhook.key -out webhook.csr -config openssl.cnf
openssl x509 -req -in webhook.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out webhook.crt -days 365 -extensions v3_req -extfile openssl.cnf 2>&1 | tail -2

# ----- Render manifests from templates -----
echo "[gen-manifests] rendering webhook-deployment.yaml + webhook-config.yaml..."
CA_B64=$(base64 < ca.crt | tr -d '\n')
WEBHOOK_CRT_B64=$(base64 < webhook.crt | tr -d '\n')
WEBHOOK_KEY_B64=$(base64 < webhook.key | tr -d '\n')

sed -e "s|__WEBHOOK_CRT_B64__|${WEBHOOK_CRT_B64}|" \
    -e "s|__WEBHOOK_KEY_B64__|${WEBHOOK_KEY_B64}|" \
    webhook-deployment.yaml.tmpl > webhook-deployment.yaml

sed -e "s|__CA_BUNDLE_B64__|${CA_B64}|" \
    webhook-config.yaml.tmpl > webhook-config.yaml

echo
echo "[ok] generated files:"
ls -1 ca.crt webhook.crt webhook-deployment.yaml webhook-config.yaml
echo
echo "Next: kubectl apply -f webhook-deployment.yaml"
