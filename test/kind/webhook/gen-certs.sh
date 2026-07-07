#!/usr/bin/env bash
# gen-certs.sh — Generate self-signed TLS certs for local kind webhook testing.
#
# Usage:
#   cd test/kind/webhook
#   ./gen-certs.sh
#
# Outputs:
#   webhook-deployment-with-certs.yaml  — ready-to-apply manifest with embedded certs
#   tls.crt / tls.key                   — raw PEM files (for inspection; not committed)
#
# The generated certs are valid for the webhook service DNS names inside the
# kind cluster.  They are self-signed and suitable for local testing ONLY.
# Do NOT use these certs in production.

set -euo pipefail

NAMESPACE="postman-insights"
SVC_NAME="postman-insights-webhook"
DAYS=365
OUT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Generating CA..."
openssl genrsa -out "$OUT_DIR/ca.key" 4096 2>/dev/null
openssl req -new -x509 -days "$DAYS" -key "$OUT_DIR/ca.key" \
  -subj "/CN=postman-insights-webhook-ca" \
  -out "$OUT_DIR/ca.crt" 2>/dev/null

echo "Generating server key and CSR..."
openssl genrsa -out "$OUT_DIR/tls.key" 4096 2>/dev/null
openssl req -new -key "$OUT_DIR/tls.key" \
  -subj "/CN=${SVC_NAME}.${NAMESPACE}.svc" \
  -out "$OUT_DIR/server.csr" 2>/dev/null

cat > "$OUT_DIR/san.ext" <<SAN
subjectAltName = DNS:${SVC_NAME},DNS:${SVC_NAME}.${NAMESPACE},DNS:${SVC_NAME}.${NAMESPACE}.svc,DNS:${SVC_NAME}.${NAMESPACE}.svc.cluster.local
SAN

echo "Signing server cert..."
openssl x509 -req -days "$DAYS" \
  -in "$OUT_DIR/server.csr" \
  -CA "$OUT_DIR/ca.crt" -CAkey "$OUT_DIR/ca.key" -CAcreateserial \
  -extfile "$OUT_DIR/san.ext" \
  -out "$OUT_DIR/tls.crt" 2>/dev/null

# Base64-encode (no line wrapping)
TLS_CRT=$(base64 < "$OUT_DIR/tls.crt" | tr -d '\n')
TLS_KEY=$(base64 < "$OUT_DIR/tls.key" | tr -d '\n')

echo "Writing webhook-deployment-with-certs.yaml..."
sed \
  -e "s|REPLACE_WITH_BASE64_ENCODED_CERT|${TLS_CRT}|" \
  -e "s|REPLACE_WITH_BASE64_ENCODED_KEY|${TLS_KEY}|" \
  "$OUT_DIR/webhook-deployment.yaml" \
  > "$OUT_DIR/webhook-deployment-with-certs.yaml"

# Clean up intermediates
rm -f "$OUT_DIR/ca.key" "$OUT_DIR/ca.crt" "$OUT_DIR/server.csr" "$OUT_DIR/san.ext" "$OUT_DIR/ca.srl"

echo "Done. Apply with:"
echo "  kubectl apply -f $OUT_DIR/webhook-deployment-with-certs.yaml"
echo ""
echo "NOTE: tls.crt and tls.key are in $OUT_DIR — do not commit them."
