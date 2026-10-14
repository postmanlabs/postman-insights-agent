#!/usr/bin/env bash
# Generates the self-signed TLS files the kind test workloads mount through
# the test-apps-tls ConfigMap (node-service, dotnet-service). They are written
# here and gitignored; nothing secret is committed.
#
#   grpc-cert.pem / grpc-key.pem   certificate and key (PEM)
#   hello-https-keystore.p12       the same pair as PKCS12, empty password
#   hello-https-trust.pem          the certificate, for clients to trust
#
# Usage:
#   ./test/kind/certs/gen-java-service-certs.sh           # keep existing files
#   ./test/kind/certs/gen-java-service-certs.sh --force   # regenerate
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT="$DIR/grpc-cert.pem"
KEY="$DIR/grpc-key.pem"
KEYSTORE="$DIR/hello-https-keystore.p12"
TRUST="$DIR/hello-https-trust.pem"

FORCE=false
for arg in "$@"; do
  case "$arg" in
    --force) FORCE=true ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) echo "unknown arg: $arg" >&2; exit 1 ;;
  esac
done

if [[ "$FORCE" != "true" && -f "$CERT" && -f "$KEY" && -f "$KEYSTORE" && -f "$TRUST" ]]; then
  echo "certs already present in $DIR (pass --force to regenerate)"
  exit 0
fi

# SAN is required by Go clients such as grpcurl, which reject CN-only certs.
openssl req -x509 -newkey rsa:2048 -days 365 -nodes \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout "$KEY" -out "$CERT"
openssl pkcs12 -export -out "$KEYSTORE" -inkey "$KEY" -in "$CERT" -passout pass:
cp "$CERT" "$TRUST"
echo "generated $CERT, $KEY, $KEYSTORE, $TRUST"
