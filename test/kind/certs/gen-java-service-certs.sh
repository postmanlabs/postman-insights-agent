#!/usr/bin/env bash
# Self-signed TLS for test/kind workloads (HTTPS + gRPC).
#
# OpenSSL steps mirror the customer container entrypoint in
# docs/nocheckin/glic.txt (cert.key / cert.crt / cert.pfx, empty PKCS12
# password). Outputs are renamed for the Kind ConfigMap layout.
#
# Usage:
#   ./test/kind/certs/gen-java-service-certs.sh
#   ./test/kind/certs/gen-java-service-certs.sh --force
#   OPENSSL_SUBJ='/CN=myhost.example.com' ./test/kind/certs/gen-java-service-certs.sh
#
# Mac clients (after port-forward):
#   curl  --cacert test/kind/certs/hello-https-trust.pem https://localhost:8443/phase5b2
#   grpcurl -cacert test/kind/certs/hello-https-trust.pem -d '{"name":"mac"}' \
#     localhost:8446 phase5c2.Greeter/SayHello

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT="$DIR/grpc-cert.pem"      # customer: /app/cert.crt
KEY="$DIR/grpc-key.pem"        # customer: /app/cert.key
KS="$DIR/hello-https-keystore.p12"  # customer: /app/cert.pfx
TRUST="$DIR/hello-https-trust.pem"

FORCE=false
for arg in "$@"; do
  case "$arg" in
    --force) FORCE=true ;;
    -h|--help)
      sed -n '2,16p' "$0"
      exit 0
      ;;
    *) echo "unknown arg: $arg" >&2; exit 1 ;;
  esac
done

if [[ "$FORCE" != "true" && -f "$CERT" && -f "$KEY" && -f "$KS" && -f "$TRUST" ]]; then
  echo "certs already present in $DIR (delete or pass --force to regenerate)"
  exit 0
fi

# Customer glic.txt uses a deployment-specific -subj; default suits Kind port-forward.
OPENSSL_SUBJ="${OPENSSL_SUBJ:-/CN=localhost}"
# Kind-only: SAN required for grpcurl (Go TLS rejects CN-only certs since Go 1.15).
OPENSSL_SAN="${OPENSSL_SAN:-DNS:localhost,IP:127.0.0.1}"

# Same commands as docs/nocheckin/glic.txt (paths mapped to Kind filenames), plus SAN for Mac grpcurl.
openssl req -x509 -newkey rsa:2048 -days 365 -nodes -x509 \
  -subj "$OPENSSL_SUBJ" \
  -addext "subjectAltName=${OPENSSL_SAN}" \
  -keyout "$KEY" -out "$CERT"

openssl pkcs12 -export \
  -out "$KS" -inkey "$KEY" -in "$CERT" \
  -passout pass:

cp "$CERT" "$TRUST"

echo "generated (customer-style openssl from docs/nocheckin/glic.txt):"
ls -la "$CERT" "$KEY" "$KS" "$TRUST"
echo "PKCS12 password: (empty — matches customer cert.pfx)"
echo "OPENSSL_SUBJ=$OPENSSL_SUBJ"
echo "OPENSSL_SAN=$OPENSSL_SAN"
