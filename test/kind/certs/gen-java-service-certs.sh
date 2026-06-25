#!/usr/bin/env bash
# Stable self-signed TLS for test/kind java-service (HTTPS + gRPC).
#
# Writes into this directory so the Mac host and the kind pod share the
# same trust PEM — no kubectl cp needed for curl/grpcurl from your laptop.
#
# Usage:
#   ./test/kind/certs/gen-java-service-certs.sh
#   ./test/kind/deploy-java-service.sh
#
# Mac clients (after port-forward):
#   curl  --cacert test/kind/certs/hello-https-trust.pem https://127.0.0.1:8443/phase5b2
#   grpcurl -cacert test/kind/certs/hello-https-trust.pem -d '{"name":"mac"}' \
#     localhost:8446 phase5c2.Greeter/SayHello

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT="$DIR/grpc-cert.pem"
KEY="$DIR/grpc-key.pem"
KS="$DIR/hello-https-keystore.p12"
TRUST="$DIR/hello-https-trust.pem"

if [[ -f "$CERT" && -f "$KEY" && -f "$KS" && -f "$TRUST" ]]; then
  echo "certs already present in $DIR (delete to regenerate)"
  exit 0
fi

openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout "$KEY" -out "$CERT" \
  -days 365 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

openssl pkcs12 -export \
  -in "$CERT" -inkey "$KEY" \
  -out "$KS" -passout pass:changeit -name hello

cp "$CERT" "$TRUST"

echo "generated:"
ls -la "$DIR"/grpc-cert.pem "$DIR"/grpc-key.pem "$DIR"/hello-https-keystore.p12 "$DIR"/hello-https-trust.pem
