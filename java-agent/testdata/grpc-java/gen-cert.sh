#!/usr/bin/env bash
# Generate a self-signed PEM cert+key for the gRPC server.
set -euo pipefail
CERT=/tmp/grpc-cert.pem
KEY=/tmp/grpc-key.pem
if [[ -f "$CERT" && -f "$KEY" ]]; then
  echo "already present: $CERT, $KEY"
  exit 0
fi
openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout "$KEY" -out "$CERT" \
  -days 365 -subj "/CN=localhost" >/dev/null 2>&1
echo "generated $CERT, $KEY"
