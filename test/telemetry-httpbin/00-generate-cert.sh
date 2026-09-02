#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/certs"
FORCE=false

usage() {
  cat <<EOF
Usage: $(basename "$0") [--force]

Generate the local CA and TLS certificate used by the telemetry-httpbin
nginx sidecar. Files are written to OUTPUT_DIR, or the certs/ directory beside
this script by default.

Set OUTPUT_DIR to generate the files somewhere else, for example:
  OUTPUT_DIR=/tmp/telemetry-httpbin-certs $(basename "$0")
EOF
}

for arg in "$@"; do
  case "${arg}" in
    --force)
      FORCE=true
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: ${arg}" >&2
      usage >&2
      exit 1
      ;;
  esac
done

command -v openssl >/dev/null 2>&1 || {
  echo "openssl is required but was not found in PATH" >&2
  exit 1
}

mkdir -p "${OUTPUT_DIR}"

artifacts=(ca.key ca.crt ca.srl tls.key tls.csr tls.crt)
if [[ "${FORCE}" != true ]]; then
  for artifact in "${artifacts[@]}"; do
    if [[ -e "${OUTPUT_DIR}/${artifact}" ]]; then
      echo "Refusing to overwrite ${OUTPUT_DIR}/${artifact}; use --force to regenerate" >&2
      exit 1
    fi
  done
fi

openssl genrsa -out "${OUTPUT_DIR}/ca.key" 2048
openssl req -x509 -new -sha256 -days 3650 \
  -key "${OUTPUT_DIR}/ca.key" \
  -out "${OUTPUT_DIR}/ca.crt" \
  -subj "/O=Local Dev/OU=Telemetry Httpbin CA/CN=telemetry-httpbin-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

openssl genrsa -out "${OUTPUT_DIR}/tls.key" 2048
openssl req -new -sha256 \
  -key "${OUTPUT_DIR}/tls.key" \
  -out "${OUTPUT_DIR}/tls.csr" \
  -subj "/O=Local Dev/OU=Telemetry Httpbin/CN=telemetry-httpbin.telemetry-httpbin.svc" \
  -addext "subjectAltName=DNS:telemetry-httpbin,DNS:telemetry-httpbin.telemetry-httpbin,DNS:telemetry-httpbin.telemetry-httpbin.svc,DNS:telemetry-httpbin.telemetry-httpbin.svc.cluster.local,DNS:localhost,IP:127.0.0.1"

openssl x509 -req -sha256 -days 825 \
  -in "${OUTPUT_DIR}/tls.csr" \
  -CA "${OUTPUT_DIR}/ca.crt" \
  -CAkey "${OUTPUT_DIR}/ca.key" \
  -CAcreateserial -CAserial "${OUTPUT_DIR}/ca.srl" \
  -out "${OUTPUT_DIR}/tls.crt" \
  -copy_extensions copy

echo "Generated local CA and TLS certificate in ${OUTPUT_DIR}"
