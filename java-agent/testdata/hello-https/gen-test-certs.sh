#!/usr/bin/env bash
# Self-signed PKCS12 for HelloHttps + PEM trust bundle for curl (no -k).
#
# Writes into ./certs/ under this directory so files are visible on the Mac
# host (dev container bind-mounts the repo at /workspace). Run kubectl cp
# from your Mac — the dev container does not have kubectl.
#
# Usage (inside dev container or any host with keytool):
#   ./gen-test-certs.sh
#   java -javaagent:... -Dhello.keystore=<certs>/hello-https-keystore.p12 ...
#   curl -s --cacert <certs>/hello-https-trust.pem https://127.0.0.1:8443/phase5b2

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="${SCRIPT_DIR}/certs"
KS="${CERT_DIR}/hello-https-keystore.p12"
PEM="${CERT_DIR}/hello-https-trust.pem"
PASS=changeit
ALIAS=hello

mkdir -p "$CERT_DIR"

if [[ ! -f "$KS" ]]; then
  keytool -genkeypair \
    -alias "$ALIAS" \
    -keyalg RSA \
    -keysize 2048 \
    -storetype PKCS12 \
    -keystore "$KS" \
    -storepass "$PASS" \
    -dname "CN=localhost" \
    -ext "SAN=DNS:localhost,IP:127.0.0.1" \
    -validity 365 \
    >/dev/null 2>&1
  echo "generated keystore: $KS"
else
  echo "keystore already exists: $KS"
fi

keytool -exportcert \
  -alias "$ALIAS" \
  -keystore "$KS" \
  -storepass "$PASS" \
  -rfc \
  -file "$PEM" \
  >/dev/null 2>&1

echo "exported trust PEM: $PEM"
echo
echo "Dev container — start HelloHttps:"
echo "  cd /workspace/java-agent"
echo "  java -javaagent:build/libs/postman-java-agent.jar -cp build/libs/postman-java-agent.jar \\"
echo "       -Dhello.keystore=$KS \\"
echo "       com.postman.insights.agent.testdata.HelloHttps"
echo
echo "Dev container — curl with certificate verification (no -k):"
echo "  curl -v --cacert $PEM https://127.0.0.1:8443/phase5b2"
echo
echo "Mac host — copy certs into a kind pod (kubectl is on the Mac, not in dev container):"
echo "  cd $SCRIPT_DIR/../..   # repo java-agent/"
echo "  kubectl cp testdata/hello-https/certs/hello-https-keystore.p12 \\"
echo "    test-apps/java-https:/tmp/hello-https-keystore.p12"
echo "  kubectl cp testdata/hello-https/certs/hello-https-trust.pem \\"
echo "    test-apps/java-https:/tmp/hello-https-trust.pem"
