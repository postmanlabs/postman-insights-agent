#!/usr/bin/env bash
# Run node-service locally on macOS/Linux for HTTPS + gRPC smoke tests.
#
# Part 1 (local):
#   ./test/kind/run-node-service-local.sh server    # terminal 1
#   ./test/kind/run-node-service-local.sh test      # terminal 2
#
# Part 2 (kind): ./test/kind/deploy-node-service.sh then same curl/grpcurl.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SERVICE_DIR="$REPO_ROOT/test/kind/node-service"
CERT_DIR="$REPO_ROOT/test/kind/certs"
TLS_DIR="$CERT_DIR"
CACERT="$CERT_DIR/hello-https-trust.pem"
HTTPS_PORT="${HTTPS_PORT:-8443}"
GRPC_PORT="${GRPC_PORT:-8446}"

port_busy() {
  lsof -i ":$1" >/dev/null 2>&1
}

"$CERT_DIR/gen-java-service-certs.sh"

export TLS_DIR BIND_HOST=127.0.0.1 HTTPS_PORT GRPC_PORT

cmd="${1:-}"

case "$cmd" in
  server)
    if port_busy "$HTTPS_PORT" || port_busy "$GRPC_PORT"; then
      echo "Ports ${HTTPS_PORT}/${GRPC_PORT} are in use (often a kind port-forward)."
      echo "Stop it with: pkill -f 'port-forward.*node-service'  (or pick other ports)"
      echo "Example: HTTPS_PORT=18443 GRPC_PORT=18446 $0 server"
      exit 1
    fi
    cd "$SERVICE_DIR"
    if [[ ! -d node_modules ]]; then
      echo "==> npm install"
      npm install --omit=dev
    fi
    echo "==> Starting server (TLS_DIR=$TLS_DIR)"
    echo "    HTTPS: https://127.0.0.1:${HTTPS_PORT}/phase5b2"
    echo "    gRPC:  phase5c2.Greeter/SayHello on 127.0.0.1:${GRPC_PORT}"
    exec node server.js
    ;;
  test)
    cd "$SERVICE_DIR"
    if [[ ! -d node_modules ]]; then
      npm install --omit=dev
    fi
    echo "==> Node client (HTTPS + gRPC)"
    node client.js 2

    echo
    echo "==> curl HTTPS"
    curl --cacert "$CACERT" -sS "https://127.0.0.1:${HTTPS_PORT}/phase5b2"
    echo

    echo "==> grpcurl gRPC"
    grpcurl -cacert "$CACERT" \
      -import-path "$SERVICE_DIR/proto" \
      -proto greeter.proto \
      -d '{"name":"from-mac"}' \
      "127.0.0.1:${GRPC_PORT}" phase5c2.Greeter/SayHello
    echo
    ;;
  *)
    echo "Usage: $0 server|test"
    echo
    echo "  server  — run HTTPS + gRPC server locally"
    echo "  test    — curl + grpcurl + node client against localhost"
    exit 1
    ;;
esac
