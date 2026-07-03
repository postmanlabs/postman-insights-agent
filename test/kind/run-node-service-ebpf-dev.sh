#!/usr/bin/env bash
# Part 1.5 — Node HTTPS + gRPC with eBPF capture in the Linux dev container.
#
# Run from your Mac (repo root). Requires Docker Desktop + pia-bpf-dev.
#
# Debian apt node (dynamic libssl.so.3 — quick smoke test):
#   ./test/kind/run-node-service-ebpf-dev.sh setup
#   ./test/kind/run-node-service-ebpf-dev.sh server
#   ./test/kind/run-node-service-ebpf-dev.sh capture
#   ./test/kind/run-node-service-ebpf-dev.sh test
#
# Official Node 20 (static BoringSSL — same TLS stack as kind node:20-bookworm-slim):
#   ./test/kind/run-node-service-ebpf-dev.sh setup-node20
#   NODE20=1 ./test/kind/run-node-service-ebpf-dev.sh server
#   NODE20=1 ./test/kind/run-node-service-ebpf-dev.sh capture
#   NODE20=1 ./test/kind/run-node-service-ebpf-dev.sh test
#
# One-shot Node 20 capture smoke test:
#   ./test/kind/run-node-service-ebpf-dev.sh smoke-node20
#
# Part 2 (kind pod): ./test/kind/deploy-node-service.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEV="$REPO_ROOT/build-scripts/dev-container.sh"
SERVICE_DIR="$REPO_ROOT/test/kind/node-service"
CERT_DIR="$REPO_ROOT/test/kind/certs"
NODE20_DIR=/opt/node20

# Use different ports for Node 20 mode to avoid clashing with apt-node server.
if [[ "${NODE20:-}" == "1" ]]; then
  HTTPS_PORT="${HTTPS_PORT:-19443}"
  GRPC_PORT="${GRPC_PORT:-19446}"
else
  HTTPS_PORT="${HTTPS_PORT:-18443}"
  GRPC_PORT="${GRPC_PORT:-18446}"
fi

node_bin() {
  if [[ "${NODE20:-}" == "1" ]]; then
    echo "$NODE20_DIR/bin/node"
  else
    echo "node"
  fi
}

install_node20_script='
ARCH=$(uname -m)
case "$ARCH" in aarch64) NODE_ARCH=arm64;; x86_64) NODE_ARCH=x64;; *) echo "unsupported arch: $ARCH"; exit 1;; esac
NODE_VER=v20.20.2
NODE_DIR=/opt/node20
if [ ! -x "$NODE_DIR/bin/node" ]; then
  echo "==> Installing official Node $NODE_VER linux-$NODE_ARCH (static BoringSSL)"
  curl -fsSL "https://nodejs.org/dist/${NODE_VER}/node-${NODE_VER}-linux-${NODE_ARCH}.tar.xz" -o /tmp/node.tar.xz
  rm -rf "$NODE_DIR"
  mkdir -p /opt
  tar -xJf /tmp/node.tar.xz -C /opt
  mv "/opt/node-${NODE_VER}-linux-${NODE_ARCH}" "$NODE_DIR"
  rm /tmp/node.tar.xz
fi
echo "Node 20: $($NODE_DIR/bin/node --version) at $NODE_DIR/bin/node"
'

cmd="${1:-}"

case "$cmd" in
  setup)
    "$CERT_DIR/gen-java-service-certs.sh"
    echo "==> Starting dev container"
    "$DEV" up
    echo "==> Building apidump-ebpf binary"
    "$DEV" run "cd /workspace && bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/programs/vmlinux.h 2>/dev/null || true && make build-ebpf"
    echo "==> npm install (node-service)"
    "$DEV" run "cd /workspace/test/kind/node-service && npm install --omit=dev"
    echo
    echo "Ready (apt node / dynamic libssl). Next:"
    echo "  Terminal 1: $0 server"
    echo "  Terminal 2: $0 capture"
    echo "  Terminal 3: $0 test"
    echo
    echo "For Node 20 / BoringSSL (kind-equivalent): $0 setup-node20"
    ;;

  setup-node20)
    "$0" setup
    echo "==> Installing official Node 20 (static BoringSSL)"
    "$DEV" run "$install_node20_script"
    echo
    echo "Ready (Node 20 / static BoringSSL — same stack as kind node-service)."
    echo "  Terminal 1: NODE20=1 $0 server"
    echo "  Terminal 2: NODE20=1 $0 capture"
    echo "  Terminal 3: NODE20=1 $0 test"
    ;;

  smoke-node20)
    "$CERT_DIR/gen-java-service-certs.sh"
    "$DEV" up
    "$DEV" run "cd /workspace && make build-ebpf 2>/dev/null || true"
    "$DEV" run "cd /workspace/test/kind/node-service && npm install --omit=dev 2>/dev/null || true"
    "$DEV" run "$install_node20_script"
    echo "==> One-shot Node 20 BoringSSL capture test"
    "$DEV" run "
      set -e
      export TLS_DIR=/workspace/test/kind/certs BIND_HOST=127.0.0.1 HTTPS_PORT=19443 GRPC_PORT=19446
      cd /workspace/test/kind/node-service
      fuser -k 19443/tcp 2>/dev/null || true
      sleep 1
      /opt/node20/bin/node server.js >/tmp/node20-srv.log 2>&1 &
      SRV=\$!
      sleep 1
      cd /workspace
      timeout 18 ./bin/postman-insights-agent apidump-ebpf --stats-every=5s >/tmp/cap-node20.log 2>&1 &
      sleep 3
      curl --cacert test/kind/certs/hello-https-trust.pem -sS https://127.0.0.1:19443/phase5b2
      echo
      wait || true
      kill \$SRV 2>/dev/null || true
      echo
      echo '=== expect: attached static=true + url=/phase5b2 ==='
      grep -E 'attached libssl.*\$SRV|phase5b2|ebpf-pid-'\$SRV /tmp/cap-node20.log || grep -E 'attached libssl|phase5b2' /tmp/cap-node20.log
    "
    ;;

  server)
    NB=$(node_bin)
    MODE=$([[ "${NODE20:-}" == "1" ]] && echo "Node 20 static BoringSSL" || echo "apt node dynamic libssl")
    "$DEV" run "
      export TLS_DIR=/workspace/test/kind/certs BIND_HOST=127.0.0.1 HTTPS_PORT=$HTTPS_PORT GRPC_PORT=$GRPC_PORT
      cd /workspace/test/kind/node-service
      echo 'Mode: $MODE'
      echo 'Binary: $NB'
      echo 'HTTPS: https://127.0.0.1:${HTTPS_PORT}/phase5b2'
      echo 'gRPC:  127.0.0.1:${GRPC_PORT} phase5c2.Greeter/SayHello'
      exec $NB server.js
    "
    ;;

  capture)
    echo "REQ/RESP appear in THIS terminal."
    echo ""
    echo "IMPORTANT:"
    echo "  1. Start server FIRST: NODE20=${NODE20:-0} $0 server"
    echo "  2. Wait for: ebpf: attached libssl uprobes pid=... static=true|false"
    echo "  3. Then: NODE20=${NODE20:-0} $0 test"
    echo "  4. Filter kind noise: grep phase5b2"
    echo ""
    "$DEV" run "
      cd /workspace
      exec ./bin/postman-insights-agent apidump-ebpf --stats-every=10s --max-capture-bytes=512 2>&1 \
        | grep --line-buffered -E 'attached libssl|REQ |RESP |stats:'
    "
    ;;

  test)
    NB=$(node_bin)
    "$DEV" run "
      export TLS_DIR=/workspace/test/kind/certs BIND_HOST=127.0.0.1 HTTPS_PORT=$HTTPS_PORT GRPC_PORT=$GRPC_PORT
      CACERT=/workspace/test/kind/certs/hello-https-trust.pem
      cd /workspace/test/kind/node-service

      SERVER_PID=\$(ss -tlnp | grep ':${HTTPS_PORT}' | sed -n 's/.*pid=\\([0-9]*\\).*/\\1/p' | head -1)
      echo \"node-server PID: \${SERVER_PID:-unknown} (expect ebpf-pid-\${SERVER_PID} url=/phase5b2)\"
      echo

      echo '=== curl HTTPS ==='
      curl --cacert \"\$CACERT\" -sS \"https://127.0.0.1:${HTTPS_PORT}/phase5b2\"
      echo

      echo '=== node client.js ==='
      $NB client.js 2
    "
    ;;

  *)
    echo "Usage: $0 setup|setup-node20|smoke-node20|server|capture|test"
    echo
    echo "  setup         — apt node (dynamic libssl) + build-ebpf"
    echo "  setup-node20  — above + official Node 20 (static BoringSSL, kind-equivalent)"
    echo "  smoke-node20  — one-shot Node 20 attach + curl + grep phase5b2"
    echo "  server        — run HTTPS+gRPC server (NODE20=1 for BoringSSL)"
    echo "  capture       — apidump-ebpf (REQ/RESP here)"
    echo "  test          — curl + node client"
    exit 1
    ;;
esac
