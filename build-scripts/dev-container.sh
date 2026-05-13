#!/usr/bin/env bash
# Helper for the HTTPS-capture-via-eBPF dev loop.
#
# Usage:
#   build-scripts/dev-container.sh build   # build the dev image (one-time / on Dockerfile change)
#   build-scripts/dev-container.sh up      # start (or restart) the persistent dev container
#   build-scripts/dev-container.sh shell   # exec an interactive shell into it
#   build-scripts/dev-container.sh run ... # exec a single command inside it
#   build-scripts/dev-container.sh down    # stop + remove it
#
# The container is privileged, has --pid=host, and mounts:
#   - the repo at /workspace
#   - /sys/kernel/btf (BTF for CO-RE)
#   - /sys/kernel/debug (tracefs, trace_pipe)
#   - /sys/fs/bpf (bpffs)
#   - /proc as /host/proc (read-only; for libssl discovery on the host)
#
# Designed for macOS + Docker Desktop (the LinuxKit VM provides the kernel)
# but works on a real Linux host too.

set -euo pipefail

IMAGE_NAME="postman-insights-agent-bpf-dev"
CONTAINER_NAME="pia-bpf-dev"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

cmd="${1:-shell}"
shift || true

case "$cmd" in
  build)
    docker build -f "$REPO_ROOT/build-scripts/Dockerfile.dev" -t "$IMAGE_NAME" "$REPO_ROOT"
    ;;

  up)
    if docker inspect -f '{{.State.Running}}' "$CONTAINER_NAME" >/dev/null 2>&1; then
      echo "$CONTAINER_NAME already running"
      exit 0
    fi
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    docker run -d \
      --name "$CONTAINER_NAME" \
      --privileged \
      --pid=host \
      --network=host \
      -v "$REPO_ROOT":/workspace \
      -v /sys/kernel/btf:/sys/kernel/btf:ro \
      -v /sys/kernel/debug:/sys/kernel/debug \
      -v /sys/fs/bpf:/sys/fs/bpf \
      -v /proc:/host/proc:ro \
      -w /workspace \
      "$IMAGE_NAME" \
      sleep infinity
    echo "started $CONTAINER_NAME"
    ;;

  shell)
    "$0" up
    exec docker exec -it "$CONTAINER_NAME" bash
    ;;

  run)
    "$0" up >/dev/null
    exec docker exec "$CONTAINER_NAME" bash -c "$*"
    ;;

  down)
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    ;;

  *)
    echo "unknown command: $cmd" >&2
    exit 1
    ;;
esac
