#!/usr/bin/env bash
# Build non-eBPF agent images (amd64 / arm64) and publish a multi-arch manifest
# to your personal GHCR package.
#
# Steps (run separately or all at once):
#   ./build-scripts/publish-to-ghcr.sh build-amd64
#   ./build-scripts/publish-to-ghcr.sh build-arm64
#   ./build-scripts/publish-to-ghcr.sh publish
#   ./build-scripts/publish-to-ghcr.sh all          # build both + publish
#
# Env overrides:
#   GHCR_USER     GitHub username (default: `gh api user -q .login`)
#   TAG           Image tag       (default: current git short SHA)
#   GITHUB_TOKEN  PAT with write:packages (default: `gh auth token`)
#
# Local image names (before publish):
#   postman-insights-agent:local-amd64
#   postman-insights-agent:local-arm64
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

GHCR_USER="${GHCR_USER:-$(gh api user -q .login)}"
TAG="${TAG:-$(git rev-parse --short HEAD)}"
TOKEN="${GITHUB_TOKEN:-$(gh auth token)}"

LOCAL_AMD64="postman-insights-agent:local-amd64"
LOCAL_ARM64="postman-insights-agent:local-arm64"
REMOTE_TAG="ghcr.io/${GHCR_USER}/postman-insights-agent:${TAG}"
REMOTE_LATEST="ghcr.io/${GHCR_USER}/postman-insights-agent:latest"
REMOTE_AMD64="ghcr.io/${GHCR_USER}/postman-insights-agent:${TAG}-amd64"
REMOTE_ARM64="ghcr.io/${GHCR_USER}/postman-insights-agent:${TAG}-arm64"

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \?//'
  exit 1
}

# Same recipe as build-scripts/Dockerfile / `make docker-build`: alpine +
# static -tags osusergo,netgo (no insights_bpf). Repo-root context so COPY works.
build_arch() {
  local platform="$1"
  local tag="$2"

  echo "==> Building non-eBPF image ${tag} (${platform})"
  docker build \
    --platform "${platform}" \
    --provenance false \
    -t "${tag}" \
    -f - \
    . <<'EOF'
FROM golang:1.25-alpine AS build
RUN apk add --no-cache libpcap-dev gcc musl-dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -tags osusergo,netgo -ldflags "-linkmode external -extldflags '-static'" \
      -o /out/postman-insights-agent .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=build /out/postman-insights-agent /postman-insights-agent
ENTRYPOINT ["/postman-insights-agent"]
EOF

  echo "==> Smoke check (${platform})"
  docker run --rm --platform "${platform}" "${tag}" --help >/dev/null
  echo "    ok: ${tag}"
}

cmd_build_amd64() {
  build_arch linux/amd64 "${LOCAL_AMD64}"
}

cmd_build_arm64() {
  build_arch linux/arm64 "${LOCAL_ARM64}"
}

cmd_publish() {
  if [ -z "${GHCR_USER}" ] || [ -z "${TOKEN}" ]; then
    echo "ERROR: need GHCR_USER and a GitHub token (gh auth login -s write:packages, or set GITHUB_TOKEN)" >&2
    exit 1
  fi

  if ! docker image inspect "${LOCAL_AMD64}" >/dev/null 2>&1; then
    echo "ERROR: missing ${LOCAL_AMD64}. Run: $0 build-amd64" >&2
    exit 1
  fi
  if ! docker image inspect "${LOCAL_ARM64}" >/dev/null 2>&1; then
    echo "ERROR: missing ${LOCAL_ARM64}. Run: $0 build-arm64" >&2
    exit 1
  fi

  echo "==> Logging in to ghcr.io as ${GHCR_USER}"
  echo "${TOKEN}" | docker login ghcr.io -u "${GHCR_USER}" --password-stdin

  echo "==> Pushing arch-specific tags"
  docker tag "${LOCAL_AMD64}" "${REMOTE_AMD64}"
  docker tag "${LOCAL_ARM64}" "${REMOTE_ARM64}"
  docker push "${REMOTE_AMD64}"
  docker push "${REMOTE_ARM64}"

  echo "==> Creating multi-arch manifest ${REMOTE_TAG}"
  # Replace any prior manifest for this tag so re-runs are idempotent.
  docker manifest rm "${REMOTE_TAG}" >/dev/null 2>&1 || true
  docker manifest create "${REMOTE_TAG}" \
    --amend "${REMOTE_AMD64}" \
    --amend "${REMOTE_ARM64}"
  docker manifest push "${REMOTE_TAG}"

  echo "==> Also tagging ${REMOTE_LATEST}"
  docker manifest rm "${REMOTE_LATEST}" >/dev/null 2>&1 || true
  docker manifest create "${REMOTE_LATEST}" \
    --amend "${REMOTE_AMD64}" \
    --amend "${REMOTE_ARM64}"
  docker manifest push "${REMOTE_LATEST}"

  echo
  echo "Done (multi-arch, non-eBPF)."
  echo "  ${REMOTE_TAG}"
  echo "  ${REMOTE_LATEST}"
  echo "  ${REMOTE_AMD64}"
  echo "  ${REMOTE_ARM64}"
  echo
  echo "Make the package public:"
  echo "  https://github.com/users/${GHCR_USER}/packages/container/postman-insights-agent/settings"
  echo
  echo "Beta DaemonSet pin (postman-insights-agent-beta.yml):"
  echo "  image:"
  echo "    repository: ghcr.io/${GHCR_USER}/postman-insights-agent"
  echo "    tag: ${TAG}"
}

cmd_all() {
  cmd_build_amd64
  cmd_build_arm64
  cmd_publish
}

STEP="${1:-}"
case "${STEP}" in
  build-amd64) cmd_build_amd64 ;;
  build-arm64) cmd_build_arm64 ;;
  publish)     cmd_publish ;;
  all)         cmd_all ;;
  *)           usage ;;
esac
