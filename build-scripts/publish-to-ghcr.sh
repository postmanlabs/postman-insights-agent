#!/usr/bin/env bash
# Build a non-eBPF agent image (works on Docker Desktop / Apple Silicon) and
# push it to your personal GHCR package.
#
# Mirrors `make docker-build` (build-scripts/Dockerfile): statically linked
# linux binary with -tags osusergo,netgo — no insights_bpf / HTTPS eBPF.
#
# Usage:
#   ./build-scripts/publish-to-ghcr.sh
#
# Env overrides:
#   GHCR_USER     GitHub username (default: `gh api user -q .login`)
#   TAG           Image tag       (default: current git short SHA)
#   PLATFORM      docker platform (default: linux/amd64)
#   GITHUB_TOKEN  PAT with write:packages (default: `gh auth token`)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

GHCR_USER="${GHCR_USER:-$(gh api user -q .login)}"
TAG="${TAG:-$(git rev-parse --short HEAD)}"
PLATFORM="${PLATFORM:-linux/amd64}"
TOKEN="${GITHUB_TOKEN:-$(gh auth token)}"

IMAGE="ghcr.io/${GHCR_USER}/postman-insights-agent:${TAG}"
LATEST="ghcr.io/${GHCR_USER}/postman-insights-agent:latest"

if [ -z "${GHCR_USER}" ] || [ -z "${TOKEN}" ]; then
  echo "ERROR: need GHCR_USER and a GitHub token (gh auth login, or set GITHUB_TOKEN)" >&2
  exit 1
fi

# Same recipe as build-scripts/Dockerfile (alpine + static link), but with a
# repo-root build context so COPY paths work, and a final runnable stage for
# DaemonSet (make docker-build only exports the binary to bin/).
echo "==> Building non-eBPF image ${IMAGE} (${PLATFORM})"
docker build \
  --platform "${PLATFORM}" \
  --provenance false \
  -t "${IMAGE}" \
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

FROM scratch
COPY --from=build /out/postman-insights-agent /postman-insights-agent
ENTRYPOINT ["/postman-insights-agent"]
EOF

echo "==> Smoke check: binary runs"
docker run --rm --platform "${PLATFORM}" "${IMAGE}" --help >/dev/null
echo "    ok"

echo "==> Logging in to ghcr.io as ${GHCR_USER}"
echo "${TOKEN}" | docker login ghcr.io -u "${GHCR_USER}" --password-stdin

echo "==> Pushing ${IMAGE}"
docker push "${IMAGE}"

docker tag "${IMAGE}" "${LATEST}"
docker push "${LATEST}"

echo
echo "Done (non-eBPF image)."
echo "  ${IMAGE}"
echo "  ${LATEST}"
echo
echo "Make the package public:"
echo "  https://github.com/users/${GHCR_USER}/packages/container/postman-insights-agent/settings"
echo
echo "Beta DaemonSet pin (postman-insights-agent-beta.yml):"
echo "  image:"
echo "    repository: ghcr.io/${GHCR_USER}/postman-insights-agent"
echo "    tag: ${TAG}"
