#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Same /phase5b2 endpoint, different query strings — validates eBPF captures
# the full request line (path + ?params), not just the route path.
#
# Usage:
#   ./test/kind/deploy-dotnet-service.sh   # if not already running
#   kubectl port-forward -n test-apps deployment/dotnet-service 8443:8443 &
#   ./test/kind/test-dotnet-query.sh
#
# Verify capture (separate terminal):
#   kubectl logs -n postman-insights daemonset/postman-insights-agent --timestamps --since=2m \
#     | grep -E 'REQ .*phase5b2'

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CA="${ROOT}/test/kind/certs/hello-https-trust.pem"
BASE="${BASE_URL:-https://127.0.0.1:8443}"
PATH_EP="/phase5b2"
CURL=(curl -sS --cacert "$CA" -w "\n  -> HTTP %{http_code}\n")

if [[ ! -f "$CA" ]]; then
  echo "missing trust PEM: $CA (run test/kind/certs/gen-java-service-certs.sh)" >&2
  exit 1
fi

echo "=== GET ${PATH_EP}?... → ${BASE} (same endpoint, varying query) ==="
echo

run() {
  local label="$1"
  shift
  echo "--- ${label} ---"
  "${CURL[@]}" "$@"
  echo
}

run "no query (baseline)" \
  "${BASE}${PATH_EP}"

run "single param" \
  "${BASE}${PATH_EP}?q=hello"

run "multiple params" \
  "${BASE}${PATH_EP}?foo=bar&baz=1"

run "percent-encoded spaces and ampersand" \
  "${BASE}${PATH_EP}?name=John%20Doe&filter=a%26b"

run "empty value" \
  "${BASE}${PATH_EP}?key=&other=x"

run "repeated keys" \
  "${BASE}${PATH_EP}?tag=a&tag=b"

run "numeric and boolean-like" \
  "${BASE}${PATH_EP}?page=2&active=true&limit=50"

run "unicode (UTF-8 percent-encoded)" \
  "${BASE}${PATH_EP}?q=caf%C3%A9"

echo "=== Expected in agent logs: url includes ?... on same path ==="
echo "  REQ ... method=GET url=/phase5b2?q=hello"
echo "  REQ ... method=GET url=/phase5b2?foo=bar&baz=1"
echo
echo "Grep:"
echo "  kubectl logs -n postman-insights daemonset/postman-insights-agent --timestamps --since=3m \\"
echo "    | grep -E 'REQ .*phase5b2.*\\?'"
