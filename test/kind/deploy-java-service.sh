#!/usr/bin/env bash
# End-to-end check of Java HTTPS capture in kind, through the production
# DaemonSet path (kube run --enable-https-capture, agent-daemonset-prod.yaml).
#
# Deploys three HTTPS services: Spring Boot on Tomcat (the JDK's SSLEngine)
# and plain Netty (its OpenSSL engine), which load the Postman Insights Java
# agent through -javaagent, and the same Spring Boot service started without
# it, into which the Insights agent attaches the Java agent. Sends each HTTPS
# requests, and checks the agent's ebpf-stats lines: Java frames reached the
# kernel programs and were parsed into HTTP messages. Captures also appear in
# Postman Insights under the cluster "pia-kind-test".
#
# Prerequisites: Docker Desktop, kind, kubectl, a Postman Insights API key.
#
# Usage:
#   export POSTMAN_INSIGHTS_API_KEY=your_key_here
#   ./test/kind/deploy-java-service.sh              # build images, deploy, check
#   ./test/kind/deploy-java-service.sh --skip-build # reuse the images in kind
set -euo pipefail

# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"

JAVA_IMAGE=pia-java-service:test
NETTY_IMAGE=pia-netty-service:test
SERVICES="java-service netty-service java-service-attach"
SKIP_BUILD=false
REQUESTS=3 # rounds of 3 requests each
# The Java agent's log prefix, with the jar's old name and the current one.
JAVA_LOG='\[postman-insights(-java)?-agent\]'

for arg in "$@"; do
  case "$arg" in
    --skip-build) SKIP_BUILD=true ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "unknown arg: $arg" >&2; exit 1 ;;
  esac
done

require_api_key
use_cluster

if [[ "$SKIP_BUILD" == "false" ]]; then
  build_agent
  echo "==> Building Java service images ${JAVA_IMAGE} and ${NETTY_IMAGE}"
  docker build -f "$REPO_ROOT/test/kind/Dockerfile.java-service" -t "$JAVA_IMAGE" "$REPO_ROOT"
  docker build -f "$REPO_ROOT/test/kind/Dockerfile.netty-service" -t "$NETTY_IMAGE" "$REPO_ROOT"
  kind load docker-image "$JAVA_IMAGE" "$NETTY_IMAGE" --name "$CLUSTER"
fi

# A fresh JVM every run, so the Insights agent attaches to it anew.
echo "==> Java service deployments"
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -
for svc in $SERVICES; do
  deploy_service "$svc"
done
# shellcheck disable=SC2086 # SERVICES is a list
wait_services $SERVICES
POD_IPS=""
for svc in $SERVICES; do
  POD_IPS="$POD_IPS $(ip_of "$svc")"
done

deploy_agent
sleep 15

# The Java agents stay dormant until the Insights agent discovers their JVMs
# and writes their control files; into java-service-attach it first attaches
# the agent.
echo "==> Waiting for the Java agents to start capturing"
for svc in $SERVICES; do
  # Discovery runs every 2 s, a JVM is attached once it has run for 5 s, and
  # the agent checks its control file every 5 s.
  capturing=false
  for _ in $(seq 1 45); do
    if kubectl logs -n "$NS" "deployment/$svc" | grep -Eq "${JAVA_LOG}"' capturing HTTPS traffic'; then
      capturing=true
      break
    fi
    sleep 1
  done
  kubectl logs -n "$NS" "deployment/$svc" | grep -E "${JAVA_LOG}" || true
  if [[ "$capturing" != true ]]; then
    echo "ERROR: the Java agent in ${svc} did not start capturing" >&2
    exit 1
  fi
done

echo "==> Sending HTTPS requests to${POD_IPS} (port 8443) from namespace ${CLIENT_NS}"
# -f: an HTTP error fails curl, and fails the client and this script.
run_client java-client "
  for ip in ${POD_IPS}; do
    for i in \$(seq 1 ${REQUESTS}); do
      curl -fsSk https://\$ip:8443/hello?name=kind-\$i; echo
      curl -fsSk https://\$ip:8443/orders/42; echo
      curl -fsSk -X POST -H 'Content-Type: application/json' -d '{\"item\":\"book\",\"qty\":2}' https://\$ip:8443/orders; echo
    done
  done"

collect_logs
fail=0
if grep -q 'ebpf: Java HTTPS capture enabled' <<<"$LOGS"; then
  echo "  PASS  Java programs loaded"
else
  echo "  FAIL  no 'Java HTTPS capture enabled' line"
  grep -E 'Java HTTPS capture' <<<"$LOGS" || true
  fail=1
fi
services=$(wc -w <<<"$SERVICES")
per_service=$((REQUESTS * 3 * 2)) # a request and a response per call
java_events=$(max_field java_events)
want=$((services * per_service))
if [[ "${java_events:-0}" -ge "$want" ]]; then
  echo "  PASS  java_events=${java_events}"
else
  echo "  FAIL  java_events=${java_events:-none}, want at least ${want}"
  fail=1
fi
for svc in $SERVICES; do
  pod=$(pod_of "$svc")
  check_at_least "$svc" msgs "$pod" "$per_service"
  # The pod's own Java events: the data frames routed to it.
  check_at_least "$svc" java_events "$pod" "$per_service"
done

# The kernel ties each Java connection to its socket, so every message has
# its IP addresses and ports: no data frame went out without them.
# java_conn_handoffs is not checked: Tomcat unwraps records that another
# worker thread read, which it counts, and the ties stay right.
v=$(max_field java_conn_unbound)
if [[ -n "$v" && "$v" -eq 0 ]]; then
  echo "  PASS  java_conn_unbound=0"
else
  echo "  FAIL  java_conn_unbound=${v:-none}, want 0"
  fail=1
fi
v=$(max_field java_conn_handoffs)
echo "  INFO  java_conn_handoffs=${v:-none} (not checked)"

# Each service's Java agent reports itself through HEARTBEAT frames.
agents=$({ grep -oE 'ebpf: Java agent [^ ]+ in pid [0-9]+ is active' <<<"$LOGS" | grep -oE 'pid [0-9]+' | sort -u | wc -l; } || true)
if [[ "${agents// /}" -ge "$services" ]]; then
  echo "  PASS  ${agents// /} Java agents heard from, capturing"
else
  echo "  FAIL  ${agents// /} Java agents heard from capturing, want ${services}"
  fail=1
fi

finish_checks
echo "==> Java HTTPS capture works end to end; check Postman Insights cluster 'pia-kind-test' for the endpoints"
