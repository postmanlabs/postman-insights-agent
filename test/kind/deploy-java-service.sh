#!/usr/bin/env bash
# Deploy java-service to kind with stable TLS (Mac + pod share trust PEM).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CERT_DIR="$REPO_ROOT/test/kind/certs"
MANIFEST="$REPO_ROOT/test/kind/java-service-workload.yaml"
NS=test-apps
CM=test-apps-tls

"$CERT_DIR/gen-java-service-certs.sh"

kubectl config use-context kind-pia-https-test 2>/dev/null || true

kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -

kubectl create configmap "$CM" -n "$NS" \
  --from-file="$CERT_DIR/grpc-cert.pem" \
  --from-file="$CERT_DIR/grpc-key.pem" \
  --from-file="$CERT_DIR/hello-https-keystore.p12" \
  --from-file="$CERT_DIR/hello-https-trust.pem" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl delete pod -n "$NS" java-https --ignore-not-found
kubectl delete pod -n "$NS" java-service --ignore-not-found

kubectl apply -f "$MANIFEST"

kubectl wait -n "$NS" --for=condition=Ready pod/java-service --timeout=120s

echo
echo "Pod ready. Trust PEM on Mac (same as in pod):"
echo "  $CERT_DIR/hello-https-trust.pem"
echo
echo "Terminal 1:"
echo "  kubectl port-forward -n $NS pod/java-service 8443:8443 8446:8446"
echo
echo "Terminal 2:"
echo "  curl --cacert $CERT_DIR/hello-https-trust.pem https://127.0.0.1:8443/phase5b2"
echo "  grpcurl -cacert $CERT_DIR/hello-https-trust.pem \\"
echo "    -import-path $REPO_ROOT/java-agent/testdata/grpc-java/src/main/proto -proto greeter.proto \\"
echo "    -d '{\"name\":\"mac\"}' localhost:8446 phase5c2.Greeter/SayHello"
echo
echo "Capture:"
echo "  kubectl logs -n postman-insights deploy/javatls-capture --tail=20 -f"
