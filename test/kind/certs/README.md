# kind test-apps TLS fixtures (shared by java-service + node-service)

Self-signed certs for `java-service` kind tests. Generated locally, mounted
into the pod via ConfigMap so **your Mac uses the same trust PEM as the pod**.

```bash
./test/kind/certs/gen-java-service-certs.sh
./test/kind/deploy-java-service.sh
```

Mac clients (with `kubectl port-forward`):

```bash
CACERT=test/kind/certs/hello-https-trust.pem
curl --cacert "$CACERT" https://127.0.0.1:8443/phase5b2
grpcurl -cacert "$CACERT" -d '{"name":"mac"}' localhost:8446 phase5c2.Greeter/SayHello
```

Files are gitignored (except this README and the gen script).
