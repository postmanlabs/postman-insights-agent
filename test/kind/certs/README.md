# kind test-apps TLS fixtures (shared by java-service + node-service + dotnet)

Self-signed certs for Kind e2e tests. Generated locally, mounted into pods
via ConfigMap `test-apps-tls` so **your Mac uses the same trust PEM as the pods**.

## Generation (customer-style)

`gen-java-service-certs.sh` uses the same OpenSSL commands as the customer
container entrypoint in [`docs/nocheckin/glic.txt`](../../docs/nocheckin/glic.txt):

- RSA 2048, 365-day self-signed cert
- PKCS12 export with **empty password** (`-passout pass:`)
- **Kind adds** `-addext subjectAltName=DNS:localhost,IP:127.0.0.1` (required for grpcurl; not in customer `glic.txt`)
- Kind renames outputs: `cert.crt` → `grpc-cert.pem`, `cert.key` → `grpc-key.pem`,
  `cert.pfx` → `hello-https-keystore.p12`

```bash
./test/kind/certs/gen-java-service-certs.sh --force
./test/kind/deploy-java-service.sh   # refreshes ConfigMap + java pod
```

Set the customer `-subj` when you have it:

```bash
OPENSSL_SUBJ='/CN=your.customer.host' ./test/kind/certs/gen-java-service-certs.sh --force
```

After regenerating certs, redeploy workloads so pods pick up the new ConfigMap
(`deploy-e2e-demo.sh --skip-build` or per-service deploy scripts).

## Mac clients (with `kubectl port-forward`)

Use **`localhost`** in URLs when the cert has `CN=localhost` (customer-style
certs typically have no IP SAN):

```bash
CACERT=test/kind/certs/hello-https-trust.pem
curl --cacert "$CACERT" https://localhost:8443/phase5b2
grpcurl -cacert "$CACERT" -d '{"name":"mac"}' localhost:8446 phase5c2.Greeter/SayHello
```

Files are gitignored (except this README and the gen script).
