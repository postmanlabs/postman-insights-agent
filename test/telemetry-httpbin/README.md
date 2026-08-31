# Telemetry httpbin

A `go-httpbin` deployment used to reproduce the daemonset's "backend
drop-reason attribution" telemetry signals (`witness_pair_expired`,
`http_parse_failed`, `capture_gap_truncated`, `latency_anomaly`) against a
real, well-behaved HTTP target instead of a bespoke fake server.

It's reachable two ways from the same pod:

- **Plain HTTP** (`:80` -> container port `8080`) -- for pcap-only capture
  testing.
- **HTTPS** (`:443` -> container port `8443`, terminated by an `nginx`
  sidecar that reverse-proxies to the httpbin container over
  `127.0.0.1:8080`) -- for eBPF libssl-uprobe capture testing, same pattern
  as `../../../SECRETS/insights-setup/https-service`.

Files:

- `ca.crt` / `ca.key`: local CA used to sign the server certificate.
- `tls.crt` / `tls.key`: server certificate and private key used by the
  `nginx` sidecar.
- `k8s.yaml`: `Namespace`, `ConfigMap` (nginx.conf), `Deployment`
  (`httpbin` + `nginx` containers), and `Service`.
- `00-generate-cert.sh`: generates the local CA and TLS certificate artifacts.
- `01-create-secret.sh`: applies the TLS secret with `kubectl`.

## Deploy

```bash
./00-generate-cert.sh
./01-create-secret.sh telemetry-httpbin
kubectl apply -f k8s.yaml
```

The generator refuses to overwrite existing artifacts. Pass `--force` to
regenerate them.

## `MAX_DURATION`

`go-httpbin`'s `/delay` and `/drip` endpoints are capped at a 10s response
time by default. The `Deployment` overrides this via the `MAX_DURATION` env
var (set to `120s`), which is comfortably past the agent's 60s
`pairCacheExpiration` (`trace/backend_collector.go`) -- long enough for a
`/delay/90` response to actually trigger `witness_pair_expired_request`
instead of resolving before the pair cache would have expired it.

If you raise `MAX_DURATION` further, also raise the `nginx.conf`
`proxy_send_timeout`/`proxy_read_timeout` values in `k8s.yaml` to match --
otherwise the HTTPS path will time out and close the connection at nginx's
default before httpbin ever gets to respond, and you'll see a `504` instead
of the desired hang.

## Drop-reason repro cheat sheet

Port-forward first (or resolve the in-cluster Service DNS name directly from
the daemonset's node):

```bash
kubectl port-forward -n telemetry-httpbin service/telemetry-httpbin 8080:80 8443:443
```

| Signal | Endpoint | Notes |
| --- | --- | --- |
| `witness_pair_expired_request` | `curl http://localhost:8080/delay/90` (or `curl --cacert ca.crt https://localhost:8443/delay/90` for the eBPF path) | Response arrives ~90s after the request -- well past the 60s pair-cache expiry, so the request-only partial witness gets flushed as expired before the response is paired to it. |
| `capture_gap_truncated` (`capture_gap_truncated_flushed`) | `curl http://localhost:8080/drip?duration=10&numbytes=65536` while running `tc netem loss <pct>` on the target pod's egress | Not reproducible from the HTTP layer alone -- httpbin just needs to be mid-stream when packet loss forces the agent's TCP reassembler to time out and skip the gap. |
| `http_parse_failed_*_truncated` / `_malformed` / `_unsupported_encoding` / `_other` | Raw socket (`nc`/Python), not curl | A well-behaved server won't voluntarily send a wrong `Content-Length` or a mislabeled `Content-Encoding` -- see the drop-reason attribution notes in the telemetry matrix doc for the exact raw-request recipes. |
| `latency_anomaly_negative_latency` / `_mismatched_pair_type` | Raw persistent-connection HTTP pipelining against `curl http://localhost:8080/get` | Timing-sensitive; best-effort repro, not guaranteed-deterministic. |

## Test with curl

```bash
# Plain HTTP
curl http://localhost:8080/get

# HTTPS, trusting the locally generated CA
curl --cacert ./ca.crt https://localhost:8443/get
```
