# Redaction Defaults

**Audience:** customer compliance officers and security reviewers.

This document is the authoritative list of what the Postman Insights
Agent redacts from captured HTTPS traffic by default, what regex
patterns it matches against, and how customers can add their own rules.

The configuration file lives at
[`data_masks/redaction_config.yaml`](../data_masks/redaction_config.yaml)
and is baked into every agent binary. The agent additionally polls the
Postman backend for customer-supplied dynamic rules (see "Customer
rules" below).

---

## Sensitive header / field names (~40 default)

Any HTTP header or JSON/form body field whose name (case-insensitive)
matches any of these triggers redaction:

### Authentication / authorization
- `authorization` — RFC 7235 standard `Authorization` header
- `proxy-authorization` — RFC 7235 proxy auth
- `proxy-authenticate` — server-issued proxy challenges
- `www-authenticate` — server-issued challenges (may contain realm /
  nonce material)
- `grpc-authorization` — gRPC alternate auth header
- `x-forwarded-authorization` — proxy-forwarded auth
- `x-forwarded-client-cert` — X.509 client cert forwarded by ingress
  proxies (often contains user identity / PII)

### Generic tokens
- `accessToken`, `access_token`, `x-access-token`
- `auth`, `auth-key`, `authKey`
- `token`, `tokenSecret`, `sessionToken`
- `clientSecret`, `clientToken`
- `consumerSecret`
- `password`
- `x-auth-token`
- `x-csrf-token`
- `x-internal-token`

### API keys
- `api-key`, `api_key`, `x-api-key`
- `secretKey`, `primarySecret`, `secondarySecret`
- `x-api-secret`, `x-shared-secret`, `x-support-secret`
- `x-portkey-api-key`, `x-portkey-virtual-key`
- `encryption_key`, `sso_jwt_key`

### Cookies
- `cookie` — RFC 6265 request cookies
- `set-cookie` — RFC 6265 response cookies

### Cloud-specific
- `x-amz-security-token` — AWS STS
- `x-amz-content-sha256` — AWS request signing (paired with secret)

### Postman-specific
- `postman_sid`

Names are matched case-insensitively. `Authorization`, `authorization`,
and `AUTHORIZATION` all trigger.

For headers, the entire value is replaced. For JSON/form bodies, the
field's value is replaced; the structure (key existence, nesting) is
preserved.

## Sensitive value regexes (~150 default)

Even when a field name is *not* in the list above, the agent scans
primitive string values against a curated set of regex patterns. These
catch known secret formats regardless of where they appear (in URLs,
in headers, embedded in JSON, etc.).

Coverage includes:

- **API keys with known prefixes** — Stripe (`sk_live_…`), Slack
  (`xoxb-…`, `xapp-…`), GitHub PATs (`ghp_…`, `gho_…`), npm tokens
  (`npm_…`), Atlassian tokens, Heroku, Twilio (`SK…`), Postman PMAKs.
- **JWTs** — base64url tokens starting with `eyJhbGciOi…`.
- **Cloud credentials** — AWS access keys (`AKIA…`), Azure SAS tokens,
  GCP service account material.
- **Generic high-entropy patterns** — 40+ char hex / base64 sequences
  that look like API tokens.
- **URL-embedded credentials** — `https://user:pass@host`,
  `amqp://creds@host`.
- **Webhook URLs** — Discord webhooks, Zoom join URLs, Zapier hooks,
  Slack webhook tokens.
- **Private keys** — PEM blocks (`-----BEGIN EC PRIVATE KEY-----` …).

Full list: `sensitive_value_regexes:` in
[`data_masks/redaction_config.yaml`](../data_masks/redaction_config.yaml).

## Replacement values

Configurable via the `--redaction-style` flag:

| Flag | Replacement | Use case |
|---|---|---|
| `--redaction-style=redact` (default) | `*REDACTED*` | Safest. Customers see "this field had something sensitive" with no further information. |
| `--redaction-style=hash` | `REDACTED:<16 hex chars>` (sha256 truncated to 8 bytes) | Enables correlation: two requests carrying the same user-id will redact to the same token, so cardinality estimation and "same user across endpoints" analysis are possible without seeing the raw value. |

**Hash mode collision probability:** 8 bytes = 64 bits. By the birthday
paradox, two RANDOM values collide with probability ~50% at ~2³² (~4.3
billion) pairs. For typical workloads this is acceptable but not
suitable for cryptographic uniqueness. The 16-byte variant
(`REDACTED:<32 hex chars>`) is reserved for a future flag if customers
request it.

## Per-mode behaviour

| Mode | Header redaction | Body redaction | Body drop | Header allowlist | Upload |
|---|---|---|---|---|---|
| `--privacy-mode=standard` (default) | ✓ sensitive-key + regex | ✓ sensitive-key + regex | — | — | ✓ |
| `--privacy-mode=strict` | ✓ + drop non-allowlisted | ✓ | ✓ | content-type, content-length, user-agent | ✓ |
| `--privacy-mode=dry-run` | ✓ | ✓ | — | — | ✗ (local JSON report only) |

In `strict` mode, the response/request **bodies** are dropped entirely
(replaced with zero values of the inferred type). Endpoint shape,
method, path, status code, latency, and the three allowlisted headers
remain. This satisfies "we can never see customer body bytes leave the
host" while preserving observability.

## What's NOT redacted by default

The following are preserved on the wire so the Postman Insights product
can do its work:

- HTTP method (GET / POST / PUT / DELETE …).
- URL path **structure** — but path segments that match a sensitive
  regex are redacted (e.g. `/users/sk_live_abc123` → `/users/*REDACTED*`).
- Query parameter **names** (values redacted if the name matches the
  sensitive list).
- HTTP status code.
- Response time / latency.
- `Content-Type` / `Content-Length` / `User-Agent` headers.
- `traceparent` / `tracestate` (W3C Trace Context — these are
  deliberately preserved for distributed tracing correlation; they
  contain no PII by design).
- Request / response **size**.

## Customer-specific rules

Customers can supply their own redaction rules via the Postman web UI
(per-service configuration). These are fetched dynamically by the
agent every 60 seconds and merged into the active redactor.

Supported rule types:

1. **Field-name list** — additional case-insensitive header / body
   field names to redact.
2. **Field-name regex** — match field names against a regex.
3. **Value regex** — match primitive string values against a regex.

Example:

```yaml
# Set via the Postman web UI, fetched by the agent at runtime.
fields_to_redact:
  field_names:
    - x-customer-internal-id
    - x-tenant-id
  field_name_regexes:
    - "^x-acme-.*"
  value_regexes:
    - "ACME_LIVE_[A-Za-z0-9]{32}"
```

## Verifying redaction is working

### Option 1: dry-run mode

```bash
sudo ./postman-insights-agent apidump \
  --enable-https-capture \
  --privacy-mode=dry-run \
  --duration 1h
```

The agent writes JSON reports to `/var/log/postman-insights/`. Each
report contains:

- per-rule hit counts (e.g. `header.authorization: 4823`),
- 5 random redacted samples for human audit.

This is the recommended customer-onboarding workflow: run for 1 hour
in dry-run mode, audit the JSON, then flip to `--privacy-mode=standard`
once satisfied.

### Option 2: redaction-coverage telemetry

When `--privacy-mode=standard` or `strict` is active, the same per-rule
counters are emitted to the Postman backend hourly and surfaced in the
per-service redaction dashboard.

A zero count on `header.authorization` over a busy hour is a smoke
signal that something is wrong — either with the redactor or with the
expected traffic shape. The customer's security team should treat this
as an alert.

## Compliance mappings

| Framework | Requirement | How the agent addresses it |
|---|---|---|
| **PCI DSS v4.0** | 3.2.1: do not store full PAN; 3.5: protect data in transit. | Card-number regexes (Stripe `sk_live_*`, generic 13–19 digit) catch PANs. Redaction happens in agent memory before any network egress. |
| **HIPAA Safeguard 164.312(e)(1)** | Transmission security — guard against unauthorized access during electronic transmission. | All upload traffic is TLS 1.2+ with certificate pinning. `--privacy-mode=strict` drops bodies entirely. |
| **GDPR Art. 32** | Pseudonymisation as an appropriate technical measure. | `--redaction-style=hash` provides deterministic pseudonymisation. |
| **SOC 2 CC6.7** | Restricted information transmission. | Single outbound destination (`api.postman.com:443`); see `docs/security-permissions.md`. |

The agent does NOT make formal certification claims; these mappings
are provided so the customer's compliance team can map agent behaviour
to their specific control matrix.

## Related documents

- [`docs/https-data-flow.md`](https-data-flow.md) — what data exists
  at each stage of the capture path.
- [`docs/security-permissions.md`](security-permissions.md) — exact
  Linux capabilities, syscalls hooked, RBAC.
- [`docs/https-capture-design.md`](https-capture-design.md) §7 — full
  privacy / redaction design.
