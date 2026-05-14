# HTTPS Capture — Data Flow

**Audience:** customer security / compliance reviewers.

**Purpose:** answer the question *"what happens to my service's HTTPS
bytes after they're decrypted in the kernel and before they reach
Postman?"* — one step at a time, with explicit answers to *what data
exists*, *who can see it*, and *what encryption applies*.

This document covers the Postman Insights Agent's eBPF-based HTTPS
capture path (enabled by `--enable-https-capture`). It does NOT cover
plaintext pcap capture, which has a separate data-flow (no decryption,
TCP/IP packet inspection only).

---

## End-to-end sequence

```
┌─────────────────────────────────────────────────────────────────────┐
│ Your application process (e.g. nginx, python service, Go service)   │
│                                                                     │
│  SSL_write(ssl_ctx, buf, len)  ──►  TLS encrypt  ──►  socket write  │
│  SSL_read (ssl_ctx, buf, len)  ◄──  TLS decrypt  ◄──  socket read   │
└─────────────────────────────────────────────────────────────────────┘
                       │  (1) uprobe fires
                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Kernel — BPF program (eBPF, in-kernel, verifier-checked, sandboxed) │
│                                                                     │
│  Reads up to N bytes from buf (N defaults to 1024, capped via       │
│  --https-body-size-cap).                                            │
│  Writes (pid, ssl_ctx, fd, dir, bytes[N]) to a ringbuf.             │
│  Does NOT modify, block, or replay the call.                        │
└─────────────────────────────────────────────────────────────────────┘
                       │  (2) ringbuf event
                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Agent process (postman-insights-agent, in userspace, NOT privileged │
│ except CAP_BPF + CAP_PERFMON for eBPF program loading)              │
│                                                                     │
│  Reads ringbuf events.                                              │
│  Resolves (pid, fd) → (local_ip, local_port, remote_ip,             │
│                        remote_port) by reading /proc/<pid>/net/tcp. │
│  Feeds bytes into akinet HTTP/1 parser or HTTP/2 frame decoder.     │
│  Reassembles HEADERS+DATA frames; decompresses HPACK; strips gRPC   │
│  length-prefix framing.                                             │
│  Produces a typed ParsedNetworkTraffic{HTTPRequest/HTTPResponse}.   │
└─────────────────────────────────────────────────────────────────────┘
                       │  (3) parsed message
                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Agent — Redactor (data_masks package)                               │
│                                                                     │
│  Replaces sensitive header values (authorization, cookie, etc.)     │
│  Replaces sensitive body field values (api_key, password, etc.)     │
│  Runs regex pass for known secret formats (Stripe sk_live_*, AWS    │
│  AKIA*, JWTs, etc.).                                                │
│  Applies privacy-mode rules:                                        │
│    - strict: drops body primitives, allows only content-type,       │
│      content-length, user-agent headers.                            │
│    - dry-run: writes redacted samples to local disk, does NOT       │
│      upload.                                                        │
│  Increments per-rule coverage counters.                             │
└─────────────────────────────────────────────────────────────────────┘
                       │  (4) redacted message (if upload enabled)
                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Agent — Witness builder + backend collector                         │
│                                                                     │
│  Witnesses one request/response pair into a protobuf message.       │
│  Batches witnesses (up to ~10 KB or 1s, whichever first).           │
│  Compresses (gzip).                                                 │
│  Encrypts the connection to api.postman.com (TLS 1.2+, certificate  │
│  pinned).                                                           │
└─────────────────────────────────────────────────────────────────────┘
                       │  (5) HTTPS POST
                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Backend (Postman, multi-region)                                     │
│                                                                     │
│  Receives, authenticates, stores encrypted-at-rest in the           │
│  customer's chosen region.                                          │
│  Runs schema/route inference and surfaces in the Postman Insights   │
│  product UI.                                                        │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Per-step detail

### (1) Application — uprobe fires

| | |
|---|---|
| **Data at this point** | Plaintext HTTPS bytes — same as the application's own process memory sees. |
| **Who can see it** | The application process itself. The Linux kernel. Any agent on the host with CAP_BPF + CAP_PERFMON that has attached a uprobe to the same symbol. |
| **Encryption** | None at this point — that's the entire point of the capture. |
| **Modifications** | None. uprobes are read-only by design. The BPF program cannot modify the buffer, block the syscall, or change the program counter. |
| **What we capture** | `SSL_write` / `SSL_read` for libssl-based apps. `crypto/tls.(*Conn).Write` and `(*Conn).Read` for Go apps. |

### (2) Kernel — BPF program

| | |
|---|---|
| **Data at this point** | Up to N bytes (default 1024) of the plaintext payload, plus `(pid, ssl_ctx_pointer, file_descriptor, direction)` metadata. |
| **Who can see it** | The agent's BPF program (in kernel) and userspace via the ringbuf. NOT the application. NOT other users on the host (BPF maps are owned by the agent's user). |
| **Encryption** | None — this is plaintext data, capped, copied to a userspace-mapped ringbuf. |
| **Storage location** | Linux ringbuf in kernel memory, lifetime = agent process. Lost on agent crash. |
| **Body-size cap enforcement** | At THIS layer — never at userspace. A 10 MB JSON body sees its first 1024 bytes copied; the remaining 10,485,752 bytes are never read by the agent. |

### (3) Agent — parsing + IP resolution

| | |
|---|---|
| **Data at this point** | Reassembled HTTP request/response message in agent process memory. Includes 4-tuple (src/dst IP+port) resolved from `/proc/<pid>/net/tcp{,6}`. |
| **Who can see it** | The agent process. Anyone with `ptrace_attach` capability on the agent (typically only root). |
| **Encryption** | None — in agent memory. |
| **Lifetime** | Held until redaction + batch upload, typically < 5 seconds. |
| **Storage location** | Agent process heap. NOT written to disk. NOT logged. |

### (4) Agent — Redactor

| | |
|---|---|
| **Data at this point** | Redacted HTTP message. Sensitive header values → `*REDACTED*` (or `REDACTED:<hash>` if `--redaction-style=hash`). Sensitive body fields → same. |
| **Who can see it** | The agent process. |
| **Encryption** | None — in agent memory. |
| **What's redacted** | Headers in `data_masks/redaction_config.yaml` (40+ default keys, see `docs/redaction-defaults.md`). Body fields matching the same key set. Body string values matching the built-in regex pattern set. Customer-supplied rules from the dynamic config. |
| **What's NOT redacted by default** | Method (GET/POST/...), URL path (e.g. `/api/v2/users/{id}`), query parameter names (values redacted if sensitive), status code, response time, content-length, content-type, response size. |

### (5) Agent — Backend upload

| | |
|---|---|
| **Data at this point** | Compressed protobuf batch of redacted witnesses. |
| **Who can see it** | The agent process before upload. Postman's backend after upload. The TLS connection is end-to-end encrypted. |
| **Encryption** | TLS 1.2+ to `api.postman.com`. Certificate pinning enforced (see `rest/client.go`). |
| **Network egress** | Only `api.postman.com:443`. The agent makes no other outbound network calls. |
| **In dry-run mode (`--privacy-mode=dry-run`)** | This step is SKIPPED. Data stays on the host and is written to `<dry-run-dir>/dry-run-<timestamp>.json` for customer audit. |

### (6) Backend storage

This is documented separately in Postman's product security white-paper.
Postman customers can request regional pinning, KMS-managed encryption
keys, retention policy controls, etc. via their account team.

---

## Data flow under each privacy mode

### `--privacy-mode=standard` (default)

Path (1) → (2) → (3) → (4) → (5) → (6). Redaction in (4) is the default
sensitive-key + regex pipeline.

### `--privacy-mode=strict`

Path same as standard, but in (4) the redactor *additionally*:
- Drops all body primitives (replaced with the type's zero value).
- Removes all headers NOT in the allowlist (`content-type`,
  `content-length`, `user-agent`).
- Method, path, status, response time, latency — preserved.

Use when your compliance posture is "we can never see customer body
bytes leave the host". You still get endpoint shape and error rates.

### `--privacy-mode=dry-run`

Path is (1) → (2) → (3) → (4) → **STOP**. No upload to Postman.

Instead, every 60 seconds the dry-run reporter writes:
`<dry-run-dir>/dry-run-<UTC ISO timestamp>.json`

The JSON contains:
- the time window,
- per-rule redaction hit counts (delta since previous report),
- 5 uniformly-random samples of redacted requests/responses for human
  audit.

Use for the customer's initial trust-building period (typically 24h to
1 week). Once the customer's security team confirms the redacted output
is acceptable, flip the flag to `standard` to enable upload.

---

## What the agent CANNOT do

By design:

- The agent **cannot modify** application traffic. eBPF uprobes are
  read-only.
- The agent **cannot block** application syscalls. uprobes don't have
  the `helper_override_return` capability.
- The agent **cannot decrypt** TLS traffic that doesn't already pass
  through a uprobed function — e.g. it cannot decrypt traffic from a
  process using a TLS library we haven't probed (Java JSSE, statically-
  linked BoringSSL today).
- The agent **cannot send data to anywhere other than Postman**. There
  is no third-party SDK, no telemetry pipeline to a vendor, no cloud
  log sink.
- The agent **cannot read** application memory beyond the buffer passed
  to the probed function. We cannot dump the heap, the stack, or
  environment variables. We see only what the application is *about
  to write* or *just read* on a TLS connection.

---

## Related documents

- [`docs/security-permissions.md`](security-permissions.md) — exact
  Linux capabilities, syscalls hooked, filesystem paths read, RBAC.
- [`docs/redaction-defaults.md`](redaction-defaults.md) — what's
  redacted by default and how to add customer-specific rules.
- [`docs/https-capture-design.md`](https-capture-design.md) — full
  architecture for the eBPF capture path.
