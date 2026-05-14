# Phase 3 — Multi-Layer Dedup (deferred design)

This is the design for Phase 3 task #6 (multi-layer dedup), which is
**not implemented today** because we ship only one capture layer
(`crypto/tls`). When we add `net/http`-layer probes alongside, this
document is the design we'll execute.

## Why dedup is needed when we add layer 2

The Phase 3 brief calls for probes at three layers:

| Layer | Symbol | What it sees | Why we'd want it |
|---|---|---|---|
| `net/http` | `(*Request).Write`, `(*Response).Write` | Application-shaped HTTP messages BEFORE serialisation. Method/path/body in their Go types. | Middleware transformations not visible at `crypto/tls`. Easier schema inference. |
| `crypto/tls` | `(*Conn).Write`, `(*Conn).Read` | Plaintext HTTP wire bytes BEFORE encryption. | What's shipping today. Most general. |
| `net.netFD` | `(*netFD).Write`, `(*netFD).Read` | Post-TLS, post-fragmentation byte stream. | Coverage for non-TLS HTTP fallback. Not required for HTTPS. |

If we attach BOTH `net/http` and `crypto/tls` to the same goroutine,
every HTTP request fires the BPF programs twice — once at each layer.
We'd see double the events for the same logical request, and the
backend would see two witnesses for the same call.

## Goroutine-keyed dedup

The natural correlation key is the **goroutine pointer** (the `g`
struct address in the Go runtime). Every goroutine that does an HTTP
request transitions through both layers; at each layer the same
goroutine is on top of the stack.

We already read the goroutine pointer in `gotls.bpf.c::goroutine_ptr`
(used for the `(*Conn).Read` RET-probing path). The same helper would
extract it for the `net/http`-layer probes.

## Proposed scheme

1. **Per-layer event tagging.** Each BPF program tags its events with
   a `layer` byte: `LAYER_NETHTTP = 1`, `LAYER_TLS = 2`, `LAYER_NETFD = 3`.

2. **Userspace dedup map**, keyed by `(pid, goroutine, txid)` where
   `txid` is a counter that increments per request observed at the
   highest layer that's available for that goroutine.

3. **Layer priority.** Per-goroutine choice rule:
   - If we've seen a `net/http` event for this goroutine: use it; drop
     subsequent `crypto/tls` and `net.netFD` events for the same txid.
   - Else if we've seen a `crypto/tls` event: use it; drop subsequent
     `net.netFD` events.
   - Else: use `net.netFD`.

4. **Eviction.** Per `(pid, goroutine)` we hold dedup state for
   max(2 × request_p99_latency, 1s), evicted by LRU under a memory cap.
   A goroutine that never returns to its idle pool (i.e., a long-lived
   stream like server-push) needs explicit eviction on stream close;
   that's tied to the `(*Response).Body.Close` probe we'd add at the
   same time as the `net/http` layer.

5. **Failure mode if dedup state is lost.** If we evict before all
   layers have fired, we emit the lower layer's event instead of the
   higher. Result: customers see byte-layer view of that one request
   instead of HTTP-layer. Acceptable degradation.

## What's already in place

- `goroutine_ptr(ctx)` helper in `ebpf/programs/gotls.bpf.c` reads the
  per-arch goroutine register (`r14` amd64 / `x28` arm64).
- Per-flow state in `ebpf/events/adapter.go::flowState` is keyed by
  `(pid, ssl_ctx, fd)` today; extending to also key by `goroutine` is
  a one-line change.
- The dedup map itself is a simple Go map (no kernel work needed); it
  lives entirely in `Adapter`.

## What's NOT in place

- The `net/http` BPF programs themselves. We'd need uprobes on:
  - `net/http.(*Request).Write(w io.Writer) error`
  - `net/http.(*Response).Write(w io.Writer) error`
  These functions take an `io.Writer` argument so we'd need to read
  the buffer indirectly (the implementation calls `io.Copy(w, body)`
  from the request body). Less convenient than `crypto/tls.Write`'s
  direct (buf, len) signature.
- ELF symbol resolution for `net/http` symbols. The same goexec
  pipeline that handles `crypto/tls.(*Conn).Write` handles these (the
  pclntab fallback covers stripped binaries identically).
- Per-Go-version testing of `net/http` symbol stability. The internal
  layout of `net/http.(*Request)` changed between Go 1.21 and 1.23
  (the `pat` field for ServeMux pattern matching) but the `Write`
  method signature has not.

## Estimated effort to ship layer 2

| Task | Effort |
|---|---|
| `net/http` BPF programs (Request.Write + Response.Write) | 2 days |
| Goroutine-keyed dedup map in `Adapter` | 1 day |
| Multi-Go-version test for `net/http` symbol stability | 0.5 day |
| Integration testing across the Phase 3 matrix | 0.5 day |

Total: ~4 days. **Not blocking any customer demo today.** Defer until
we have a concrete case where layer-1 (`crypto/tls`) is insufficient
(e.g. a customer reports that middleware-transformed bodies hide
fields they care about).

## Why we're documenting this rather than building it

1. **No customer is asking for it today.** Layer 1 (`crypto/tls`)
   captures every HTTP request before encryption, including bodies.
   Middleware that mutates bodies BEFORE `crypto/tls.Write` is rare in
   practice (the common pattern is request-validation middleware that
   runs on the server, not on outbound writes).

2. **Adding probes adds attach surface area.** Every additional uprobe
   is per-PID overhead and one more thing that can fail. The single-
   layer design has been hardened across kind e2e + multi-Go-version
   matrix; adding another layer is a regression risk.

3. **The dedup design is non-trivial.** Goroutine reuse (Go's `sync.Pool`
   recycles goroutine pointers; same `g` can serve many requests) and
   long-lived streams (server-push, websocket upgrades held by the
   same goroutine for hours) need explicit lifecycle handling. Better
   to design once with a real customer case than to design twice.

This document exists so when the requirement arises, the next session
has the design ready to execute.
