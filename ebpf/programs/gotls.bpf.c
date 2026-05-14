// SPDX-License-Identifier: Apache-2.0
//
// gotls.bpf.c — minimum-viable Phase 3 uprobes for Go crypto/tls.
//
// We attach to:
//   crypto/tls.(*Conn).Write   — entry probe captures plaintext being sent.
//   crypto/tls.(*Conn).Read    — exit probe captures plaintext that was read.
//
// Go register ABI (Go 1.17+):
//
//   amd64: arg0=rax, arg1=rbx, arg2=rcx, arg3=rdi, arg4=rsi, arg5=r8,
//          arg6=r9, arg7=r10, arg8=r11, arg9=r12, ret=rax
//   arm64: arg0=x0, ..., arg7=x7
//
// For Go method receivers, the receiver is `arg0`. So
//   crypto/tls.(*Conn).Write(c *Conn, b []byte)
// has:
//   arg0 = c          (Conn*)
//   arg1 = data       (data pointer)
//   arg2 = len        (len)
//   arg3 = cap        (cap)
//
// Slices in Go are passed as three registers (data, len, cap) per the register
// ABI. So we read arg1 as the byte pointer and arg2 as the length.
//
// IMPORTANT: Uretprobes on Go are unreliable because Go can resize/move
// goroutine stacks during execution, invalidating any saved return addresses.
// For Phase 3 minimum-viable we accept this and only use entry probes (write
// is captured at entry; read is harder and currently skipped — see
// // TODO(phase3) below).

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef BPF_UPROBE
#define BPF_UPROBE(name, args...) BPF_KPROBE(name, ##args)
#endif

char LICENSE[] SEC("license") = "GPL";

// Mirror the libssl event layout so userspace can reuse events.SSLEvent /
// events.Adapter without modification. We borrow the same MAX_EVENT_PAYLOAD
// from event.h.
#include "event.h"

// Map shared with libssl.bpf.c is not portable across program collections,
// so we declare an *independent* ringbuf for gotls events. Userspace
// instantiates one reader per program collection. The downstream adapter is
// the same.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 21);
} gotls_events SEC(".maps");

// Per-CPU counters (mirror libssl's layout for telemetry uniformity).
//   0 = events emitted, 1 = dropped (ringbuf full), 2 = read failures,
//   3 = bytes captured.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} gotls_counters SEC(".maps");

static __always_inline void gotls_counter_inc(__u32 idx, __u64 by) {
    __u64 *v = bpf_map_lookup_elem(&gotls_counters, &idx);
    if (v) *v += by;
}

// Read-only knob configured by userspace at load time.
volatile const __u32 gotls_max_capture_bytes = MAX_EVENT_PAYLOAD;

// ------------------------------------------------------------------
// Argument extraction.
//
// On amd64 register ABI (Go 1.17+), method args are in:
//   ax, bx, cx, di, si, r8, r9, r10, r11, r12
// For arm64 the kernel's struct pt_regs already exposes regs[0..7] which
// map to x0..x7. We provide a small helper.
// ------------------------------------------------------------------

#if defined(__TARGET_ARCH_arm64) || defined(bpf_target_arm64)
#define GO_ARG(ctx, n) PT_REGS_PARM1_CORE(ctx) // placeholder — see below
#endif

// Inline arg readers using the libbpf PT_REGS_* macros. For amd64 the ABI
// uses different registers than the System V C calling convention, so we
// bypass PT_REGS_PARM and read the specific registers directly via the
// pt_regs CO-RE accessors.
//
// We use BPF_CORE_READ_INTO on the synthetic per-arch struct pt_regs___amd64
// (libbpf 1.3+) or just direct field reads (libbpf 1.1).

static __always_inline __u64 go_arg(struct pt_regs *ctx, int n) {
#if defined(bpf_target_x86) || defined(__x86_64__) || defined(__TARGET_ARCH_x86)
    switch (n) {
        case 0: return ctx->ax;
        case 1: return ctx->bx;
        case 2: return ctx->cx;
        case 3: return ctx->di;
        case 4: return ctx->si;
        case 5: return ctx->r8;
        case 6: return ctx->r9;
        case 7: return ctx->r10;
        case 8: return ctx->r11;
        case 9: return ctx->r12;
    }
#elif defined(bpf_target_arm64) || defined(__aarch64__) || defined(__TARGET_ARCH_arm64)
    if (n >= 0 && n < 8) {
        return ctx->regs[n];
    }
#endif
    return 0;
}

// Common emit path: copy up to `len` bytes from user_buf into a ringbuf
// event, populating the same struct ssl_event the libssl uprobes use.
static __always_inline int gotls_emit(__u64 pid_tgid,
                                       __u64 conn_ptr,
                                       const void *user_buf,
                                       __u32 reported_len,
                                       __u8 direction) {
    if (!user_buf || reported_len == 0) return -1;

    struct ssl_event *e = bpf_ringbuf_reserve(&gotls_events, sizeof(*e), 0);
    if (!e) { gotls_counter_inc(1, 1); return -1; }

    __u32 to_copy = reported_len;
    if (to_copy > gotls_max_capture_bytes) to_copy = gotls_max_capture_bytes;
    to_copy &= (MAX_EVENT_PAYLOAD - 1);
    if (to_copy == 0 && reported_len > 0) to_copy = 1;

    e->ts_ns        = bpf_ktime_get_ns();
    e->pid          = pid_tgid >> 32;
    e->tid          = (__u32)pid_tgid;
    e->ssl_ctx      = conn_ptr;      // we reuse this slot for the Go *tls.Conn
    e->len_total    = reported_len;
    e->len_captured = to_copy;
    e->fd           = -1;            // Go fd extraction not yet wired
    e->direction    = direction;
    __builtin_memset(e->_pad, 0, sizeof(e->_pad));

    if (bpf_probe_read_user(e->payload, to_copy, user_buf) != 0) {
        bpf_ringbuf_discard(e, 0);
        gotls_counter_inc(2, 1);
        return -1;
    }

    bpf_ringbuf_submit(e, 0);
    gotls_counter_inc(0, 1);
    gotls_counter_inc(3, to_copy);
    return 0;
}

// crypto/tls.(*Conn).Write(c *Conn, b []byte) (int, error)
//
// Register ABI on entry:
//   arg0 = c                    (*tls.Conn)
//   arg1 = b.data               (byte pointer)
//   arg2 = b.len                (length)
//   arg3 = b.cap                (cap)
//
// We capture the plaintext at entry (before TLS encryption mangles it).
SEC("uprobe/crypto_tls_Conn_Write")
int BPF_UPROBE(uprobe_gotls_write) {
    __u64 id   = bpf_get_current_pid_tgid();
    __u64 conn = go_arg(ctx, 0);
    __u64 ptr  = go_arg(ctx, 1);
    __u64 n    = go_arg(ctx, 2);
    if (n == 0 || ptr == 0) return 0;
    gotls_emit(id, conn, (const void *)ptr, (__u32)n, DIR_EGRESS);
    return 0;
}

// crypto/tls.(*Conn).Read(c *Conn, b []byte) (int, error)
//
// On entry, `b` is the destination buffer — empty at this point (filled by
// the call). We need the bytes *after* the read completes. Two options:
//
//   (a) uretprobe (unreliable on Go due to stack moves).
//   (b) Stash buf pointer in a map keyed by goroutine, then attach a
//       uprobe at each RET instruction in the function body and read
//       n_read from rax.
//
// (b) is what OBI does. For Phase 3 minimum-viable we accept the gap —
// Go HTTPS request bodies are captured (Write side); Response bodies
// from the SERVER perspective are also captured (server calls Write to
// send response). Client-side response reading is the only gap.
//
// TODO(phase3-followup): implement RET-instruction probing for Read.
