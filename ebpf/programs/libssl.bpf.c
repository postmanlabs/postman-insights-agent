// SPDX-License-Identifier: Apache-2.0
//
// libssl uprobes — Phase 1 of HTTPS capture for the Postman Insights Agent.
//
// Architecture (mirrors OBI bpf/generictracer/libssl.c, simplified):
//
//   uprobe  SSL_read(SSL*, void* buf, int num)
//     └─► stash (buf, ssl) in active_ssl_read_args[pid_tid]
//
//   uretprobe SSL_read(int ret)              ret = bytes decrypted (or <0)
//     └─► look up args, read min(ret, MAX_EVENT_PAYLOAD) bytes from buf,
//         emit ssl_event{direction=INGRESS} into ringbuf
//
//   Symmetric for SSL_write / SSL_read_ex / SSL_write_ex.
//
// We intentionally do NOT replicate OBI's full connection-tracking machinery
// (ssl_to_conn, pid_tid_to_conn, etc.) at this phase. Correlation of bytes
// into HTTP requests/responses happens in userspace via the existing
// akinet.HTTPRequestParser / akinet.HTTPResponseParser fed with the raw
// byte streams keyed by (pid, ssl_ctx, direction).
//
// Compilation:
//   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
//         -I$(LIBBPF_HDRS) -c libssl.bpf.c -o libssl.bpf.o
//
// In our build we use cilium/ebpf's bpf2go to do this and generate Go
// bindings. See ebpf/loader/loader.go.

//go:build ignore

#include "vmlinux.h"                      // BTF-generated kernel types
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "event.h"

// libbpf < 1.3 (Debian bookworm ships 1.1) lacks BPF_UPROBE / BPF_URETPROBE.
// They are documented aliases for BPF_KPROBE / BPF_KRETPROBE — uprobes use the
// same struct pt_regs * context. Define the aliases if absent so the source
// compiles on older libbpf and is still readable.
#ifndef BPF_UPROBE
#define BPF_UPROBE(name, args...)    BPF_KPROBE(name, ##args)
#endif
#ifndef BPF_URETPROBE
#define BPF_URETPROBE(name, args...) BPF_KRETPROBE(name, ##args)
#endif

char LICENSE[] SEC("license") = "GPL";    // required for some BPF helpers

// -----------------------------------------------------------------------------
// Maps
// -----------------------------------------------------------------------------

// Per-thread args stash: entry uprobe writes, exit uretprobe reads.
// Key:  pid_tgid (kernel-style 64-bit thread identifier)
// Value: pointer to plaintext buffer + SSL* + length pointer (for *_ex variants)
struct ssl_args_t {
    __u64 buf;                            // user-space pointer to plaintext
    __u64 ssl;                            // SSL* — opaque connection id
    __u64 len_ptr;                        // for SSL_{read,write}_ex: pointer
                                          // to size_t output param
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);                   // pid_tgid
    __type(value, struct ssl_args_t);
} active_ssl_read_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct ssl_args_t);
} active_ssl_write_args SEC(".maps");

// Output ring buffer. 2 MB per ringbuf; cilium/ebpf reads on the Go side.
// OBI uses the same size.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 21);         // 2 MiB
} events SEC(".maps");

// PID allowlist. Userspace populates this with target PIDs (discovered
// containers in target namespaces). An empty map means "trace everyone",
// useful for the spike; production builds will require explicit allow.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);                   // tgid
    __type(value, __u8);                  // sentinel
} target_pids SEC(".maps");

// Volatile knob set from userspace at load time.
// 0 = trace all PIDs (spike); 1 = only trace PIDs in target_pids.
volatile const __u32 enforce_pid_allowlist = 0;

// Volatile knob: max bytes to copy from plaintext buffer. Clamped to
// MAX_EVENT_PAYLOAD at compile time. Power of two recommended.
volatile const __u32 max_capture_bytes = MAX_EVENT_PAYLOAD;

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

static __always_inline int pid_allowed(__u32 tgid) {
    if (!enforce_pid_allowlist) {
        return 1;
    }
    return bpf_map_lookup_elem(&target_pids, &tgid) != NULL;
}

// Copy up to `len` bytes from `user_buf` into a freshly-reserved ringbuf
// event and submit it. Returns 0 on success, -1 on failure.
//
// NOTE on the verifier: we must mask `to_copy` so the verifier can prove
// the bounded read. The mask is MAX_EVENT_PAYLOAD - 1 (power of two).
static __always_inline int emit_event(
        __u64 pid_tgid,
        __u64 ssl_ctx,
        const void *user_buf,
        __u32 reported_len,
        __u8 direction) {
    if (!user_buf || reported_len == 0) {
        return -1;
    }

    struct ssl_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        // Ringbuf full — kernel will count this in bpf_ringbuf_query().
        return -1;
    }

    __u32 to_copy = reported_len;
    if (to_copy > max_capture_bytes) {
        to_copy = max_capture_bytes;
    }
    // Verifier-friendly bound — power-of-two mask.
    to_copy &= (MAX_EVENT_PAYLOAD - 1);
    // Guarantee at least 1 byte if reported_len > 0, so the verifier is happy
    // with the bpf_probe_read_user below.
    if (to_copy == 0 && reported_len > 0) {
        to_copy = 1;
    }

    e->ts_ns        = bpf_ktime_get_ns();
    e->pid          = pid_tgid >> 32;
    e->tid          = (__u32)pid_tgid;
    e->ssl_ctx      = ssl_ctx;
    e->len_total    = reported_len;
    e->len_captured = to_copy;
    e->direction    = direction;
    __builtin_memset(e->_pad, 0, sizeof(e->_pad));

    if (bpf_probe_read_user(e->payload, to_copy, user_buf) != 0) {
        bpf_ringbuf_discard(e, 0);
        return -1;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// -----------------------------------------------------------------------------
// SSL_read
// -----------------------------------------------------------------------------
// int SSL_read(SSL *ssl, void *buf, int num);
//
SEC("uprobe/SSL_read")
int BPF_UPROBE(uprobe_ssl_read, void *ssl, const void *buf, int num) {
    (void)num;
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    if (!pid_allowed(tgid)) return 0;

    struct ssl_args_t args = {
        .buf     = (__u64)buf,
        .ssl     = (__u64)ssl,
        .len_ptr = 0,
    };
    bpf_map_update_elem(&active_ssl_read_args, &id, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read")
int BPF_URETPROBE(uretprobe_ssl_read, int ret) {
    __u64 id = bpf_get_current_pid_tgid();
    if (!pid_allowed(id >> 32)) return 0;

    struct ssl_args_t *args = bpf_map_lookup_elem(&active_ssl_read_args, &id);
    if (!args || ret <= 0) {
        bpf_map_delete_elem(&active_ssl_read_args, &id);
        return 0;
    }

    emit_event(id, args->ssl, (const void *)args->buf, (__u32)ret, DIR_INGRESS);
    bpf_map_delete_elem(&active_ssl_read_args, &id);
    return 0;
}

// -----------------------------------------------------------------------------
// SSL_read_ex
// -----------------------------------------------------------------------------
// int SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes);
//
SEC("uprobe/SSL_read_ex")
int BPF_UPROBE(uprobe_ssl_read_ex,
               void *ssl,
               const void *buf,
               size_t num,
               size_t *readbytes) {
    (void)num;
    __u64 id = bpf_get_current_pid_tgid();
    if (!pid_allowed(id >> 32)) return 0;

    struct ssl_args_t args = {
        .buf     = (__u64)buf,
        .ssl     = (__u64)ssl,
        .len_ptr = (__u64)readbytes,
    };
    bpf_map_update_elem(&active_ssl_read_args, &id, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read_ex")
int BPF_URETPROBE(uretprobe_ssl_read_ex, int ret) {
    __u64 id = bpf_get_current_pid_tgid();
    if (!pid_allowed(id >> 32)) return 0;

    struct ssl_args_t *args = bpf_map_lookup_elem(&active_ssl_read_args, &id);
    if (!args || ret != 1) {                      // SSL_read_ex returns 1 on success
        bpf_map_delete_elem(&active_ssl_read_args, &id);
        return 0;
    }

    size_t read_len = 0;
    bpf_probe_read_user(&read_len, sizeof(read_len), (void *)args->len_ptr);

    emit_event(id, args->ssl, (const void *)args->buf, (__u32)read_len, DIR_INGRESS);
    bpf_map_delete_elem(&active_ssl_read_args, &id);
    return 0;
}

// -----------------------------------------------------------------------------
// SSL_write
// -----------------------------------------------------------------------------
// int SSL_write(SSL *ssl, const void *buf, int num);
//
// Note: for write we capture the buffer on entry (before encryption); the
// return value confirms how many bytes were actually consumed.
//
SEC("uprobe/SSL_write")
int BPF_UPROBE(uprobe_ssl_write, void *ssl, const void *buf, int num) {
    __u64 id = bpf_get_current_pid_tgid();
    if (!pid_allowed(id >> 32)) return 0;

    struct ssl_args_t args = {
        .buf     = (__u64)buf,
        .ssl     = (__u64)ssl,
        .len_ptr = (__u64)num,                     // stash num (not a pointer)
    };
    bpf_map_update_elem(&active_ssl_write_args, &id, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_write")
int BPF_URETPROBE(uretprobe_ssl_write, int ret) {
    __u64 id = bpf_get_current_pid_tgid();
    if (!pid_allowed(id >> 32)) return 0;

    struct ssl_args_t *args = bpf_map_lookup_elem(&active_ssl_write_args, &id);
    if (!args || ret <= 0) {
        bpf_map_delete_elem(&active_ssl_write_args, &id);
        return 0;
    }

    emit_event(id, args->ssl, (const void *)args->buf, (__u32)ret, DIR_EGRESS);
    bpf_map_delete_elem(&active_ssl_write_args, &id);
    return 0;
}

// -----------------------------------------------------------------------------
// SSL_write_ex
// -----------------------------------------------------------------------------
// int SSL_write_ex(SSL *ssl, const void *buf, size_t num, size_t *written);
//
SEC("uprobe/SSL_write_ex")
int BPF_UPROBE(uprobe_ssl_write_ex,
               void *ssl,
               const void *buf,
               size_t num,
               size_t *written) {
    (void)num;
    __u64 id = bpf_get_current_pid_tgid();
    if (!pid_allowed(id >> 32)) return 0;

    struct ssl_args_t args = {
        .buf     = (__u64)buf,
        .ssl     = (__u64)ssl,
        .len_ptr = (__u64)written,
    };
    bpf_map_update_elem(&active_ssl_write_args, &id, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_write_ex")
int BPF_URETPROBE(uretprobe_ssl_write_ex, int ret) {
    __u64 id = bpf_get_current_pid_tgid();
    if (!pid_allowed(id >> 32)) return 0;

    struct ssl_args_t *args = bpf_map_lookup_elem(&active_ssl_write_args, &id);
    if (!args || ret != 1) {
        bpf_map_delete_elem(&active_ssl_write_args, &id);
        return 0;
    }

    size_t written = 0;
    bpf_probe_read_user(&written, sizeof(written), (void *)args->len_ptr);

    emit_event(id, args->ssl, (const void *)args->buf, (__u32)written, DIR_EGRESS);
    bpf_map_delete_elem(&active_ssl_write_args, &id);
    return 0;
}
