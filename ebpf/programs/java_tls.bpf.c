// SPDX-License-Identifier: Apache-2.0
//
// java_tls — Phase 5a of HTTPS capture for the Postman Insights Agent.
//
// Goal
// ----
// Receive decrypted plaintext from a JVM via a single `ioctl()` syscall and
// emit it on the SAME `ssl_event` ringbuf used by libssl.bpf.c, so the
// userspace adapter (ebpf/events.Adapter) treats Java traffic identically to
// native libssl traffic.
//
// Wire format (frozen for the agent ↔ kernel interface)
// -----------------------------------------------------
//
//   fd  == 0          (sentinel — JVMs never do real ioctl on stdin)
//   cmd == 0x0b10b1   (magic — chosen by OBI; we deliberately reuse so the
//                      same Java agent JAR could in principle drive either
//                      runtime)
//   arg points to:
//
//     struct java_packet {
//         u8  operation;        //   0: 1=SEND, 2=RECV
//         u8  s_addr[16];       //   1: IPv6 (or IPv4-in-v6) source
//         u8  d_addr[16];       //  17: IPv6 (or IPv4-in-v6) dest
//         u16 s_port;           //  33
//         u16 d_port;           //  35
//         u32 buf_len;          //  37
//         // bytes at offset   //  41 .. 41+buf_len
//     };
//
//   Total fixed header: 41 bytes. Layout is byte-packed — NO compiler
//   padding. This must match OBI's `IOCTLPacket.java` and the Java agent
//   we will ship in Phase 5b.
//
// Mapping to ssl_event
// --------------------
//   operation==1 (SEND) -> direction = DIR_EGRESS
//   operation==2 (RECV) -> direction = DIR_INGRESS
//   ssl_ctx             = synthetic 64-bit id derived from the conn tuple
//                         so a single "Java connection" routes consistently
//                         in the adapter's per-flow state.
//   fd                  = -1 (we don't have one; userspace tolerates this
//                         the same way it tolerates unresolved SSL* fds).
//
// Out of scope for 5a
// -------------------
//   * Java thread-parenting / context propagation (OBI's k_ioctl_java_threads
//     op). We don't ship distributed tracing.
//   * IPv6 enrichment. The C harness emits IPv4 in the first 4 bytes.
//   * Per-PID rate limiting. libssl has it; we add it for java_tls once 5b
//     proves the path with a real JVM. The kprobe is gated on the
//     PID allowlist (same map keying as libssl).

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "event.h"

char LICENSE[] SEC("license") = "GPL";

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

#define JAVA_IOCTL_MAGIC      0x0b10b1
#define JAVA_OP_SEND          1
#define JAVA_OP_RECV          2

// Offsets into the user-space java_packet (must match the layout above).
#define JP_OFF_OP             0
#define JP_OFF_SADDR          1
#define JP_OFF_DADDR         17
#define JP_OFF_SPORT         33
#define JP_OFF_DPORT         35
#define JP_OFF_BUFLEN        37
#define JP_HEADER_SIZE       41

// -----------------------------------------------------------------------------
// Maps
// -----------------------------------------------------------------------------

// Output ringbuf — same size as libssl's so the userspace reader's expectations
// hold. Intentionally a SEPARATE ringbuf from libssl's so this program can be
// loaded conditionally (only when Java capture is enabled), and so userspace
// can attach a dedicated reader. The event struct is identical.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 21);              // 2 MiB
} java_events SEC(".maps");

// PID allowlist. Same shape and semantics as libssl's target_pids. Empty map
// means "trace everyone" only when enforce_pid_allowlist is false.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);                        // tgid
    __type(value, __u8);
} java_target_pids SEC(".maps");

// Telemetry counters — same indices as libssl for consistency:
//   0 = events emitted
//   1 = ringbuf-reserve failures
//   2 = probe_read_user failures
//   3 = bytes captured
//   4 = ioctl calls observed but rejected (wrong fd/cmd) — diagnostic
//   5 = events dropped because the PID was not in the allowlist
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 6);
    __type(key, __u32);
    __type(value, __u64);
} java_counters SEC(".maps");

static __always_inline void counter_inc(__u32 idx, __u64 by) {
    __u64 *v = bpf_map_lookup_elem(&java_counters, &idx);
    if (v) {
        *v += by;
    }
}

// Compile-time-overridable knobs (rewritten by the Go loader at load time).
volatile const __u32 java_enforce_pid_allowlist = 0;
__u32 java_max_capture_bytes = MAX_EVENT_PAYLOAD;

static __always_inline int pid_allowed(__u32 tgid) {
    if (!java_enforce_pid_allowlist) {
        return 1;
    }
    return bpf_map_lookup_elem(&java_target_pids, &tgid) != NULL;
}

// Synthesise an opaque 64-bit "connection id" from a conn-tuple. The adapter
// uses (pid, ssl_ctx, direction) as a flow key — we only need this value to
// be stable across SEND/RECV of one logical connection, and unique enough
// across concurrent connections in the same PID. A hash of the last 4 bytes
// of each address (the IPv4 part for v4-mapped) plus the ports is plenty
// for that.
static __always_inline __u64 synth_ssl_ctx(__u32 s_ip4, __u32 d_ip4,
                                           __u16 s_port, __u16 d_port) {
    // Canonicalise so SEND and RECV from the same socket hash equally,
    // even though the agent reports them with src/dst swapped.
    __u32 a = s_ip4 ^ d_ip4;
    __u32 p = ((__u32)s_port) ^ ((__u32)d_port);
    return ((__u64)a << 32) | (__u64)(p | (s_ip4 << 16) | d_ip4);
}

// -----------------------------------------------------------------------------
// The kprobe
// -----------------------------------------------------------------------------
//
// long sys_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg)
//
// On kernels with syscall wrapper enabled (the default since ~4.17 on x86),
// the syscall entry is reached via a stub that boxes the registers; we use
// BPF_KPROBE_SYSCALL via cilium's tracing helpers, but the most portable
// approach (and what OBI uses) is to read the args via PT_REGS_PARM*() on
// the wrapped pt_regs that the syscall entry passes as its first arg.
//
// SEC name is informational once cilium/ebpf attaches by explicit function
// name (see ebpf/loader/loader_javatls_linux.go). We name it `sys_ioctl` so
// `bpftool prog show` reports something familiar; the actual attach uses
// link.Kprobe("sys_ioctl", ...) which resolves the right arch-prefixed
// symbol (`__x64_sys_ioctl` on amd64, `__arm64_sys_ioctl` on arm64) via
// the kernel's symbol aliases.
SEC("kprobe/sys_ioctl")
int BPF_KPROBE(java_kprobe_sys_ioctl) {
    const __u64 id = bpf_get_current_pid_tgid();
    const __u32 tgid = id >> 32;

    if (!pid_allowed(tgid)) {
        // Don't increment a counter here — this fires for EVERY ioctl in
        // the system when the allowlist is enforced. Pure noise.
        return 0;
    }

    // The syscall wrapper passes the real pt_regs as PARM1.
    struct pt_regs *__ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);

    unsigned int fd = 0;
    unsigned int cmd = 0;
    unsigned long arg = 0;
    bpf_probe_read(&fd,  sizeof(fd),  (void *)&PT_REGS_PARM1(__ctx));
    bpf_probe_read(&cmd, sizeof(cmd), (void *)&PT_REGS_PARM2(__ctx));
    bpf_probe_read(&arg, sizeof(arg), (void *)&PT_REGS_PARM3(__ctx));

    if (fd != 0) {
        return 0;                              // not our sentinel — common
    }
    if (cmd != JAVA_IOCTL_MAGIC) {
        // fd==0 + non-magic cmd: extremely rare in practice but theoretically
        // possible (a process explicitly ioctl()'ing stdin). Bump a counter
        // so we can spot it if it happens in production.
        counter_inc(4, 1);
        return 0;
    }
    if (!arg) {
        counter_inc(2, 1);
        return 0;
    }

    const __u8 *uarg = (const __u8 *)arg;

    __u8 op = 0;
    if (bpf_probe_read_user(&op, sizeof(op), uarg + JP_OFF_OP) != 0) {
        counter_inc(2, 1);
        return 0;
    }
    __u8 direction;
    if (op == JAVA_OP_SEND) {
        direction = DIR_EGRESS;
    } else if (op == JAVA_OP_RECV) {
        direction = DIR_INGRESS;
    } else {
        // Reserve op==3 etc. for OBI's java-thread-mapping path (NOT
        // implemented in 5a — see header comment).
        return 0;
    }

    __u32 s_ip4 = 0, d_ip4 = 0;
    __u16 s_port = 0, d_port = 0;
    // For 5a's harness we only care about the IPv4 dotted-quad which we
    // place in the first 4 bytes of the v6 addr slot. 5b's Java agent may
    // populate the full v6 address; that's fine — we still hash to the
    // same ssl_ctx for SEND/RECV pairs.
    bpf_probe_read_user(&s_ip4,  sizeof(s_ip4),  uarg + JP_OFF_SADDR);
    bpf_probe_read_user(&d_ip4,  sizeof(d_ip4),  uarg + JP_OFF_DADDR);
    bpf_probe_read_user(&s_port, sizeof(s_port), uarg + JP_OFF_SPORT);
    bpf_probe_read_user(&d_port, sizeof(d_port), uarg + JP_OFF_DPORT);

    __u32 reported_len = 0;
    if (bpf_probe_read_user(&reported_len, sizeof(reported_len),
                            uarg + JP_OFF_BUFLEN) != 0) {
        counter_inc(2, 1);
        return 0;
    }
    if (reported_len == 0) {
        return 0;
    }

    struct ssl_event *e = bpf_ringbuf_reserve(&java_events, sizeof(*e), 0);
    if (!e) {
        counter_inc(1, 1);
        return 0;
    }

    __u32 to_copy = reported_len;
    if (to_copy > java_max_capture_bytes) {
        to_copy = java_max_capture_bytes;
    }
    // Clamp to compile-time array bound (verifier proof via conditional).
    // The old mask (&= MAX_EVENT_PAYLOAD-1) was a bug: 1024 & 1023 == 0,
    // causing payloads of exactly MAX_EVENT_PAYLOAD bytes to be emitted as 1 byte.
    if (to_copy > MAX_EVENT_PAYLOAD) {
        to_copy = MAX_EVENT_PAYLOAD;
    }

    e->ts_ns        = bpf_ktime_get_ns();
    e->pid          = tgid;
    e->tid          = (__u32)id;
    e->ssl_ctx      = synth_ssl_ctx(s_ip4, d_ip4, s_port, d_port);
    e->len_total    = reported_len;
    e->len_captured = to_copy;
    e->fd           = -1;
    e->direction    = direction;
    __builtin_memset(e->_pad, 0, sizeof(e->_pad));

    if (bpf_probe_read_user(e->payload, to_copy, uarg + JP_HEADER_SIZE) != 0) {
        bpf_ringbuf_discard(e, 0);
        counter_inc(2, 1);
        return 0;
    }

    bpf_ringbuf_submit(e, 0);
    counter_inc(0, 1);
    counter_inc(3, to_copy);
    return 0;
}
