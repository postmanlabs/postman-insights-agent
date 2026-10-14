// SPDX-License-Identifier: Apache-2.0
//
// Java TLS capture for the Postman Insights Agent.
//
// The Postman Java agent, running inside a JVM, hooks javax.net.ssl.SSLEngine
// and hands each call's plaintext to the kernel as a frame (java_frame.h): a
// positional write to /dev/null at offset JAVA_FRAME_MAGIC. These programs
// read the frame on syscall entry and turn it into the same ssl_event the
// libssl uprobes emit, on the same ring buffer, so everything after the ring
// buffer (routing by netns, the adapter, the HTTP parsers) is shared.
//
//   glibc: FileChannel.write(buf, pos)  ->  pwrite64(fd, buf, count, pos)
//   musl:  FileChannel.write(buf, pos)  ->  pwritev2(fd, iov, 1, pos, 0, RWF_NOAPPEND)
//
// Every positional write on the node runs these programs, so the first check
// is the offset: one compare, then out for every normal write.
//
// Only frames from processes in allowed network namespaces (java_netns, the
// monitored pods) are accepted. The kernel stamps pid, tid and netns itself,
// so an agent cannot attribute traffic to another pod.

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "event.h"
#include "common.h"
#include "java_frame.h"

char LICENSE[] SEC("license") = "GPL";    // required for some BPF helpers

// Network namespaces whose processes may send frames. Userspace adds a
// monitored pod's netns inode when it starts capturing for the pod and
// removes it when the pod goes away. Keyed by netns rather than PID because
// the netns inode is the same in every PID namespace (see current_netns).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);                   // netns inode
    __type(value, __u8);                  // sentinel
} java_netns SEC(".maps");

// Per-PID rate-cap buckets for Java senders (--https-rate-cap-per-sec).
// They refill themselves: the first event after a one-second window starts a
// new window with a full bucket. Userspace cannot refill them the way it
// refills libssl's buckets, because it does not know the senders' PIDs as the
// kernel sees them (they differ in nested PID namespaces). LRU, so buckets of
// exited processes age out.
struct java_rate_bucket {
    __u64 window_start_ns;
    __u64 tokens;                         // left in the current window
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);                   // tgid
    __type(value, struct java_rate_bucket);
} java_rate_buckets SEC(".maps");

#define NSEC_PER_SEC 1000000000ULL

// Takes one event from tgid's bucket; returns 0 when the bucket is empty.
// Concurrent senders on other CPUs can race on a window change; the cap is
// approximate there, never unbounded.
static __always_inline int java_rate_take(__u32 tgid) {
    __u32 cap = rate_cap_per_sec;
    if (cap == 0) {
        return 1;
    }
    __u64 now = bpf_ktime_get_ns();
    struct java_rate_bucket *b = bpf_map_lookup_elem(&java_rate_buckets, &tgid);
    if (!b) {
        struct java_rate_bucket fresh = { .window_start_ns = now, .tokens = cap - 1 };
        bpf_map_update_elem(&java_rate_buckets, &tgid, &fresh, BPF_NOEXIST);
        return 1;
    }
    if (now - b->window_start_ns >= NSEC_PER_SEC) {
        b->window_start_ns = now;
        b->tokens = cap - 1;
        return 1;
    }
    // Same underflow guard as rate_take in libssl.bpf.c.
    if (__sync_fetch_and_sub(&b->tokens, 1) == 0) {
        __sync_fetch_and_add(&b->tokens, 1);
        return 0;
    }
    return 1;
}

// Telemetry counters, per-CPU so increments are lock-free; userspace sums
// across CPUs. Indices must match ebpf/loader (JavaCounter*).
#define JAVA_CTR_FRAMES_SEEN       0  // writes at the magic offset
#define JAVA_CTR_EVENTS_EMITTED    1  // ring buffer submits
#define JAVA_CTR_EVENTS_DROPPED    2  // ring buffer full
#define JAVA_CTR_READ_FAILED       3  // bpf_probe_read_user failed
#define JAVA_CTR_BYTES_CAPTURED    4  // sum of len_captured
#define JAVA_CTR_RATE_CAPPED       5  // dropped by the per-PID rate cap
#define JAVA_CTR_NETNS_REJECTED    6  // sender not in an allowed netns
#define JAVA_CTR_MALFORMED         7  // failed validation
#define JAVA_CTR_CONTROL_FRAMES    8  // HELLO and CLOSE frames (not forwarded yet)
#define JAVA_CTR_MAX               9

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, JAVA_CTR_MAX);
    __type(key, __u32);
    __type(value, __u64);
} java_counters SEC(".maps");

static __always_inline void java_counter_inc(__u32 idx, __u64 by) {
    __u64 *v = bpf_map_lookup_elem(&java_counters, &idx);
    if (v) {
        *v += by;  // per-CPU array; no atomic needed
    }
}

// Set from userspace at load time. 1 = accept frames only from netns in
// java_netns (NodeCollector); 0 = accept frames from every process
// (standalone apidump, which captures the whole host).
volatile const __u32 enforce_netns_allowlist = 1;

// Validates one frame (buf, count: the whole positional write) and emits its
// payload as an ssl_event. The checks match javatls.Parse in Go.
static __always_inline int handle_frame(const __u8 *buf, __u64 count) {
    java_counter_inc(JAVA_CTR_FRAMES_SEEN, 1);

    __u32 netns = current_netns();
    if (enforce_netns_allowlist && !bpf_map_lookup_elem(&java_netns, &netns)) {
        java_counter_inc(JAVA_CTR_NETNS_REJECTED, 1);
        return 0;
    }

    if (count < JAVA_FRAME_HEADER_SIZE) {
        java_counter_inc(JAVA_CTR_MALFORMED, 1);
        return 0;
    }
    struct java_frame_header h;
    if (bpf_probe_read_user(&h, sizeof(h), buf) != 0) {
        java_counter_inc(JAVA_CTR_READ_FAILED, 1);
        return 0;
    }
    if (h.version != JAVA_FRAME_VERSION_1 ||
        h.op < JAVA_FRAME_OP_SEND || h.op > JAVA_FRAME_OP_CLOSE ||
        h._reserved != 0 ||
        (__u64)h.payload_len + JAVA_FRAME_HEADER_SIZE != count ||
        h.total_len < h.payload_len) {
        java_counter_inc(JAVA_CTR_MALFORMED, 1);
        return 0;
    }

    __u8 direction;
    if (h.op == JAVA_FRAME_OP_SEND) {
        direction = DIR_EGRESS;
    } else if (h.op == JAVA_FRAME_OP_RECV) {
        direction = DIR_INGRESS;
    } else {
        // TODO(INS-363): forward HELLO (agent telemetry) and CLOSE (free the
        // connection's flow state early) to userspace.
        java_counter_inc(JAVA_CTR_CONTROL_FRAMES, 1);
        return 0;
    }
    if (h.payload_len == 0) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    if (!java_rate_take(pid_tgid >> 32)) {
        java_counter_inc(JAVA_CTR_RATE_CAPPED, 1);
        return 0;
    }

    struct ssl_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        java_counter_inc(JAVA_CTR_EVENTS_DROPPED, 1);
        return 0;
    }

    // Same bounding as emit_event in libssl.bpf.c: the 64-bit AND gives the
    // verifier smin=0, then clamp to the runtime knob and the array bound.
    __u64 to_copy = (__u64)h.payload_len & 0xffffffffULL;
    if (to_copy > max_capture_bytes) {
        to_copy = max_capture_bytes;
    }
    if (to_copy > MAX_EVENT_PAYLOAD) {
        to_copy = MAX_EVENT_PAYLOAD;
    }

    e->ts_ns        = bpf_ktime_get_ns();
    e->pid          = pid_tgid >> 32;
    e->tid          = (__u32)pid_tgid;
    e->ssl_ctx      = h.conn_id | JAVA_CONN_ID_TAG;
    e->len_total    = h.total_len;
    e->len_captured = to_copy;
    e->fd           = -1;                 // TODO(INS-366): correlate with the socket fd
    e->direction    = direction;
    __builtin_memset(e->_pad, 0, sizeof(e->_pad));
    e->netns        = netns;

    if (bpf_probe_read_user(e->payload, to_copy, buf + JAVA_FRAME_HEADER_SIZE) != 0) {
        bpf_ringbuf_discard(e, 0);
        java_counter_inc(JAVA_CTR_READ_FAILED, 1);
        return 0;
    }

    bpf_ringbuf_submit(e, 0);
    java_counter_inc(JAVA_CTR_EVENTS_EMITTED, 1);
    java_counter_inc(JAVA_CTR_BYTES_CAPTURED, to_copy);
    return 0;
}

// ssize_t pwrite64(unsigned int fd, const char *buf, size_t count, loff_t pos);
SEC("tracepoint/syscalls/sys_enter_pwrite64")
int tp_sys_enter_pwrite64(struct trace_event_raw_sys_enter *ctx) {
    if ((__u64)ctx->args[3] != JAVA_FRAME_MAGIC) {
        return 0;
    }
    return handle_frame((const __u8 *)ctx->args[1], (__u64)ctx->args[2]);
}

// The vectored variants carry the offset in pos_l, which holds the whole
// offset on 64-bit kernels. The agent always writes a single iovec.
static __always_inline int handle_vectored(struct trace_event_raw_sys_enter *ctx) {
    if ((__u64)ctx->args[3] != JAVA_FRAME_MAGIC) {
        return 0;
    }
    if ((__u64)ctx->args[2] != 1) {
        java_counter_inc(JAVA_CTR_FRAMES_SEEN, 1);
        java_counter_inc(JAVA_CTR_MALFORMED, 1);
        return 0;
    }
    struct iovec iov;
    if (bpf_probe_read_user(&iov, sizeof(iov), (const void *)ctx->args[1]) != 0) {
        java_counter_inc(JAVA_CTR_FRAMES_SEEN, 1);
        java_counter_inc(JAVA_CTR_READ_FAILED, 1);
        return 0;
    }
    return handle_frame((const __u8 *)iov.iov_base, (__u64)iov.iov_len);
}

// ssize_t pwritev2(unsigned long fd, const struct iovec *vec, unsigned long vlen,
//                  unsigned long pos_l, unsigned long pos_h, rwf_t flags);
// musl implements pwrite() with this.
SEC("tracepoint/syscalls/sys_enter_pwritev2")
int tp_sys_enter_pwritev2(struct trace_event_raw_sys_enter *ctx) {
    return handle_vectored(ctx);
}

// ssize_t pwritev(unsigned long fd, const struct iovec *vec, unsigned long vlen,
//                 unsigned long pos_l, unsigned long pos_h);
// No libc uses this for pwrite() today; attached so one switching to it does
// not silently stop capture. Costs one compare per call.
SEC("tracepoint/syscalls/sys_enter_pwritev")
int tp_sys_enter_pwritev(struct trace_event_raw_sys_enter *ctx) {
    return handle_vectored(ctx);
}
