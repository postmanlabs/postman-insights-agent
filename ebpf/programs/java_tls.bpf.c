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
#include <bpf/bpf_endian.h>

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
    __s64 tokens;                         // left in the current window; signed, see bucket_take
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);                   // tgid
    __type(value, struct java_rate_bucket);
} java_rate_buckets SEC(".maps");

// Per-PID HEARTBEAT buckets, separate from the rate cap so that a busy agent
// never looks dead, but still bounded: any process in an allowed netns can
// write frames, and unlimited heartbeats would fill the shared ring buffer.
// The agent sends one every 30 s; the bucket allows HEARTBEAT_BURST per
// window, which leaves room for timing jitter at a window boundary.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);                   // tgid
    __type(value, struct java_rate_bucket);
} java_heartbeat_buckets SEC(".maps");

#define NSEC_PER_SEC 1000000000ULL
#define HEARTBEAT_WINDOW_NS (30 * NSEC_PER_SEC)
#define HEARTBEAT_BURST     3

// Takes one event from tgid's bucket in buckets, which holds cap events per
// window_ns; returns 0 when the bucket is empty.
//
// tokens is signed, and an empty bucket is restored after a failed take: a
// take racing on another CPU then sees zero or less and fails too, so the
// count can dip below zero for an instant but never wraps around to "full".
// Only one CPU creates a bucket; the others take from it. Two CPUs can both
// start a new window, each with a full bucket: the cap is approximate there,
// by at most the number of CPUs per window, and never unbounded.
static __always_inline int bucket_take(void *buckets, __u32 tgid, __s64 cap, __u64 window_ns) {
    __u64 now = bpf_ktime_get_ns();
    struct java_rate_bucket *b = bpf_map_lookup_elem(buckets, &tgid);
    if (!b) {
        struct java_rate_bucket fresh = { .window_start_ns = now, .tokens = cap - 1 };
        if (bpf_map_update_elem(buckets, &tgid, &fresh, BPF_NOEXIST) == 0) {
            return 1;
        }
        // Another CPU created it first.
        b = bpf_map_lookup_elem(buckets, &tgid);
        if (!b) {
            return 0;
        }
    }
    if (now - b->window_start_ns >= window_ns) {
        b->window_start_ns = now;
        b->tokens = cap - 1;
        return 1;
    }
    if (__sync_fetch_and_sub(&b->tokens, 1) <= 0) {
        __sync_fetch_and_add(&b->tokens, 1);
        return 0;
    }
    return 1;
}

// Takes one data or CLOSE event from tgid's rate-cap bucket.
static __always_inline int java_rate_take(__u32 tgid) {
    __u32 cap = rate_cap_per_sec;
    if (cap == 0) {
        return 1;
    }
    return bucket_take(&java_rate_buckets, tgid, cap, NSEC_PER_SEC);
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
#define JAVA_CTR_CONTROL_FRAMES    8  // HEARTBEAT and CLOSE frames
#define JAVA_CTR_HEARTBEAT_LIMITED 9  // HEARTBEATs over the per-PID limit
#define JAVA_CTR_CONN_BOUND        10 // connections tied to their socket
#define JAVA_CTR_CONN_UNBOUND      11 // data frames of connections not tied to a socket
#define JAVA_CTR_CONN_MISMATCH     12 // a later read on a connection's thread was another socket's
#define JAVA_CTR_MAX               13

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

// ---------------------------------------------------------------------------
// Connection addresses
//
// The Java agent sees SSLEngines, not sockets, so its frames carry no
// addresses. The servers and clients we capture read the socket on the thread
// that then unwraps what it read (Tomcat NIO, Netty, Jetty, Undertow, the JDK's
// blocking SSLSocket): so the socket a thread read from just before a RECV
// frame is the frame's connection. tcp_recvmsg records, for the threads of
// processes that send frames, the addresses of the socket each last read; a
// connection's first RECV frame ties it to them (java_conns), and every event
// of the connection then carries them. The agent sends an empty RECV frame at
// a connection's first unwrap, during the handshake, so the tie exists before
// the first request or response, whichever side sends first.
//
// When a thread did not read a socket just before (an engine unwrapped on
// another thread than the one that read), the connection stays untied, and
// its events carry no addresses rather than wrong ones.
// ---------------------------------------------------------------------------

// Processes that sent a valid frame: only their socket reads are recorded,
// so every other process's tcp_recvmsg costs one lookup.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);                   // tgid
    __type(value, __u8);
} java_senders SEC(".maps");

// The socket a thread of a java_senders process last read from.
struct thread_read {
    __u64 ts_ns;
    struct conn_tuple tuple;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);                   // pid_tgid
    __type(value, struct thread_read);
} java_thread_reads SEC(".maps");

// Connections tied to their socket's addresses. Removed on CLOSE; LRU for
// connections that end without one.
struct java_conn_key {
    __u32 tgid;
    __u32 _pad;
    __u64 conn_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct java_conn_key);
    __type(value, struct conn_tuple);
} java_conns SEC(".maps");

// How recent a thread's read must be to tie a RECV frame to its socket: an
// unwrap follows the read it decrypts within microseconds, but a GC pause
// can come in between.
#define THREAD_READ_MAX_AGE_NS (50ULL * 1000 * 1000)

#define AF_INET  2
#define AF_INET6 10

static __always_inline void sock_tuple(struct sock *sk, struct conn_tuple *t) {
    __builtin_memset(t, 0, sizeof(*t));
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family == AF_INET) {
        t->family = CONN_FAMILY_INET;
        bpf_core_read(t->local_addr, 4, &sk->__sk_common.skc_rcv_saddr);
        bpf_core_read(t->remote_addr, 4, &sk->__sk_common.skc_daddr);
    } else if (family == AF_INET6) {
        t->family = CONN_FAMILY_INET6;
        bpf_core_read(t->local_addr, 16, &sk->__sk_common.skc_v6_rcv_saddr);
        bpf_core_read(t->remote_addr, 16, &sk->__sk_common.skc_v6_daddr);
    } else {
        return;
    }
    t->local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    t->remote_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
}

static __always_inline void record_thread_read(struct sock *sk) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    if (!bpf_map_lookup_elem(&java_senders, &tgid)) {
        return;
    }
    // A thread's entry is rewritten in place: an LRU update on every read
    // would cost several times the rest.
    struct thread_read *r = bpf_map_lookup_elem(&java_thread_reads, &pid_tgid);
    if (r) {
        sock_tuple(sk, &r->tuple);
        r->ts_ns = bpf_ktime_get_ns();
        return;
    }
    struct thread_read fresh = { .ts_ns = bpf_ktime_get_ns() };
    sock_tuple(sk, &fresh.tuple);
    bpf_map_update_elem(&java_thread_reads, &pid_tgid, &fresh, BPF_ANY);
}

// int tcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, ...);
// The first argument is the same on every kernel. fentry where the kernel
// supports it (x86_64 5.5+, arm64 6.0+), else kprobe; the loader picks.
SEC("fentry/tcp_recvmsg")
int BPF_PROG(fentry_tcp_recvmsg, struct sock *sk) {
    record_thread_read(sk);
    return 0;
}

SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(kprobe_tcp_recvmsg, struct sock *sk) {
    record_thread_read(sk);
    return 0;
}

// BPF has no memcmp: compare the 40 bytes as five words.
static __always_inline int tuple_equal(const struct conn_tuple *a, const struct conn_tuple *b) {
    const __u64 *x = (const __u64 *)a, *y = (const __u64 *)b;
#pragma unroll
    for (int i = 0; i < (int)(sizeof(*a) / sizeof(__u64)); i++) {
        if (x[i] != y[i]) {
            return 0;
        }
    }
    return 1;
}

// Ties connection conn_id of the current process to the socket the current
// thread just read, on a RECV frame. A connection is tied once; a later read
// of another socket before one of its RECV frames is counted, not followed.
static __always_inline void bind_conn(__u64 conn_id) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct thread_read *r = bpf_map_lookup_elem(&java_thread_reads, &pid_tgid);
    if (!r || r->tuple.family == CONN_FAMILY_UNKNOWN ||
        bpf_ktime_get_ns() - r->ts_ns > THREAD_READ_MAX_AGE_NS) {
        return;
    }
    struct java_conn_key k = { .tgid = pid_tgid >> 32, .conn_id = conn_id };
    struct conn_tuple *bound = bpf_map_lookup_elem(&java_conns, &k);
    if (!bound) {
        if (bpf_map_update_elem(&java_conns, &k, &r->tuple, BPF_NOEXIST) == 0) {
            java_counter_inc(JAVA_CTR_CONN_BOUND, 1);
        }
        return;
    }
    if (!tuple_equal(bound, &r->tuple)) {
        java_counter_inc(JAVA_CTR_CONN_MISMATCH, 1);
    }
}

// Copies connection conn_id's addresses into t, or marks them unknown.
static __always_inline void conn_tuple_of(__u32 tgid, __u64 conn_id, struct conn_tuple *t) {
    struct java_conn_key k = { .tgid = tgid, .conn_id = conn_id };
    struct conn_tuple *bound = bpf_map_lookup_elem(&java_conns, &k);
    if (bound) {
        __builtin_memcpy(t, bound, sizeof(*t));
    } else {
        __builtin_memset(t, 0, sizeof(*t));
    }
}

// Emits a HEARTBEAT or CLOSE frame as a control_event. A CLOSE takes a token
// from the sender's rate-cap bucket, like data; a HEARTBEAT (one per JVM every
// 30 s) takes one from its own bucket instead, so a busy agent never looks
// dead.
static __always_inline int emit_control(const struct java_frame_header *h, const __u8 *buf, __u32 netns) {
    java_counter_inc(JAVA_CTR_CONTROL_FRAMES, 1);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u8 kind = EVENT_KIND_JAVA_HEARTBEAT;
    __u64 to_copy = (__u64)h->payload_len & 0xffffffffULL;
    if (h->op == JAVA_FRAME_OP_CLOSE) {
        if (!java_rate_take(pid_tgid >> 32)) {
            java_counter_inc(JAVA_CTR_RATE_CAPPED, 1);
            return 0;
        }
        kind = EVENT_KIND_JAVA_CLOSE;
        to_copy = 0;
    } else if (!bucket_take(&java_heartbeat_buckets, pid_tgid >> 32, HEARTBEAT_BURST, HEARTBEAT_WINDOW_NS)) {
        java_counter_inc(JAVA_CTR_HEARTBEAT_LIMITED, 1);
        return 0;
    }
    if (to_copy > MAX_CONTROL_PAYLOAD) {
        to_copy = MAX_CONTROL_PAYLOAD;
    }

    struct control_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        java_counter_inc(JAVA_CTR_EVENTS_DROPPED, 1);
        return 0;
    }
    e->ts_ns        = bpf_ktime_get_ns();
    e->pid          = pid_tgid >> 32;
    e->tid          = (__u32)pid_tgid;
    e->ssl_ctx      = h->conn_id | JAVA_CONN_ID_TAG;
    e->len_total    = h->payload_len;
    e->len_captured = to_copy;
    e->fd           = -1;
    e->direction    = DIR_EGRESS;         // unused for control events
    e->kind         = kind;
    __builtin_memset(e->_pad, 0, sizeof(e->_pad));
    e->netns        = netns;
    if (kind == EVENT_KIND_JAVA_CLOSE) {
        // The connection is done: its addresses go with the CLOSE.
        conn_tuple_of(pid_tgid >> 32, h->conn_id, &e->tuple);
        struct java_conn_key k = { .tgid = pid_tgid >> 32, .conn_id = h->conn_id };
        bpf_map_delete_elem(&java_conns, &k);
    } else {
        __builtin_memset(&e->tuple, 0, sizeof(e->tuple));
    }
    if (to_copy > 0 &&
        bpf_probe_read_user(e->payload, to_copy, buf + JAVA_FRAME_HEADER_SIZE) != 0) {
        bpf_ringbuf_discard(e, 0);
        java_counter_inc(JAVA_CTR_READ_FAILED, 1);
        return 0;
    }
    bpf_ringbuf_submit(e, 0);
    java_counter_inc(JAVA_CTR_EVENTS_EMITTED, 1);
    return 0;
}

// Validates one frame (buf, count: the whole positional write) and emits its
// payload as an ssl_event, or a control frame as a control_event. The checks
// match javatls.Parse in Go.
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

    // From now on this process's socket reads are recorded.
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    if (!bpf_map_lookup_elem(&java_senders, &tgid)) {
        __u8 one = 1;
        bpf_map_update_elem(&java_senders, &tgid, &one, BPF_ANY);
    }

    __u8 direction;
    if (h.op == JAVA_FRAME_OP_SEND) {
        direction = DIR_EGRESS;
    } else if (h.op == JAVA_FRAME_OP_RECV) {
        direction = DIR_INGRESS;
        // An empty RECV frame (a handshake unwrap) only ties the connection.
        bind_conn(h.conn_id);
    } else {
        return emit_control(&h, buf, netns);
    }
    if (h.payload_len == 0) {
        return 0;
    }

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
    e->fd           = -1;                 // no fd: the kernel fills in tuple
    e->direction    = direction;
    e->kind         = EVENT_KIND_DATA;
    __builtin_memset(e->_pad, 0, sizeof(e->_pad));
    e->netns        = netns;
    conn_tuple_of(pid_tgid >> 32, h.conn_id, &e->tuple);
    if (e->tuple.family == CONN_FAMILY_UNKNOWN) {
        java_counter_inc(JAVA_CTR_CONN_UNBOUND, 1);
    }

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
