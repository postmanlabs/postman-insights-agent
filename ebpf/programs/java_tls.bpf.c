// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
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
//          and, where the kernel rejects RWF_NOAPPEND (before 6.9), pwrite64
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

char LICENSE[] SEC("license") = "Dual BSD/GPL"; // GPL-compatible: required for some BPF helpers

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
#define JAVA_CTR_CONN_BOUND        10 // connections tied to their socket (or given their addresses)
#define JAVA_CTR_CONN_UNBOUND      11 // data frames of connections not tied to a socket
#define JAVA_CTR_CONN_HANDOFF      12 // RECV frames of a tied connection on a thread that last read another socket
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

// Set from userspace at load time: 1 when this kernel rejects pwritev2's
// RWF_NOAPPEND flag (it was added in Linux 6.9). musl's pwrite() first tries
// pwritev2 with RWF_NOAPPEND and, when the kernel fails it with EOPNOTSUPP,
// writes again with pwrite64. The syscall tracepoints see both calls, so on
// such a kernel the failing pwritev2 is skipped and the pwrite64 carries the
// frame; otherwise every frame of a musl JVM would be read twice.
volatile const __u32 pwritev2_noappend_rejected = 0;
#define RWF_NOAPPEND_FLAG 0x00000020  // RWF_NOAPPEND, include/uapi/linux/fs.h

// ---------------------------------------------------------------------------
// Connection addresses
//
// Every event of a connection carries its addresses, from java_conns, which
// gets them in one of two ways.
//
// A blocking socket's (the JDK's SSLSocket): the agent has the socket, so it
// sends its addresses in an ADDRESS frame before the connection's first data
// frame. Its frames are marked JAVA_FRAME_FLAG_SOCKET and are never tied by
// the thread's reads below: a socket read can return plaintext that an
// earlier read already decrypted, without reading the socket.
//
// An SSLEngine's: the agent sees engines, not sockets. The servers and
// clients we capture unwrap a connection's handshake on the thread that read
// it (Tomcat NIO, Netty, Jetty, Undertow): so the socket a thread read from
// just before a connection's first RECV frame is the connection's.
// tcp_recvmsg records, for the threads of processes that send frames, the
// addresses of the socket each last read bytes from; a connection's first
// RECV frame ties it to them, and every event of the connection then carries
// them. The agent sends an empty RECV frame at a connection's first unwrap
// that consumed TLS bytes, during the handshake, so the tie exists before the
// first request or response, whichever side sends first. Later records may
// be unwrapped on another thread than the one that read them: Tomcat reads a
// segment with the handshake's last flight and the first request on one
// worker thread, finishes the handshake, and unwraps the request on another.
// That changes nothing, as a connection is tied once.
//
// Some clients read on one thread and unwrap on another (the JDK's
// HttpClient: its selector thread reads, a worker unwraps), but write the
// socket on the thread that wrapped. So a SEND frame whose bytes are yet to be
// written (JAVA_FRAME_FLAG_BEFORE_WRITE: a wrap) of a connection not yet tied
// leaves the connection pending on its thread, and the thread's next socket
// write (tcp_sendmsg) ties it; another connection's wrap before that write
// makes it ambiguous (see struct thread_send).
// The agent also sends an empty SEND frame at every wrap that produced bytes
// to write without plaintext (the handshake's), so every wrap announces its
// write.
//
// When a thread did not read a socket just before (an engine unwrapped on
// another thread than the one that read), nor write one just after a SEND,
// the connection stays untied, and its events carry no addresses rather than
// wrong ones. Two cases are tied wrongly, and cannot be told apart here: an
// engine unwrapped on a thread that read another TCP socket (a database's, a
// downstream call's) within THREAD_READ_MAX_AGE_NS, and not its own, is tied
// to that socket; and a wrap of a connection not yet tied is tied to the
// socket the wrapping thread writes next within THREAD_SEND_MAX_AGE_NS (with
// no other connection's wrap in between), which is another socket when
// another thread writes the wrap's bytes, or the thread first writes another
// connection's leftover bytes. RECV frames of a tied connection on a thread
// whose last read was another socket's are counted (JAVA_CTR_CONN_HANDOFF):
// records another thread read, as Tomcat's later ones, or a wrong tie. It
// shows how often a server unwraps on another thread than the one that read,
// not how many ties are wrong.
// ---------------------------------------------------------------------------

// Processes that sent a valid frame: only their socket reads are recorded,
// so every other process's tcp_recvmsg costs one lookup.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);                   // tgid
    __type(value, __u8);
} java_senders SEC(".maps");

// The socket a thread of a java_senders process last read bytes from, and
// when that read returned (a blocking read can wait long before the data that
// its RECV frame decrypts arrives). A read that returned none (EAGAIN from a
// non-blocking read, the end of the stream, an error) read nothing to
// decrypt, so it changes nothing: it is not the socket of what the thread
// unwraps next, and the read before it may be (Tomcat reads again, and gets
// EAGAIN, before unwrapping bytes an earlier read buffered). With kprobes,
// reading_sk holds the socket of the read in progress until it returns.
struct thread_read {
    __u64 ts_ns;
    __u64 reading_sk;
    struct conn_tuple tuple;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);                   // pid_tgid
    __type(value, struct thread_read);
} java_thread_reads SEC(".maps");

// Connections tied to their socket's addresses. Removed on CLOSE; LRU for
// connections that end without one. The process's start time is part of the
// key: connection ids restart at 1 in every JVM, and a reused PID must not
// inherit a dead JVM's connections.
struct java_conn_key {
    __u32 tgid;
    __u32 _pad;
    __u64 start_ns;                       // the process's start time (group leader's start_time)
    __u64 conn_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct java_conn_key);
    __type(value, struct conn_tuple);
} java_conns SEC(".maps");

// How recent a thread's read must be to tie a RECV frame to its socket: an
// unwrap follows the read it decrypts within microseconds of the read
// returning, but a GC pause can come in between.
#define THREAD_READ_MAX_AGE_NS (50ULL * 1000 * 1000)

// Whose bytes a thread's next socket write carries, as its SEND frames
// announce them (JAVA_FRAME_FLAG_BEFORE_WRITE: a wrap, written after the
// frame): the write, within THREAD_SEND_MAX_AGE_NS of the last announcement,
// ties that connection if it is not tied yet. When announcements of two
// connections are outstanding (a thread that wraps for several connections,
// then writes them), the next write could be either's: the entry is then
// ambiguous, every later SEND frame keeps it so, and it only expires, so a
// write cannot end it and leave a later announcement to tie to the wrong
// write. The window is shorter than for reads: a frame whose bytes another
// thread writes must not tie to this thread's next, unrelated write.
// A connection tied when it announced its write is not tied by it: so one
// that closes on another thread before the write (Tomcat's workers) is not
// tied again, to the socket of whatever the thread writes next.
struct thread_send {
    __u64 ts_ns;                          // the last SEND frame
    __u64 conn_id;                        // whose write is next, unless ambiguous
    __u8  ambiguous;
    __u8  tied;                           // conn_id was tied at its SEND frame
    __u8  _pad[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);                   // pid_tgid
    __type(value, struct thread_send);
} java_thread_sends SEC(".maps");

#define THREAD_SEND_MAX_AGE_NS (10ULL * 1000 * 1000)

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

// The current thread's read record, when it belongs to a java_senders process.
static __always_inline struct thread_read *thread_read_of(__u64 pid_tgid) {
    __u32 tgid = pid_tgid >> 32;
    if (!bpf_map_lookup_elem(&java_senders, &tgid)) {
        return 0;
    }
    return bpf_map_lookup_elem(&java_thread_reads, &pid_tgid);
}

// Records sk as the socket the current thread last read bytes from, now.
static __always_inline void record_thread_read(struct sock *sk) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    if (!bpf_map_lookup_elem(&java_senders, &tgid)) {
        return;
    }
    __u64 now = bpf_ktime_get_ns();
    // A thread's entry is rewritten in place: an LRU update on every read
    // would cost several times the rest.
    struct thread_read *r = bpf_map_lookup_elem(&java_thread_reads, &pid_tgid);
    if (r) {
        sock_tuple(sk, &r->tuple);
        r->ts_ns = now;
        return;
    }
    struct thread_read fresh = { .ts_ns = now };
    sock_tuple(sk, &fresh.tuple);
    bpf_map_update_elem(&java_thread_reads, &pid_tgid, &fresh, BPF_ANY);
}

// The read counts when it returns, and only when it returned bytes: fexit
// where the kernel supports BPF trampolines (x86_64 5.5+, arm64 6.0+); else
// kprobe, which remembers the socket, and kretprobe, which records it. An
// fexit program reads the return value after the arguments, whose number has
// changed (Linux 5.19 removed nonblock, a later kernel addr_len), so there is
// one program per number of arguments. The loader picks from the kernel's
// BTF. Only the first argument and the return value are used.

// int tcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags);
SEC("fexit/tcp_recvmsg")
int BPF_PROG(fexit_tcp_recvmsg4, struct sock *sk, struct msghdr *msg, size_t len, int flags, int ret) {
    if (ret > 0) {
        record_thread_read(sk);
    }
    return 0;
}

// int tcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags,
//                 int *addr_len);                               (Linux 5.19+)
SEC("fexit/tcp_recvmsg")
int BPF_PROG(fexit_tcp_recvmsg5, struct sock *sk, struct msghdr *msg, size_t len, int flags,
             int *addr_len, int ret) {
    if (ret > 0) {
        record_thread_read(sk);
    }
    return 0;
}

// int tcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
//                 int flags, int *addr_len);                    (before Linux 5.19)
SEC("fexit/tcp_recvmsg")
int BPF_PROG(fexit_tcp_recvmsg6, struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
             int flags, int *addr_len, int ret) {
    if (ret > 0) {
        record_thread_read(sk);
    }
    return 0;
}

SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(kprobe_tcp_recvmsg, struct sock *sk) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    if (!bpf_map_lookup_elem(&java_senders, &tgid)) {
        return 0;
    }
    struct thread_read *r = bpf_map_lookup_elem(&java_thread_reads, &pid_tgid);
    if (r) {
        // A read still marked in progress had its return missed: the record
        // is the read before it, which may not be the socket the thread
        // unwraps next, so it is no longer evidence, whatever this read
        // returns. A read that returns bytes records its socket again.
        if (r->reading_sk) {
            r->ts_ns = 0;
        }
        r->reading_sk = (__u64)sk;
        return 0;
    }
    struct thread_read fresh = { .reading_sk = (__u64)sk };
    bpf_map_update_elem(&java_thread_reads, &pid_tgid, &fresh, BPF_ANY);
    return 0;
}

// The socket stays referenced by the read until it returns, so the kprobe's
// pointer is still the read's socket here.
SEC("kretprobe/tcp_recvmsg")
int BPF_KRETPROBE(kretprobe_tcp_recvmsg, int ret) {
    struct thread_read *r = thread_read_of(bpf_get_current_pid_tgid());
    if (!r || !r->reading_sk) {
        return 0;
    }
    if (ret > 0) {
        sock_tuple((struct sock *)r->reading_sk, &r->tuple);
        r->ts_ns = bpf_ktime_get_ns();
    }
    r->reading_sk = 0;
    return 0;
}

// The key of the current process's connection conn_id.
static __always_inline struct java_conn_key current_conn_key(__u64 conn_id) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct java_conn_key k = {
        .tgid     = bpf_get_current_pid_tgid() >> 32,
        .start_ns = BPF_CORE_READ(task, group_leader, start_time),
        .conn_id  = conn_id,
    };
    return k;
}

// Ties the connection the current thread just wrapped for, if any, to sk.
static __always_inline void record_thread_send(struct sock *sk) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    if (!bpf_map_lookup_elem(&java_senders, &tgid)) {
        return;
    }
    struct thread_send *p = bpf_map_lookup_elem(&java_thread_sends, &pid_tgid);
    if (!p) {
        return;
    }
    __u64 age = bpf_ktime_get_ns() - p->ts_ns;
    if (age <= THREAD_SEND_MAX_AGE_NS && p->ambiguous) {
        return;                           // ends only by expiring
    }
    __u64 conn_id = p->conn_id;
    __u8 tied = p->tied;
    bpf_map_delete_elem(&java_thread_sends, &pid_tgid);
    if (age > THREAD_SEND_MAX_AGE_NS || tied) {
        return;
    }
    struct conn_tuple t;
    sock_tuple(sk, &t);
    if (t.family == CONN_FAMILY_UNKNOWN) {
        return;
    }
    struct java_conn_key k = current_conn_key(conn_id);
    if (bpf_map_update_elem(&java_conns, &k, &t, BPF_NOEXIST) == 0) {
        java_counter_inc(JAVA_CTR_CONN_BOUND, 1);
    }
}

// int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size);
// The write counts when it starts: the bytes are this thread's to write.
SEC("fentry/tcp_sendmsg")
int BPF_PROG(fentry_tcp_sendmsg, struct sock *sk) {
    record_thread_send(sk);
    return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(kprobe_tcp_sendmsg, struct sock *sk) {
    record_thread_send(sk);
    return 0;
}

// On a SEND frame of connection conn_id: one whose bytes are yet to be
// written (JAVA_FRAME_FLAG_BEFORE_WRITE) announces the thread's next write
// as the connection's, tied or not (a tied one's write must not tie another
// that announces after it, nor itself again once closed). A second
// connection's announcement before that write makes the entry ambiguous (see
// struct thread_send). A SEND frame whose bytes were written already
// announces nothing.
static __always_inline void pend_conn(__u64 conn_id, __u16 flags) {
    if (!(flags & JAVA_FRAME_FLAG_BEFORE_WRITE)) {
        return;
    }
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 now = bpf_ktime_get_ns();
    struct java_conn_key k = current_conn_key(conn_id);
    __u8 tied = bpf_map_lookup_elem(&java_conns, &k) != 0;
    struct thread_send *w = bpf_map_lookup_elem(&java_thread_sends, &pid_tgid);
    if (w) {
        if (now - w->ts_ns <= THREAD_SEND_MAX_AGE_NS && (w->ambiguous || w->conn_id != conn_id)) {
            w->ambiguous = 1;
        } else {
            w->conn_id = conn_id;
            w->ambiguous = 0;
            w->tied = tied;
        }
        w->ts_ns = now;
        return;
    }
    struct thread_send p = { .ts_ns = now, .conn_id = conn_id, .tied = tied };
    bpf_map_update_elem(&java_thread_sends, &pid_tgid, &p, BPF_ANY);
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
// thread just read, on a RECV frame. A connection is tied once; a later RECV
// frame after a read of another socket is counted, not followed (see
// JAVA_CTR_CONN_HANDOFF).
//
// With kprobes, a read whose kretprobe was missed (the kernel's limit of
// concurrent instances reached) leaves reading_sk set: the record is the read
// before it, of another socket maybe, so nothing ties until the next read
// returns. A frame always follows its read's return, so reading_sk is
// otherwise 0 here.
static __always_inline void bind_conn(__u64 conn_id) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct thread_read *r = bpf_map_lookup_elem(&java_thread_reads, &pid_tgid);
    if (!r || r->tuple.family == CONN_FAMILY_UNKNOWN || r->ts_ns == 0 || r->reading_sk != 0 ||
        bpf_ktime_get_ns() - r->ts_ns > THREAD_READ_MAX_AGE_NS) {
        return;
    }
    struct java_conn_key k = current_conn_key(conn_id);
    struct conn_tuple *bound = bpf_map_lookup_elem(&java_conns, &k);
    if (!bound) {
        if (bpf_map_update_elem(&java_conns, &k, &r->tuple, BPF_NOEXIST) == 0) {
            java_counter_inc(JAVA_CTR_CONN_BOUND, 1);
        }
        return;
    }
    if (!tuple_equal(bound, &r->tuple)) {
        java_counter_inc(JAVA_CTR_CONN_HANDOFF, 1);
    }
}

// Gives connection conn_id of the current process the addresses an ADDRESS
// frame carries (a blocking socket's, which the agent has). They replace any
// the connection had. The kernel trusts them as it trusts the plaintext: a
// process can misdescribe only its own connections, whose pod the kernel
// stamps itself. The agent sends one again every heartbeat interval while
// the connection is in use, so one dropped here, or forgotten (LRU eviction,
// an Insights agent restart), comes back. Like a data frame, the frame takes a token from the
// sender's rate-cap bucket: it is the one frame that adds to java_conns
// without a socket read.
static __always_inline int set_conn_address(const struct java_frame_header *h, const __u8 *buf) {
    struct conn_tuple t;
    if (h->payload_len != JAVA_FRAME_ADDRESS_SIZE) {
        java_counter_inc(JAVA_CTR_MALFORMED, 1);
        return 0;
    }
    if (bpf_probe_read_user(&t, sizeof(t), buf + JAVA_FRAME_HEADER_SIZE) != 0) {
        java_counter_inc(JAVA_CTR_READ_FAILED, 1);
        return 0;
    }
    const __u32 *local = (const __u32 *)t.local_addr, *remote = (const __u32 *)t.remote_addr;
    if ((t.family != CONN_FAMILY_INET && t.family != CONN_FAMILY_INET6) ||
        t._pad[0] != 0 || t._pad[1] != 0 || t._pad[2] != 0 ||
        (t.family == CONN_FAMILY_INET &&
         (local[1] | local[2] | local[3] | remote[1] | remote[2] | remote[3]) != 0)) {
        java_counter_inc(JAVA_CTR_MALFORMED, 1);
        return 0;
    }
    if (!java_rate_take(bpf_get_current_pid_tgid() >> 32)) {
        java_counter_inc(JAVA_CTR_RATE_CAPPED, 1);
        return 0;
    }
    struct java_conn_key k = current_conn_key(h->conn_id);
    if (bpf_map_update_elem(&java_conns, &k, &t, BPF_ANY) == 0) {
        java_counter_inc(JAVA_CTR_CONN_BOUND, 1);
    }
    return 0;
}

_Static_assert(sizeof(struct conn_tuple) == JAVA_FRAME_ADDRESS_SIZE,
               "an ADDRESS frame's payload is a struct conn_tuple");

// Copies the current process's connection conn_id's addresses into t, or
// marks them unknown.
static __always_inline void conn_tuple_of(__u64 conn_id, struct conn_tuple *t) {
    struct java_conn_key k = current_conn_key(conn_id);
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
    // A CLOSE forgets its connection whether or not its event goes out, so
    // a dropped CLOSE leaves no stale tie taking up java_conns; the event, if
    // any, carries the addresses. It also ends the connection's wait for the
    // thread's next write: a wrap that produced the close_notify and
    // returned CLOSED sends its SEND frame and the CLOSE before the write,
    // which must not tie the closed connection again.
    struct conn_tuple closed_tuple;
    __builtin_memset(&closed_tuple, 0, sizeof(closed_tuple));
    if (h->op == JAVA_FRAME_OP_CLOSE) {
        conn_tuple_of(h->conn_id, &closed_tuple);
        struct java_conn_key k = current_conn_key(h->conn_id);
        bpf_map_delete_elem(&java_conns, &k);
        struct thread_send *p = bpf_map_lookup_elem(&java_thread_sends, &pid_tgid);
        if (p && !p->ambiguous && p->conn_id == h->conn_id) {
            bpf_map_delete_elem(&java_thread_sends, &pid_tgid);
        }
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
    __builtin_memcpy(&e->tuple, &closed_tuple, sizeof(e->tuple));
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
// payload as an ssl_event, or a control frame as a control_event, or applies
// an ADDRESS frame. The checks match javatls.Parse in Go.
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
        h.op < JAVA_FRAME_OP_SEND || h.op > JAVA_FRAME_OP_ADDRESS ||
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
        // An empty SEND frame (a handshake wrap) only announces the thread's
        // next socket write.
        pend_conn(h.conn_id, h.flags);
    } else if (h.op == JAVA_FRAME_OP_RECV) {
        direction = DIR_INGRESS;
        // An empty RECV frame (a handshake unwrap) only ties the connection.
        // A socket's come with an ADDRESS frame instead.
        if (!(h.flags & JAVA_FRAME_FLAG_SOCKET)) {
            bind_conn(h.conn_id);
        }
    } else if (h.op == JAVA_FRAME_OP_ADDRESS) {
        return set_conn_address(&h, buf);
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
    conn_tuple_of(h.conn_id, &e->tuple);
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
// musl implements pwrite() with this, with RWF_NOAPPEND, and falls back to
// pwrite64 where the kernel rejects the flag (pwritev2_noappend_rejected).
SEC("tracepoint/syscalls/sys_enter_pwritev2")
int tp_sys_enter_pwritev2(struct trace_event_raw_sys_enter *ctx) {
    if (pwritev2_noappend_rejected && ((__u64)ctx->args[5] & RWF_NOAPPEND_FLAG)) {
        return 0;
    }
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
