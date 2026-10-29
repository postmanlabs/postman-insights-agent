// SPDX-License-Identifier: Apache-2.0
//
// Shared event format between BPF (kernel) and Go (userspace).
// Keep this file ABI-stable: changes here must be matched in
// ebpf/events/event.go.

#ifndef __POSTMAN_INSIGHTS_EBPF_EVENT_H__
#define __POSTMAN_INSIGHTS_EBPF_EVENT_H__

// Direction of data on the wire from the local process's perspective.
// Matches semantics of akinet.NetTrafficDirection.
#define DIR_EGRESS  0  // data the local process is sending (SSL_write)
#define DIR_INGRESS 1  // data the local process is receiving (SSL_read)

// What an event is. Data events carry plaintext (struct ssl_event). The others
// come from the Java agent's control frames and use struct control_event.
#define EVENT_KIND_DATA           0
#define EVENT_KIND_JAVA_HEARTBEAT 1  // payload: the agent's status, key=value lines
#define EVENT_KIND_JAVA_CLOSE     2  // the connection ssl_ctx closed; no payload

// Max plaintext bytes copied per event. Sized to fit an HTTP
// request/response head plus a typical JSON body. Bodies beyond this are
// truncated; the full length is preserved in `len_total` for accounting.
//
// NOTE: this is also the fixed size reserved in the ring buffer per event
// (bpf_ringbuf_reserve(sizeof(struct ssl_event))), so EVERY event — even a
// tiny healthcheck — costs this many bytes of ring space regardless of how
// many bytes are actually copied. When raising it, raise the `events` ringbuf
// size in libssl.bpf.c proportionally to keep event-count headroom.
//
// Raised 4096 -> 16384: 4 KiB truncated common ~11-12 KiB JSON list responses
// (see len_total >> len_captured in traces). 16 KiB covers those with headroom
// while keeping per-event copy cost bounded (the runtime max_capture_bytes knob
// + CPU thermostat still throttle actual copies under load). Power of two.
#define MAX_EVENT_PAYLOAD 16384

// A TCP connection's addresses, as the kernel's socket has them. Java events
// carry it (the Java agent sees engines, not sockets: the kernel ties each
// Java connection to the socket its thread read from, see java_tls.bpf.c).
// libssl events leave it unknown and are resolved from fd in userspace.
#define CONN_FAMILY_UNKNOWN 0
#define CONN_FAMILY_INET    2   // AF_INET: addresses in the first 4 bytes
#define CONN_FAMILY_INET6   10  // AF_INET6, including IPv4-mapped addresses

struct conn_tuple {
    __u8  family;                         // CONN_FAMILY_*
    __u8  _pad[3];
    __u16 local_port;                     // host byte order
    __u16 remote_port;                    // host byte order
    __u8  local_addr[16];                 // network byte order
    __u8  remote_addr[16];                // network byte order
};

// A single decrypted-bytes event emitted by an SSL_read or SSL_write
// uretprobe. One TLS record may produce multiple events; the userspace
// adapter reassembles by (pid, tid, ssl_ctx).
//
// fd is set from the ssl_ctx → fd map (populated by the SSL_set_fd uprobe).
// 0 means "unknown" — the userspace resolver should fall back to leaving
// SrcIP/DstIP zero.
struct ssl_event {
    __u64 ts_ns;                          // bpf_ktime_get_ns()
    __u32 pid;                            // tgid (Linux "process id")
    __u32 tid;                            // pid  (Linux "thread id")
    __u64 ssl_ctx;                        // SSL* pointer — opaque connection id
    __u32 len_captured;                   // bytes actually copied to payload[]
    __u32 len_total;                      // total bytes the syscall reported
    __s32 fd;                             // socket fd associated with ssl_ctx, or -1
    __u8  direction;                      // DIR_EGRESS or DIR_INGRESS
    __u8  kind;                           // EVENT_KIND_*
    __u8  _pad[2];                        // align to 8 bytes
    __u32 netns;                          // network-namespace inode (task->nsproxy->net_ns->ns.inum).
                                          // Routing key: stable across PID namespaces, unlike `pid`,
                                          // so it matches the pod netns discovery filters on even in
                                          // nested environments (KIND/k3d/minikube-docker).
    struct conn_tuple tuple;              // the connection's addresses, when the kernel knows them
    __u8  payload[MAX_EVENT_PAYLOAD];
};

// Max payload bytes of a control event: a HEARTBEAT's status lines (a few
// hundred bytes).
#define MAX_CONTROL_PAYLOAD 1024

// A control event (kind other than EVENT_KIND_DATA): struct ssl_event with a
// small payload, so each one reserves about 1 KiB of the ring buffer rather
// than 16 KiB. The fields before payload are identical; userspace reads the
// kind, then only len_captured payload bytes.
struct control_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 tid;
    __u64 ssl_ctx;
    __u32 len_captured;
    __u32 len_total;
    __s32 fd;
    __u8  direction;
    __u8  kind;
    __u8  _pad[2];
    __u32 netns;
    struct conn_tuple tuple;
    __u8  payload[MAX_CONTROL_PAYLOAD];
};

_Static_assert(__builtin_offsetof(struct control_event, payload) ==
               __builtin_offsetof(struct ssl_event, payload),
               "control_event must match ssl_event up to payload");
_Static_assert(__builtin_offsetof(struct control_event, kind) ==
               __builtin_offsetof(struct ssl_event, kind),
               "control_event must have ssl_event's kind offset");
_Static_assert(__builtin_offsetof(struct control_event, tuple) ==
               __builtin_offsetof(struct ssl_event, tuple),
               "control_event must have ssl_event's tuple offset");
_Static_assert(sizeof(struct conn_tuple) == 40, "conn_tuple is 40 bytes");

#endif // __POSTMAN_INSIGHTS_EBPF_EVENT_H__
