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
    __u8  _pad[3];                        // align to 8 bytes
    __u32 netns;                          // network-namespace inode (task->nsproxy->net_ns->ns.inum).
                                          // Routing key: stable across PID namespaces, unlike `pid`,
                                          // so it matches the pod netns discovery filters on even in
                                          // nested environments (KIND/k3d/minikube-docker).
    __u8  payload[MAX_EVENT_PAYLOAD];
};

#endif // __POSTMAN_INSIGHTS_EBPF_EVENT_H__
