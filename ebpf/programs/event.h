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

// Max plaintext bytes copied per event. Sized to fit a typical HTTP
// request/response head (method+path+headers). Bodies beyond this are
// truncated; the full length is preserved in `len_total` for accounting.
//
// Mirrors OBI's FULL_BUF_SIZE (bpf/common/http_info.h). Power of two.
#define MAX_EVENT_PAYLOAD 1024

// A single decrypted-bytes event emitted by an SSL_read or SSL_write
// uretprobe. One TLS record may produce multiple events; the userspace
// adapter reassembles by (pid, tid, ssl_ctx).
struct ssl_event {
    __u64 ts_ns;                          // bpf_ktime_get_ns()
    __u32 pid;                            // tgid (Linux "process id")
    __u32 tid;                            // pid  (Linux "thread id")
    __u64 ssl_ctx;                        // SSL* pointer — opaque connection id
    __u32 len_captured;                   // bytes actually copied to payload[]
    __u32 len_total;                      // total bytes the syscall reported
    __u8  direction;                      // DIR_EGRESS or DIR_INGRESS
    __u8  _pad[7];                        // align to 8 bytes
    __u8  payload[MAX_EVENT_PAYLOAD];
};

#endif // __POSTMAN_INSIGHTS_EBPF_EVENT_H__
