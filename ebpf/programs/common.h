// SPDX-License-Identifier: Apache-2.0
//
// Definitions shared by the BPF objects (libssl.bpf.c, java_tls.bpf.c).
//
// The maps below exist once at runtime. The libssl object creates them; the
// loader hands them to the other objects through
// CollectionOptions.MapReplacements, which requires identical definitions in
// every object. Defining them here once guarantees that.
//
// Include after vmlinux.h, the libbpf headers and event.h.

#ifndef __POSTMAN_INSIGHTS_EBPF_COMMON_H__
#define __POSTMAN_INSIGHTS_EBPF_COMMON_H__

// Output ring buffer; cilium/ebpf reads on the Go side. Each event reserves a
// fixed sizeof(struct ssl_event) (~MAX_EVENT_PAYLOAD) regardless of bytes
// copied, so the ring holds ~ (size / sizeof(event)) events. Sized to 8 MiB so
// that with the 16 KiB MAX_EVENT_PAYLOAD we retain ~512 events of headroom -
// the same headroom the original 2 MiB / 4 KiB gave (keep these proportional).
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 23);         // 8 MiB
} events SEC(".maps");

// Per-PID rate-cap token bucket (sampling layer 2; design doc §6.2).
// Userspace refills tokens periodically; the BPF probe decrements one token
// per event and drops the event when the bucket is empty.
//
//   Key:   tgid (__u32)
//   Value: bucket { tokens, _pad }
//
// We use __sync_fetch_and_sub for the atomic decrement so multi-CPU access
// is safe. If a PID isn't in the map (e.g. wasn't refilled yet), default to
// "unlimited" - favours availability over strictness.
struct rate_bucket {
    __u64 tokens;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);                   // tgid
    __type(value, struct rate_bucket);
} pid_rate_buckets SEC(".maps");

// The globals below live in each object's own data section, so the loader
// sets them on every object.

// Userspace-controlled global rate cap. 0 disables rate limiting (default).
// When > 0, userspace refills each known PID's bucket to this value once a
// second.
__u32 rate_cap_per_sec = 0;

// Set from userspace at load time AND can be updated at runtime by the CPU
// thermostat goroutine. Lives in .data (writable post-load). Clamped to
// MAX_EVENT_PAYLOAD at compile time. Power of two recommended.
__u32 max_capture_bytes = MAX_EVENT_PAYLOAD;

static __always_inline int rate_take(__u32 tgid) {
    if (rate_cap_per_sec == 0) {
        return 1;  // disabled - always allow
    }
    struct rate_bucket *b = bpf_map_lookup_elem(&pid_rate_buckets, &tgid);
    if (!b) {
        return 1;  // unknown PID - don't drop; let userspace catch up
    }
    __u64 prev = __sync_fetch_and_sub(&b->tokens, 1);
    // __sync_fetch_and_sub returns the OLD value. If it was 0, our
    // decrement just made it underflow - we should treat that as "no
    // tokens" and reject. Restore by re-adding so the count stays at 0.
    if (prev == 0) {
        __sync_fetch_and_add(&b->tokens, 1);
        return 0;
    }
    return 1;
}

// Network-namespace inode of the calling task. This is the routing key the
// userspace NodeCollector matches against the pod's netns (from
// /proc/<pid>/ns/net). Unlike `pid` (bpf_get_current_pid_tgid returns the
// init-namespace tgid), the netns inode is identical across PID-namespace
// nesting, so routing works even when the agent runs inside a nested node
// container (KIND/k3d/minikube --driver=docker). 0 if it cannot be read.
static __always_inline __u32 current_netns(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    return BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);
}

#endif // __POSTMAN_INSIGHTS_EBPF_COMMON_H__
