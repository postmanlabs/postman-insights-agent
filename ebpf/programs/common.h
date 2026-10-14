// SPDX-License-Identifier: Apache-2.0
//
// Definitions shared by the BPF objects (libssl.bpf.c, java_tls.bpf.c).
//
// The ring buffer below exists once at runtime. The libssl object creates it;
// the loader hands it to the other objects through
// CollectionOptions.MapReplacements, which requires identical definitions in
// every object. Defining it here once guarantees that.
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

// The globals below live in each object's own data section, so the loader
// sets them on every object.

// Userspace-controlled per-PID rate cap, in events per second. 0 disables
// rate limiting (default). libssl.bpf.c enforces it with buckets userspace
// refills every second; java_tls.bpf.c with buckets that refill themselves.
__u32 rate_cap_per_sec = 0;

// Set from userspace at load time AND can be updated at runtime by the CPU
// thermostat goroutine. Lives in .data (writable post-load). Clamped to
// MAX_EVENT_PAYLOAD at compile time. Power of two recommended.
__u32 max_capture_bytes = MAX_EVENT_PAYLOAD;

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
