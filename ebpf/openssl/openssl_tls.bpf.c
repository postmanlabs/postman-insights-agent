//go:build ignore
// +build ignore

#include "../include/common.h"
#include "../include/bpf_tracing.h"

#define MAX_TLS_DATA 512
#define DIR_WRITE 1
#define DIR_READ  2
#define FLAG_TRUNCATED 1

struct ssl_io_args {
    __u64 ssl_ptr;
    __u64 buf_ptr;
};

struct tls_event {
    __u64 timestamp_ns;
    __u64 ssl_ptr;
    __u32 pid;
    __u32 tid;
    __s32 fd;
    __u32 total_len;
    __u32 data_len;
    __u32 direction;
    __u32 flags;
    __u8  data[MAX_TLS_DATA];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, __u64);
    __type(value, __u32);
} ssl_fd_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, __u64);
    __type(value, struct ssl_io_args);
} pending_write SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, __u64);
    __type(value, struct ssl_io_args);
} pending_read SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} tls_events SEC(".maps");

static __always_inline __u32 get_tid(__u64 pid_tgid) {
    return pid_tgid;
}

static __always_inline __u32 get_pid(__u64 pid_tgid) {
    return pid_tgid >> 32;
}

static __always_inline int emit_event(struct ssl_io_args *args, __s64 captured_len, __u32 direction) {
    if (!args || captured_len <= 0) {
        return 0;
    }

    __u32 copy_len = (__u32)captured_len;
    __u32 flags = 0;
    if (copy_len > MAX_TLS_DATA) {
        copy_len = MAX_TLS_DATA;
        flags |= FLAG_TRUNCATED;
    }

    struct tls_event *event = bpf_ringbuf_reserve(&tls_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = get_pid(pid_tgid);
    event->tid = get_tid(pid_tgid);
    event->ssl_ptr = args->ssl_ptr;
    event->direction = direction;
    event->total_len = (__u32)captured_len;
    event->data_len = copy_len;
    event->flags = flags;

    __u32 *fd = bpf_map_lookup_elem(&ssl_fd_map, &args->ssl_ptr);
    if (fd) {
        event->fd = *(__s32 *)fd;
    } else {
        event->fd = -1;
    }

    if (copy_len > 0) {
        bpf_probe_read_user(event->data, copy_len, (const void *)args->buf_ptr);
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

static __always_inline __u64 tid_key() {
    return bpf_get_current_pid_tgid();
}

SEC("uprobe/SSL_set_fd")
int handle_ssl_set_fd(struct pt_regs *ctx) {
    __u64 ssl = (__u64)PT_REGS_PARM1(ctx);
    __u32 fd = (__u32)PT_REGS_PARM2(ctx);
    bpf_map_update_elem(&ssl_fd_map, &ssl, &fd, BPF_ANY);
    return 0;
}

SEC("uprobe/SSL_free")
int handle_ssl_free(struct pt_regs *ctx) {
    __u64 ssl = (__u64)PT_REGS_PARM1(ctx);
    bpf_map_delete_elem(&ssl_fd_map, &ssl);
    return 0;
}

SEC("uprobe/SSL_write")
int handle_ssl_write_entry(struct pt_regs *ctx) {
    struct ssl_io_args args = {};
    args.ssl_ptr = (__u64)PT_REGS_PARM1(ctx);
    args.buf_ptr = (__u64)PT_REGS_PARM2(ctx);

    __u64 key = tid_key();
    bpf_map_update_elem(&pending_write, &key, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_write")
int handle_ssl_write_exit(struct pt_regs *ctx) {
    __u64 key = tid_key();
    struct ssl_io_args *args = bpf_map_lookup_elem(&pending_write, &key);
    if (!args) {
        return 0;
    }

    __s64 ret = (__s64)PT_REGS_RC(ctx);
    emit_event(args, ret, DIR_WRITE);

    bpf_map_delete_elem(&pending_write, &key);
    return 0;
}

SEC("uprobe/SSL_read")
int handle_ssl_read_entry(struct pt_regs *ctx) {
    struct ssl_io_args args = {};
    args.ssl_ptr = (__u64)PT_REGS_PARM1(ctx);
    args.buf_ptr = (__u64)PT_REGS_PARM2(ctx);

    __u64 key = tid_key();
    bpf_map_update_elem(&pending_read, &key, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read")
int handle_ssl_read_exit(struct pt_regs *ctx) {
    __u64 key = tid_key();
    struct ssl_io_args *args = bpf_map_lookup_elem(&pending_read, &key);
    if (!args) {
        return 0;
    }

    __s64 ret = (__s64)PT_REGS_RC(ctx);
    emit_event(args, ret, DIR_READ);

    bpf_map_delete_elem(&pending_read, &key);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
