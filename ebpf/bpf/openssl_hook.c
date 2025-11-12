// eBPF program to hook into OpenSSL SSL_write and SSL_read functions
// This captures plaintext data before encryption (SSL_write) and after decryption (SSL_read)

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Maximum size of data to capture per call
#define MAX_CAPTURE_SIZE 65536

// Event structure sent to user space
struct ssl_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    __u32 fd;
    __u32 is_write;  // 1 for SSL_write, 0 for SSL_read
    __u32 data_len;
    __u8 data[MAX_CAPTURE_SIZE];
};

// Perf event map to send data to user space
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// Map to store context between uprobe and uretprobe for SSL_read
// Key: PID+TID, Value: buffer pointer and size
struct ssl_read_ctx {
    void *buf;
    int num;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);  // PID+TID
    __type(value, struct ssl_read_ctx);
} ssl_read_context SEC(".maps");

// Hook for SSL_write - captures data before encryption
SEC("uprobe/SSL_write")
int uprobe_ssl_write(struct pt_regs *ctx) {
    struct ssl_event event = {};
    
    // Get process and thread IDs
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = (__u32)bpf_get_current_pid_tgid();
    event.timestamp_ns = bpf_ktime_get_ns();
    event.is_write = 1;
    
    // Get function arguments
    // SSL_write(SSL *ssl, const void *buf, int num)
    // Architecture-specific argument extraction
    // x86_64: rdi=ssl, rsi=buf, rdx=num
    // ARM64: x0=ssl, x1=buf, x2=num
    void *buf;
    int num;
    
    // Use architecture-agnostic helpers (PT_REGS_PARM macros handle this)
    buf = (void *)PT_REGS_PARM2(ctx);
    num = (int)PT_REGS_PARM3(ctx);
    
    if (num <= 0 || num > MAX_CAPTURE_SIZE) {
        return 0;
    }
    
    // Get file descriptor from SSL structure (simplified - actual offset may vary)
    // This is a simplified approach; in production, you'd need to read the SSL struct
    event.fd = 0;  // Will be populated from SSL struct if needed
    
    // Copy data from user space
    long ret = bpf_probe_read_user(&event.data, num, buf);
    if (ret < 0) {
        return 0;
    }
    
    event.data_len = num;
    
    // Send event to user space
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

// Hook for SSL_read - stores context for uretprobe
SEC("uprobe/SSL_read")
int uprobe_ssl_read(struct pt_regs *ctx) {
    // SSL_read(SSL *ssl, void *buf, int num)
    void *buf = (void *)PT_REGS_PARM2(ctx);
    int num = (int)PT_REGS_PARM3(ctx);
    
    if (num <= 0 || num > MAX_CAPTURE_SIZE) {
        return 0;
    }
    
    // Store context for uretprobe
    __u64 pid_tid = bpf_get_current_pid_tgid();
    struct ssl_read_ctx ctx_data = {
        .buf = buf,
        .num = num,
    };
    
    bpf_map_update_elem(&ssl_read_context, &pid_tid, &ctx_data, BPF_ANY);
    
    return 0;
}

// Uretprobe for SSL_read - captures data after decryption completes
SEC("uretprobe/SSL_read")
int uretprobe_ssl_read(struct pt_regs *ctx) {
    struct ssl_event event = {};
    
    __u64 pid_tid = bpf_get_current_pid_tgid();
    event.pid = pid_tid >> 32;
    event.tid = (__u32)pid_tid;
    event.timestamp_ns = bpf_ktime_get_ns();
    event.is_write = 0;
    
    // Get return value (number of bytes read)
    long ret_val = PT_REGS_RC(ctx);
    if (ret_val <= 0 || ret_val > MAX_CAPTURE_SIZE) {
        // Clean up context even on error
        bpf_map_delete_elem(&ssl_read_context, &pid_tid);
        return 0;
    }
    
    // Retrieve context stored in uprobe
    struct ssl_read_ctx *ctx_data = bpf_map_lookup_elem(&ssl_read_context, &pid_tid);
    if (!ctx_data) {
        return 0;
    }
    
    // Copy data from buffer (now contains decrypted data)
    void *buf = ctx_data->buf;
    int num = ctx_data->num;
    
    // Use the actual number of bytes read (ret_val) as the length
    int data_len = ret_val < num ? ret_val : num;
    
    long ret = bpf_probe_read_user(&event.data, data_len, buf);
    if (ret < 0) {
        bpf_map_delete_elem(&ssl_read_context, &pid_tid);
        return 0;
    }
    
    event.data_len = data_len;
    event.fd = 0;  // Can be populated from SSL struct if needed
    
    // Clean up context
    bpf_map_delete_elem(&ssl_read_context, &pid_tid);
    
    // Send event to user space
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

// Similar hooks for SSL_write_ex and SSL_read_ex (OpenSSL 1.1.1+)
SEC("uprobe/SSL_write_ex")
int uprobe_ssl_write_ex(struct pt_regs *ctx) {
    // Similar to SSL_write but returns size_t
    return uprobe_ssl_write(ctx);
}

SEC("uretprobe/SSL_read_ex")
int uretprobe_ssl_read_ex(struct pt_regs *ctx) {
    // Similar to SSL_read but returns size_t
    return uretprobe_ssl_read(ctx);
}

char LICENSE[] SEC("license") = "GPL";

