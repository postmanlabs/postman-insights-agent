// SPDX-License-Identifier: Apache-2.0
//
// Phase 5a harness — emulates what the Phase 5b Java agent will do via JNI.
//
// We allocate one `java_packet` (1-byte op + 36-byte connection tuple +
// 4-byte length + payload) and call ioctl(0, 0x0b10b1, &packet) twice:
// once with op=SEND carrying a synthetic HTTP request, once with op=RECV
// carrying a synthetic HTTP response. The kernel-side java_tls.bpf.c
// program should emit two ringbuf events, which the agent's apidump-javatls
// command will parse into one REQ and one RESP.
//
// Usage:
//   ./harness                  # one REQ + one RESP
//   ./harness --wrong-cmd      # ioctl(0, 0xDEAD, ...) — kernel should ignore
//   ./harness --burst 100      # 100 REQ/RESP pairs (for stress / counters)
//   ./harness --verbose        # print errno on each ioctl

#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define JAVA_IOCTL_MAGIC 0x0b10b1UL
#define OP_SEND 1
#define OP_RECV 2

// Must match the wire format declared in ebpf/programs/java_tls.bpf.c.
//
//   offset  size  field
//   ------  ----  -----
//        0     1  operation
//        1    16  s_addr (IPv6; IPv4 in first 4 bytes for v4 sockets)
//       17    16  d_addr
//       33     2  s_port (host order — kernel just hashes; semantics are
//                          fixed by the Java agent in phase 5b)
//       35     2  d_port
//       37     4  buf_len
//       41   ...  buffer
//
// We declare the header packed to make the offsets exact.
struct __attribute__((packed)) java_packet_header {
    uint8_t  op;
    uint8_t  s_addr[16];
    uint8_t  d_addr[16];
    uint16_t s_port;
    uint16_t d_port;
    uint32_t buf_len;
};

#define HEADER_SIZE 41
_Static_assert(sizeof(struct java_packet_header) == HEADER_SIZE,
               "java_packet_header must be 41 bytes packed");

// 32 KiB scratch buffer — fits the harness's small synthetic payloads with
// plenty of headroom.
static unsigned char g_scratch[32 * 1024];

static int do_ioctl(unsigned long cmd, uint8_t op,
                    const char *payload, uint32_t payload_len,
                    int verbose) {
    if (HEADER_SIZE + payload_len > sizeof(g_scratch)) {
        fprintf(stderr, "harness: payload too large (%u)\n", payload_len);
        return -1;
    }

    memset(g_scratch, 0, HEADER_SIZE);
    struct java_packet_header *hdr = (struct java_packet_header *)g_scratch;
    hdr->op = op;
    // 127.0.0.1 in v4-mapped slot 0..3
    hdr->s_addr[0] = 127; hdr->s_addr[1] = 0; hdr->s_addr[2] = 0; hdr->s_addr[3] = 1;
    hdr->d_addr[0] = 127; hdr->d_addr[1] = 0; hdr->d_addr[2] = 0; hdr->d_addr[3] = 1;
    hdr->s_port = (op == OP_SEND) ? 54321 : 8443;
    hdr->d_port = (op == OP_SEND) ? 8443  : 54321;
    hdr->buf_len = payload_len;
    memcpy(g_scratch + HEADER_SIZE, payload, payload_len);

    int rc = ioctl(0, cmd, g_scratch);
    if (verbose) {
        fprintf(stderr, "ioctl(0, 0x%lx, ...) = %d (errno=%d %s)\n",
                cmd, rc, errno, strerror(errno));
    }
    // We EXPECT ioctl() to return -1 / ENOTTY (the magic command is not a
    // real ioctl). The kprobe still fires before the kernel rejects the
    // command — that's the whole point of the bridge.
    return 0;
}

static const char *kReq =
    "GET /phase5a HTTP/1.1\r\n"
    "Host: harness.local\r\n"
    "User-Agent: postman-insights-javatls-harness/0.5a\r\n"
    "Accept: */*\r\n"
    "\r\n";

static const char *kResp =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 28\r\n"
    "\r\n"
    "hello-from-phase5a-harness\r\n";

int main(int argc, char **argv) {
    unsigned long cmd = JAVA_IOCTL_MAGIC;
    int burst = 1;
    int verbose = 0;
    int negative_op = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--wrong-cmd")) {
            cmd = 0xDEADUL;          // anything except the magic
        } else if (!strcmp(argv[i], "--burst") && i + 1 < argc) {
            burst = atoi(argv[++i]);
            if (burst < 1) burst = 1;
        } else if (!strcmp(argv[i], "--verbose")) {
            verbose = 1;
        } else if (!strcmp(argv[i], "--bad-op")) {
            // Sends op=99 — kernel should ignore (not SEND, not RECV).
            negative_op = 1;
        } else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            fprintf(stderr,
                "Usage: %s [--wrong-cmd] [--bad-op] [--burst N] [--verbose]\n",
                argv[0]);
            return 0;
        } else {
            fprintf(stderr, "unknown arg: %s\n", argv[i]);
            return 2;
        }
    }

    fprintf(stderr, "harness: pid=%d cmd=0x%lx burst=%d\n",
            getpid(), cmd, burst);

    for (int i = 0; i < burst; i++) {
        if (negative_op) {
            // Single ioctl with an op outside {SEND, RECV}.
            do_ioctl(cmd, /*op=*/99, kReq, (uint32_t)strlen(kReq), verbose);
        } else {
            do_ioctl(cmd, OP_SEND, kReq,  (uint32_t)strlen(kReq),  verbose);
            do_ioctl(cmd, OP_RECV, kResp, (uint32_t)strlen(kResp), verbose);
        }
    }
    fprintf(stderr, "harness: done\n");
    return 0;
}
