// SPDX-License-Identifier: Apache-2.0
//
// Wire format of the frames the Postman Java agent hands to the kernel.
//
// The agent, running inside a JVM, copies decrypted TLS bytes into a direct
// buffer and issues a positional write to /dev/null at offset
// JAVA_FRAME_MAGIC. The write itself does nothing; java_tls.bpf.c reads the
// buffer on syscall entry. glibc issues pwrite64 for this call, musl issues
// pwritev2 with a single iovec.
//
// This header is one of three copies of the format, which must stay in sync:
//   - ebpf/javatls/frame.go (Go; its tests check this header's constants)
//   - java-agent/src/main/java/com/postman/insights/agent/bootstrap/Frame.java
// Shared example frames live in ebpf/javatls/testdata/frames-v1.json and are
// tested on both the Go and the Java side.
//
// The format is versioned: an agent loaded into a JVM cannot be unloaded, so
// a newer DaemonSet must keep reading older agents' frames until those JVMs
// restart. Never change the meaning of an existing field; add a version.

#ifndef __POSTMAN_INSIGHTS_EBPF_JAVA_FRAME_H__
#define __POSTMAN_INSIGHTS_EBPF_JAVA_FRAME_H__

// Write offset that marks a frame ("PMINSIGH" as a little-endian u64). A
// positive 64-bit value far beyond any real file offset, so no legitimate
// positional write matches it.
#define JAVA_FRAME_MAGIC 0x504D494E53494748ULL

#define JAVA_FRAME_VERSION_1 1

// Bytes before the payload.
#define JAVA_FRAME_HEADER_SIZE 40

// op values.
#define JAVA_FRAME_OP_SEND      1 // plaintext the JVM sent (consumed by SSLEngine.wrap)
#define JAVA_FRAME_OP_RECV      2 // plaintext the JVM received (produced by SSLEngine.unwrap);
                                  // empty at a connection's first unwrap, which ties the
                                  // connection to its socket (java_tls.bpf.c)
#define JAVA_FRAME_OP_HEARTBEAT 3 // agent liveness and status; payload is key=value lines
#define JAVA_FRAME_OP_CLOSE     4 // connection closed; no payload
#define JAVA_FRAME_OP_ADDRESS   5 // the connection's addresses, from the agent; payload below

// An ADDRESS frame's payload: the connection's TCP addresses, which the agent
// knows for a blocking socket (it has the socket), laid out as the kernel's
// struct conn_tuple (event.h):
//    0  u8      family       2 (IPv4) or 10 (IPv6, including IPv4-mapped)
//    1  u8[3]   zero
//    4  u16     local_port   little-endian
//    6  u16     remote_port  little-endian
//    8  u8[16]  local_addr   network byte order; IPv4 in the first 4 bytes, the rest zero
//   24  u8[16]  remote_addr  the same
#define JAVA_FRAME_ADDRESS_SIZE 40

// flags bits.
#define JAVA_FRAME_FLAG_ROLE_KNOWN   0x1  // the client/server role is known
#define JAVA_FRAME_FLAG_CLIENT_MODE  0x2  // the JVM is the TLS client (valid with ROLE_KNOWN)
#define JAVA_FRAME_FLAG_PEER_KNOWN   0x4  // peer_addr and peer_port are set
#define JAVA_FRAME_FLAG_SOCKET       0x8  // a blocking socket's frame: its addresses come in an
                                          // ADDRESS frame, never from the thread's socket reads
#define JAVA_FRAME_FLAG_BEFORE_WRITE 0x10 // SEND: the frame's bytes are written to the
                                          // socket after it, by the thread that sent it
                                          // when the framework writes inline (a wrap)

// Java connection ids are tagged with the top bit when they become an
// ssl_event's ssl_ctx. User-space pointers never set bit 63, so Java ids can
// never collide with real SSL* pointers from the libssl uprobes.
#define JAVA_CONN_ID_TAG (1ULL << 63)

// Multi-byte fields are little-endian, except peer_port (network byte order).
// Every field is naturally aligned, so the struct needs no packing.
struct java_frame_header {
    __u8  version;       // JAVA_FRAME_VERSION_1
    __u8  op;            // JAVA_FRAME_OP_*
    __u16 flags;         // JAVA_FRAME_FLAG_*
    __u32 payload_len;   // payload bytes in this frame
    __u64 conn_id;       // agent-assigned id, unique per connection within the JVM, from a
                         // random start below 2^62, so a reused PID does not reuse ids
    __u8  peer_addr[16]; // IPv6, or IPv4-mapped IPv6; zero when unknown
    __u16 peer_port;     // network byte order; zero when unknown
    __u16 _reserved;     // zero
    __u32 total_len;     // bytes the engine call produced or consumed (>= payload_len)
};

_Static_assert(sizeof(struct java_frame_header) == JAVA_FRAME_HEADER_SIZE,
               "java_frame_header must be JAVA_FRAME_HEADER_SIZE bytes");

#endif // __POSTMAN_INSIGHTS_EBPF_JAVA_FRAME_H__
