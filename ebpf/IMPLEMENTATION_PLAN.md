# HTTPS Traffic Capture Implementation Plan

## Overview

This document outlines the changes needed to add HTTPS traffic capturing support to the Postman Insights Agent using eBPF uprobes, similar to how Pixie does it.

## Current Architecture

The agent currently uses **libpcap** to capture packets at the network interface level:
- Captures raw TCP packets
- Reassembles TCP streams
- Parses HTTP/HTTP2 from plaintext TCP
- Cannot decrypt HTTPS traffic (only sees encrypted payload)

## Proposed Architecture

Add **eBPF uprobes** to intercept plaintext data at the application level:
- Hook into TLS library functions (OpenSSL, GnuTLS, BoringSSL)
- Capture data **before encryption** (SSL_write) and **after decryption** (SSL_read)
- Feed plaintext data into existing HTTP parsing pipeline

## Required Changes

### 1. Dependencies

Add to `go.mod`:
```bash
go get github.com/cilium/ebpf
go get github.com/cilium/ebpf/cmd/bpf2go
```

### 2. eBPF Program Compilation

The eBPF C program (`openssl_hook.c`) needs to be compiled:

```bash
# Compile eBPF program
clang -target bpf -O2 -g -c ebpf/openssl_hook.c -o ebpf/openssl_hook.o

# Generate Go bindings (requires bpf2go)
go generate ./ebpf
```

Create `ebpf/bpf2go.go`:
```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang openssl_hook ebpf/openssl_hook.c
```

### 3. eBPF Program Improvements

The current `openssl_hook.c` is a skeleton. It needs:

1. **Proper argument extraction** for different architectures (x86_64, ARM64)
2. **SSL structure parsing** to extract file descriptors and connection info
3. **Context storage** between uprobe and uretprobe for SSL_read
4. **Support for multiple OpenSSL versions** (different struct layouts)
5. **Error handling** for edge cases

Key improvements needed:
- Use eBPF maps to store context between uprobe/uretprobe pairs
- Read SSL structure to get file descriptor
- Handle variable-length data correctly
- Support SSL_write_ex and SSL_read_ex (OpenSSL 1.1.1+)

### 4. Go Implementation Completion

Complete the implementation in `ebpf/loader.go`:

1. **Load compiled eBPF programs** using bpf2go-generated bindings
2. **Attach uprobes** to discovered processes
3. **Process perf events** from the ring buffer
4. **Parse HTTP** from captured plaintext data
5. **Resolve connection info** from file descriptors

### 5. Process Discovery

Implement process discovery to find applications using TLS:

- Scan `/proc/*/maps` for libssl.so, libgnutls.so, etc.
- Track process lifecycle (attach to new processes)
- Handle containerized environments (different PID namespaces)

### 6. Integration with Existing Pipeline

Modify `apidump/apidump.go` to optionally enable HTTPS capture:

```go
if args.EnableHTTPSCapture {
    go func() {
        errChan <- ebpf.CollectHTTPS(
            args.ServiceID,
            traceTags,
            stop,
            collector,
            apidumpTelemetry,
        )
    }()
}
```

### 7. CLI Flags

Add to `cmd/internal/apidump/common_flags.go`:

```go
EnableHTTPSCapture bool // --enable-https-capture
```

## Implementation Steps

### Phase 1: Basic eBPF Infrastructure
- [x] Create eBPF program skeleton
- [x] Create Go loader structure
- [ ] Compile eBPF program successfully
- [ ] Load eBPF program into kernel
- [ ] Test basic uprobe attachment

### Phase 2: Data Capture
- [ ] Capture data from SSL_write
- [ ] Capture data from SSL_read (using uretprobe)
- [ ] Handle perf event ring buffer
- [ ] Parse SSLEvent structures

### Phase 3: Connection Tracking
- [ ] Extract file descriptor from SSL structure
- [ ] Resolve connection info from /proc
- [ ] Map SSL events to network connections
- [ ] Handle connection lifecycle

### Phase 4: HTTP Parsing
- [ ] Parse plaintext data as HTTP
- [ ] Use existing HTTP parser factories
- [ ] Handle HTTP/1.1 and HTTP/2
- [ ] Match requests and responses

### Phase 5: Process Discovery
- [ ] Scan for TLS-using processes
- [ ] Attach to discovered processes
- [ ] Handle process lifecycle events
- [ ] Support containerized environments

### Phase 6: Integration
- [ ] Add CLI flags
- [ ] Integrate with apidump flow
- [ ] Merge with pcap-based capture
- [ ] Handle errors gracefully

### Phase 7: Testing & Documentation
- [ ] Test with various TLS libraries
- [ ] Test with different OpenSSL versions
- [ ] Performance testing
- [ ] Security review
- [ ] Documentation

## Technical Challenges

### 1. SSL Structure Layout
Different OpenSSL versions have different struct layouts. Solutions:
- Use multiple eBPF programs for different versions
- Use BTF (BPF Type Format) if available
- Probe struct offsets at runtime

### 2. Context Between Uprobe/Uretprobe
For SSL_read, we need the buffer pointer from the uprobe in the uretprobe. Solution:
- Use eBPF maps to store context (PID+TID as key)
- Store buffer pointer and size
- Clean up map entries after processing

### 3. Multi-threaded Applications
Multiple threads may use the same SSL connection. Solution:
- Use PID+TID as unique identifier
- Track per-thread context

### 4. Performance
eBPF uprobes have overhead. Solutions:
- Filter at eBPF level (only capture HTTP traffic)
- Use sampling if needed
- Optimize data copying

### 5. Security & Privacy
Capturing plaintext HTTPS requires careful handling:
- Require explicit opt-in
- Log access and usage
- Ensure secure data handling
- Comply with regulations

## Alternative Approaches

### 1. Use Existing Tools
- **eCapture**: Open-source tool that does this
- Could integrate or learn from their approach

### 2. Kernel TLS (kTLS) Offload
If applications use kTLS, could hook at kernel level instead

### 3. Library Interposition
Use LD_PRELOAD to intercept TLS calls (simpler but less portable)

## References

- [Pixie eBPF Documentation](https://docs.px.dev/about-pixie/pixie-ebpf/)
- [eCapture Project](https://github.com/gojue/ecapture)
- [Cilium eBPF Go Library](https://github.com/cilium/ebpf)
- [Linux eBPF Uprobes](https://www.kernel.org/doc/html/latest/trace/uprobetracer.html)

## Next Steps

1. **Research**: Study eCapture and Pixie implementations in detail
2. **Prototype**: Get basic SSL_write capture working
3. **Iterate**: Add SSL_read, connection tracking, HTTP parsing
4. **Test**: Validate with real applications
5. **Integrate**: Merge with existing pipeline
6. **Document**: Complete user documentation

