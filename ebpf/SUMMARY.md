# HTTPS Traffic Capture - Implementation Summary

## What Has Been Created

This implementation provides the foundation for adding HTTPS traffic capture support to the Postman Insights Agent using eBPF uprobes, similar to Pixie's approach.

### Files Created

1. **`ebpf/README.md`** - Overview and usage documentation
2. **`ebpf/openssl_hook.c`** - eBPF program skeleton for hooking into OpenSSL functions
3. **`ebpf/loader.go`** - Go code structure for loading and managing eBPF programs
4. **`ebpf/integration.go`** - Integration code showing how to connect with existing pipeline
5. **`ebpf/IMPLEMENTATION_PLAN.md`** - Detailed implementation plan and technical challenges
6. **`ebpf/SUMMARY.md`** - This file

### Code Changes

1. **`cmd/internal/apidump/common_flags.go`** - Added `--enable-https-capture` flag

## Current Status

### ✅ Completed

- Directory structure and base components
- eBPF program skeleton (C code)
- Go loader structure with placeholders
- Integration points identified
- CLI flag added
- Documentation created

### ⚠️ Requires Implementation

The current code is a **skeleton/placeholder** that shows the architecture. To make it functional, you need to:

1. **Add Dependencies**
   ```bash
   go get github.com/cilium/ebpf
   go get github.com/cilium/ebpf/cmd/bpf2go
   ```

2. **Compile eBPF Program**
   ```bash
   clang -target bpf -O2 -g -c ebpf/openssl_hook.c -o ebpf/openssl_hook.o
   ```

3. **Generate Go Bindings**
   Create `ebpf/bpf2go.go`:
   ```go
   //go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang openssl_hook ebpf/openssl_hook.c
   ```
   Then run: `go generate ./ebpf`

4. **Complete eBPF Program**
   - Fix argument extraction for different architectures
   - Add SSL structure parsing
   - Implement context storage between uprobe/uretprobe
   - Handle multiple OpenSSL versions

5. **Complete Go Implementation**
   - Implement actual eBPF loading in `loader.go`
   - Add process discovery
   - Implement connection tracking
   - Parse HTTP from captured plaintext

6. **Integrate with apidump**
   - Add HTTPS capture to `apidump/apidump.go` Run() function
   - Handle the `EnableHTTPSCapture` flag

## How It Works (When Complete)

1. **Discovery**: Agent scans running processes to find those using TLS libraries (libssl.so, etc.)

2. **Attachment**: eBPF uprobes are attached to:
   - `SSL_write` / `SSL_write_ex` - captures data before encryption
   - `SSL_read` / `SSL_read_ex` - captures data after decryption (via uretprobe)

3. **Capture**: When applications call these functions, eBPF programs:
   - Extract the plaintext data buffer
   - Get process/thread IDs
   - Send events to user space via perf ring buffer

4. **Processing**: Go code:
   - Reads events from perf ring buffer
   - Resolves connection info (IP addresses, ports) from file descriptors
   - Parses plaintext data as HTTP using existing parsers
   - Feeds into existing collector pipeline

5. **Output**: Captured HTTPS traffic flows through the same pipeline as HTTP traffic captured via pcap

## Key Differences from Pixie

- **Pixie**: Full observability platform with extensive eBPF infrastructure
- **This Implementation**: Focused on HTTPS capture for API monitoring
- **Approach**: Similar technique (uprobes on TLS functions) but integrated into existing pcap-based architecture

## Security Considerations

⚠️ **Important**: Capturing plaintext HTTPS traffic requires:
- Root/privileged access
- Careful security and privacy handling
- Compliance with organizational policies
- Secure data handling and storage

## Next Steps

1. Study existing implementations (eCapture, Pixie) for reference
2. Complete eBPF program implementation
3. Test with simple applications first
4. Add support for multiple TLS libraries (OpenSSL, GnuTLS, BoringSSL)
5. Integrate with existing pipeline
6. Performance testing and optimization
7. Security review

## References

- [Pixie eBPF Documentation](https://docs.px.dev/about-pixie/pixie-ebpf/)
- [eCapture Project](https://github.com/gojue/ecapture)
- [Cilium eBPF Library](https://github.com/cilium/ebpf)

