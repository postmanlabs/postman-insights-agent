# eBPF-based HTTPS Traffic Capture

This directory contains eBPF programs and Go code for capturing HTTPS traffic by hooking into TLS library functions before encryption and after decryption.

## Overview

Unlike the pcap-based capture which sees encrypted traffic at the network level, this approach uses eBPF uprobes to intercept plaintext data at the application level by hooking into TLS library functions:

- **SSL_write** / **SSL_write_ex**: Captures data before encryption (client requests, server responses)
- **SSL_read** / **SSL_read_ex**: Captures data after decryption (server responses, client requests)

## Architecture

```
Application (TLS Library)
    ↓
eBPF Uprobe (SSL_write/SSL_read)
    ↓
eBPF Program (captures plaintext)
    ↓
Perf Event Ring Buffer
    ↓
Go User Space (processes data)
    ↓
HTTP Parser (existing pipeline)
```

## Supported TLS Libraries

- OpenSSL (libssl.so)
- GnuTLS (libgnutls.so)
- BoringSSL (libssl.so)
- Go's crypto/tls (via cgo wrapper)

## Requirements

- Linux kernel 4.18+ (for eBPF uprobes)
- Root/privileged access (to load eBPF programs)
- libbpf development libraries
- clang/llvm for compiling eBPF programs

## Usage

The HTTPS capture runs alongside the existing pcap-based capture. Enable it with:

```bash
postman-insights-agent apidump --enable-https-capture
```

## Security Considerations

⚠️ **Warning**: Capturing plaintext HTTPS traffic requires elevated privileges and raises significant security and privacy concerns. Ensure:

1. Proper access controls are in place
2. Compliance with organizational policies and regulations
3. Secure handling of captured data
4. Appropriate logging and monitoring

