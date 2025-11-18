package openssl

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-D__TARGET_ARCH_x86 -I../include" OpenSSLTLS openssl_tls.bpf.c -- -I../include -D__TARGET_ARCH_x86
