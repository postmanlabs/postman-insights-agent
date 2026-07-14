/*
 * PLACEHOLDER — not a real vmlinux.h.
 *
 * The real header is a multi-megabyte BTF dump of the arm64 kernel and must be
 * generated on a Linux host (it cannot be produced on the macOS release
 * machines). Generate and commit it with:
 *
 *     ./ebpf/programs/gen-vmlinux.sh
 *
 * Until that is done, this #error makes any eBPF build fail loudly rather than
 * silently producing a broken or non-eBPF binary.
 */
#error "vmlinux_arm64.h is a placeholder — run ebpf/programs/gen-vmlinux.sh on a Linux host and commit the real header."
