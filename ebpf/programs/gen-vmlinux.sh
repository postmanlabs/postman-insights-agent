#!/usr/bin/env bash
#
# Generate the committed per-architecture vmlinux.h headers.
#
# WHY THIS EXISTS
# ---------------
# eBPF C is compiled with CO-RE ("Compile Once, Run Everywhere"), which needs a
# vmlinux.h describing kernel struct layouts. It's normally produced from a
# running Linux kernel's BTF (/sys/kernel/btf/vmlinux). Our RELEASE build runs
# on macOS machines that have no Linux kernel BTF, so we cannot generate this
# file at release time. Instead we generate it ONCE per architecture from a
# recent stable Ubuntu LTS kernel and commit the result. Thanks to CO-RE, the
# resulting programs still relocate correctly against whatever (>= 5.8) kernel
# they actually run on at the customer site.
#
# WHAT IT PRODUCES
# ----------------
#   ebpf/programs/vmlinux_amd64.h
#   ebpf/programs/vmlinux_arm64.h
#
# The build (agent Dockerfiles and the superstar release Dockerfile) copies the
# arch-appropriate file to ebpf/programs/vmlinux.h before running `go generate`.
#
# HOW TO RUN
# ----------
# Run on a Linux host (or in Docker) once per release to refresh the headers,
# then commit them. Requires Docker.
#
#   ./ebpf/programs/gen-vmlinux.sh
#
# Refresh cadence: regenerate at each release from the current stable Ubuntu LTS
# image. Kernel-version drift is handled by CO-RE, so an up-to-date LTS baseline
# is sufficient; we do NOT track individual customer kernel versions.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Ubuntu LTS image whose kernel BTF we snapshot. Bump at each release.
LTS_IMAGE="${LTS_IMAGE:-ubuntu:24.04}"

gen_for_arch() {
  local docker_arch="$1"   # linux/amd64 | linux/arm64
  local out_suffix="$2"    # amd64 | arm64

  echo "==> Generating vmlinux_${out_suffix}.h from ${LTS_IMAGE} (${docker_arch})"

  # We can't read /sys/kernel/btf/vmlinux of an arbitrary arch from a foreign
  # host, so we install the matching linux-tools BTF + bpftool inside a
  # same-arch container and dump the kernel's shipped BTF blob.
  docker run --rm --platform "${docker_arch}" -v "${HERE}:/out" "${LTS_IMAGE}" bash -c '
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -q
    # dwarves provides bpftool-compatible BTF tooling; linux-headers/-tools
    # ship the vmlinux BTF for the packaged kernel.
    apt-get install -y -q bpftool linux-headers-generic >/dev/null 2>&1 || \
      apt-get install -y -q dwarves linux-headers-generic >/dev/null
    # Prefer the packaged kernel BTF; fall back to the running one if present.
    btf=""
    for c in /sys/kernel/btf/vmlinux /usr/lib/modules/*/build/vmlinux; do
      if [ -e "$c" ]; then btf="$c"; break; fi
    done
    if [ -z "$btf" ]; then
      echo "ERROR: no kernel BTF found in this image; try a newer LTS_IMAGE" >&2
      exit 1
    fi
    bpftool btf dump file "$btf" format c
  ' > "${HERE}/vmlinux_${out_suffix}.h.tmp"

  mv "${HERE}/vmlinux_${out_suffix}.h.tmp" "${HERE}/vmlinux_${out_suffix}.h"
  echo "==> Wrote ebpf/programs/vmlinux_${out_suffix}.h ($(wc -l < "${HERE}/vmlinux_${out_suffix}.h") lines)"
}

gen_for_arch linux/amd64 amd64
gen_for_arch linux/arm64 arm64

echo "==> Done. Review and commit the updated vmlinux_*.h files."
