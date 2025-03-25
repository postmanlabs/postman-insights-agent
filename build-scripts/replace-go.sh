#!/usr/bin/env bash

# HACK to replace Go with 1.21.0. This is intended to be run in a
# golang:1.18.3-buster container.

set -euo pipefail

case "${HOSTTYPE}" in
x86_64)
  arch=amd64
  ;;
aarch64)
  arch=arm64
  ;;
*)
  echo "Unable to replace Go: Unknown host type ${HOSTTYPE}" >&2
  exit 1
esac

rm -rf /usr/local/go
wget https://golang.org/dl/go1.21.0.linux-${arch}.tar.gz
tar -C /usr/local -zxf go1.21.0.linux-${arch}.tar.gz
