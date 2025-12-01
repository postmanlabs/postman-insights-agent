#!/bin/bash
set -e

OUTPUT_FILE="${ECAPTURE_OUTPUT_FILE:-/tmp/shared/tls.txt}"

echo "Starting ecapture..."
echo "Output file: ${OUTPUT_FILE}"

mkdir -p "$(dirname "${OUTPUT_FILE}")"

# Increase memlock limit so eBPF maps can be created
echo "Raising memlock ulimit..."
ulimit -l unlimited || echo "Failed to raise memlock limit"

# Simple command based on ecapture help output
exec ecapture tls -m pcap --pcapfile "${OUTPUT_FILE}"
