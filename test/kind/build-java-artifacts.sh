#!/usr/bin/env bash
# Build postman-java-agent.jar and grpc-java.jar for Kind e2e.
#
# Uses Docker (gradle:8-jdk17) so hosts with only JDK 21/26 still work.
# The java-agent Gradle project pins toolchain = 17; Gradle 9 + JDK 26 alone
# is not enough without auto-provisioning.
#
# Usage: ./test/kind/build-java-artifacts.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GRADLE_IMAGE="${GRADLE_IMAGE:-gradle:8-jdk17}"

echo "==> Building Java artifacts via ${GRADLE_IMAGE}"

docker run --rm \
  -v "$REPO_ROOT/java-agent:/work" \
  -w /work \
  "$GRADLE_IMAGE" \
  bash -c '
    set -euo pipefail
    apt-get update -qq
    apt-get install -y -qq make gcc >/dev/null
    make -C src/main/c
    gradle --no-daemon shadowJar
  '

docker run --rm \
  -v "$REPO_ROOT/java-agent/testdata/grpc-java:/work" \
  -w /work \
  "$GRADLE_IMAGE" \
  gradle --no-daemon shadowJar

echo "==> Built:"
ls -lh "$REPO_ROOT/java-agent/build/libs/postman-java-agent.jar"
ls -lh "$REPO_ROOT/java-agent/testdata/grpc-java/build/libs/grpc-java.jar"
