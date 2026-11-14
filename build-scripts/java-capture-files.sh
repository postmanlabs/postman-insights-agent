#!/bin/sh
# Builds the files Java HTTPS capture needs next to the Insights agent, under
# the names the agent loads them by from /opt/postman (ebpf/javatls/contract.go;
# ebpf/javatls/contract_test.go checks this script against it), and checks
# them. Release images (Postman's release build) and build-scripts/Dockerfile.ebpf
# both call it, so the names live in this repository only.
#
# Usage: build-scripts/java-capture-files.sh jar|helper|all OUTDIR [VERSION]
#   jar     the Java agent jar, versioned VERSION (default 0.0.0-dev), and its
#           SHA-256 file; needs a JDK (Gradle downloads itself)
#   helper  the postman-insights-jvm-attach helper, static; needs Go
#   all     both
set -eu

JAR_NAME=postman-insights-java-agent.jar
HELPER_NAME=postman-insights-jvm-attach

if [ "$#" -lt 2 ]; then
    awk '/^# Usage/ { p = 1 } /^set -eu/ { exit } p' "$0" >&2
    exit 2
fi
what=$1
version=${3:-0.0.0-dev}
repo=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$2"
out=$(cd "$2" && pwd)

fail() {
    echo "ERROR: java-capture-files: $*" >&2
    exit 1
}

# Prints a jar's manifest, with unzip, or the JDK's jar tool where there is no
# unzip (the eclipse-temurin images).
read_manifest() {
    if command -v unzip > /dev/null; then
        unzip -p "$1" META-INF/MANIFEST.MF
        return
    fi
    tmp=$(mktemp -d)
    (cd "$tmp" && jar xf "$1" META-INF/MANIFEST.MF && cat META-INF/MANIFEST.MF)
    rm -rf "$tmp"
}

build_jar() {
    # sh: module zips (how release builds get this source) keep no exec bits.
    (cd "$repo/java-agent" && sh gradlew --no-daemon -q "-PagentVersion=${version}" agentJar)
    cp "$repo/java-agent/build/agent/$JAR_NAME" "$out/$JAR_NAME"
    (cd "$out" && sha256sum "$JAR_NAME" > "$JAR_NAME.sha256")
    chmod 0644 "$out/$JAR_NAME" "$out/$JAR_NAME.sha256"

    (cd "$out" && sha256sum -c "$JAR_NAME.sha256" > /dev/null) || fail "$JAR_NAME does not match its SHA-256"
    manifest=$(read_manifest "$out/$JAR_NAME" | tr -d '\r')
    echo "$manifest" | grep -qx "Implementation-Version: ${version}" || fail "$JAR_NAME is not versioned ${version}"
    echo "$manifest" | grep -qx "Agent-Class: com.postman.insights.agent.AgentMain" || fail "$JAR_NAME has no Agent-Class"
}

build_helper() {
    (cd "$repo" && CGO_ENABLED=0 go build -ldflags "-s -w" -o "$out/$HELPER_NAME" "./cmd/$HELPER_NAME")
    chmod 0755 "$out/$HELPER_NAME"
}

case "$what" in
    jar) build_jar ;;
    helper) build_helper ;;
    all) build_jar; build_helper ;;
    *) fail "unknown target $what (jar, helper or all)" ;;
esac
