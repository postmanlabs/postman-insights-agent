#!/usr/bin/env bash
# Generate a self-signed PKCS12 keystore at /tmp/spring-boot-https-keystore.p12
# if one doesn't exist. Mirrors the auto-gen in HelloHttps.java.

set -euo pipefail
KS=/tmp/spring-boot-https-keystore.p12
PASS=changeit

if [[ -f "$KS" ]]; then
  echo "keystore already exists: $KS"
  exit 0
fi

keytool -genkeypair \
  -alias hello \
  -keyalg RSA \
  -keysize 2048 \
  -storetype PKCS12 \
  -keystore "$KS" \
  -storepass "$PASS" \
  -dname "CN=localhost" \
  -validity 365 \
  >/dev/null 2>&1

echo "generated $KS"
