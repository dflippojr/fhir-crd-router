#!/usr/bin/env bash
# Exercise the commands a new user runs, including sibling-module installation.
set -euo pipefail
cd "$(dirname "$0")/../.."

./mvnw -B -ntp -q install -DskipTests
output=$(mktemp)
trap 'rm -f "$output"' EXIT

# Capture both streams and check before printing, so a leak does not enter CI logs.
if ./mvnw -B -ntp -pl examples-quickstart exec:java > "$output" 2>&1; then
  result=0
else
  result=$?
fi

# The sample currently uses authType NONE and contains no credential values.
# Still reject common credential representations if logging ever starts leaking them.
if grep -Eiq -- 'Authorization[[:space:]]*[:=]|Bearer[[:space:]]|access_token|client_secret|-----BEGIN ([A-Z]+ )*PRIVATE KEY-----' "$output"; then
  echo '::error::Quickstart output contains credential material (output withheld)'
  exit 1
fi
cat "$output"
if [ "$result" -ne 0 ]; then
  echo "::error::Quickstart exited with status $result"
  exit "$result"
fi
if grep -Eq 'Exception in thread|Caused by:|Suppressed:|^[[:space:]]+at [^ ]+\(|[[:alnum:]_.$]+(Exception|Error)(:|[[:space:]])' "$output"; then
  echo '::error::Quickstart printed an exception or stack trace'
  exit 1
fi

# verify() discovers once, discoverServices() once more, then callHook() POSTs.
# Anchor the whole line to enforce the metadata-only allowlist, not just a prefix.
metadata='attempt=1 start=[0-9TZ:.+-]+ status=200 [0-9]+ ms HTTP_SUCCESS'
test "$(grep -Ec "^(DISCOVERY|TOKEN|HOOK) payer=" "$output" || true)" -eq 3
test "$(grep -Ec "^DISCOVERY payer=DEMO-PAYER env=SANDBOX GET $metadata$" "$output" || true)" -eq 2
test "$(grep -Ec "^HOOK payer=DEMO-PAYER env=SANDBOX POST $metadata$" "$output" || true)" -eq 1
grep -q '^Recorded lastVerifiedAt=' "$output"
grep -q '^Hook response cards: \[' "$output"
grep -q '^Coverage information for ' "$output"
echo 'Quickstart smoke passed: exit 0, two discovery GETs and one hook POST, no stack trace or credentials.'
