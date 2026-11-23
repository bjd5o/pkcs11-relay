#!/bin/sh
# Provider simulator test (milestone 7, task 12): a real relay and an auto-approving
# relay-test-approver (softcard fixtures) on this Mac, and the SampleSigner app in the iOS
# simulator, linking RelayPKCS11.xcframework. The UI test imports the fixture client config
# without a client key (the app writes it to Library/Application Support/relay-pkcs11 in its
# container; no environment variable), so the provider creates the key there. The test reads the
# pairing code the app shows and writes it to a file here; only then does the test approver
# start, approving the pairing whose code matches, as a person comparing the codes would. Then
# the app signs with sign-ec and verifies the signature with the public key it read through
# PKCS#11.
#
#   tests/sim-provider.sh [simulator name]   (default: an iPad on the newest runtime the SDK covers)
# Needs: Xcode, the iOS Rust targets (mise.toml), xcodegen (mise.toml), python3. No YubiKey.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
W=$(mktemp -d)
PORT=${RELAY_PORT:-18444}
SIM=${1:-}
RELAY_PID=""
APPROVER_PID=""
cleanup() {
  [ -n "$APPROVER_PID" ] && kill "$APPROVER_PID" 2>/dev/null || true
  [ -n "$RELAY_PID" ] && kill "$RELAY_PID" 2>/dev/null || true
  if [ -n "${KEEP:-}" ]; then echo "kept $W"; else rm -rf "$W"; fi
}
trap cleanup EXIT INT TERM
# shellcheck source=tests/sim-lib.sh
. "$ROOT/tests/sim-lib.sh"

echo "== build"
cargo build -q -p relay-server -p relay-test-approver
PROFILE=dev apps/apple/build-provider-xcframework.sh
(cd apps/apple && xcodegen -q)

pick_simulator iPad "$SIM"
# A fresh install, so the provider creates a new client key: the container (and the key in it)
# otherwise survives from the last run, and re-importing a config keeps an existing key.
BUNDLE=$(xcodebuild -project apps/apple/RelayApprover.xcodeproj -scheme SampleSigner -showBuildSettings 2>/dev/null |
  awk '$1 == "PRODUCT_BUNDLE_IDENTIFIER" { print $3; exit }')
xcrun simctl boot "$UDID" 2>/dev/null || true
xcrun simctl uninstall "$UDID" "$BUNDLE" 2>/dev/null || true

echo "== fixtures and relay on https://localhost:$PORT"
start_relay

# The folder a person would pick in Files: the client config and the files it names. No client
# key: the provider creates one in the app's container on first run.
mkdir "$W/import"
cp "$W/provider.toml" "$W/signer.asc" "$W/relay-ca.pem" "$W/attestation-root.pem" "$W/import/"

# The test approver knows the client only by the code the app will show, not by its key.
python3 -I -c '
import re, sys
path, code_file = sys.argv[1], sys.argv[2]
s = open(path).read()
s, n = re.subn(r"(\[\[trusted_clients\]\]\nclient_id = \"[^\"]*\"\n)public_key = \"[^\"]*\"\n",
               lambda m: m.group(1) + "pairing_code_file = \"%s\"\n" % code_file, s)
assert n == 1, "approver-a.toml: trusted_clients entry not found"
open(path, "w").write(s)
' "$W/approver-a.toml" "$W/pairing-code"

echo "== test approver (starts once the app shows the pairing code; approves it and the signature)"
(
  i=0
  until [ -s "$W/pairing-code" ]; do
    i=$((i + 1)); [ $i -gt 1200 ] && exit 1
    sleep 0.5
  done
  echo "pairing code from the app: $(cat "$W/pairing-code")"
  exec target/debug/relay-test-approver run --config "$W/approver-a.toml" --auto-approve
) >"$W/approver.log" 2>&1 &
APPROVER_PID=$!

echo "== UI test on '$SIM'"
TEST_RUNNER_SAMPLE_SIGNER_IMPORT="$W/import" \
TEST_RUNNER_SAMPLE_SIGNER_CODE_FILE="$W/pairing-code" \
xcodebuild -project apps/apple/RelayApprover.xcodeproj -scheme SampleSigner \
  -destination "$DEST" \
  -only-testing:SampleSignerUITests \
  test >"$W/xcodebuild.log" 2>&1 || {
    grep -E "error|failed|XCTAssert|relay-pkcs11" "$W/xcodebuild.log" | tail -40
    echo "--- approver"; tail -20 "$W/approver.log"; echo "--- relay"; tail -20 "$W/relay.log"
    exit 1
  }
grep -E "Executed" "$W/xcodebuild.log" | tail -1
grep -E "pairing code from the app|pairing approved" "$W/approver.log" | cut -c1-200
echo "provider simulator test passed"
