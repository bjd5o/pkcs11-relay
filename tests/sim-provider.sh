#!/bin/sh
# Provider simulator test (milestone 7, task 12): a real relay and an auto-approving
# relay-test-approver (softcard fixtures) on this Mac, and the SampleSigner app in the iOS
# simulator, linking RelayPKCS11.xcframework. The UI test imports the fixture client config
# (the app writes it to Library/Application Support/relay-pkcs11 in its container; no
# environment variable), pairs (the test approver approves), signs with sign-ec and checks the
# app verified the signature with the public key it read through PKCS#11.
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

echo "== fixtures and relay on https://localhost:$PORT"
start_relay

echo "== test approver (approves the pairing and the signature)"
target/debug/relay-test-approver run --config "$W/approver-a.toml" --auto-approve >"$W/approver.log" 2>&1 &
APPROVER_PID=$!

# The folder a person would pick in Files: the client config and the files it names. The
# fixture client key comes along so the test approver recognises the client; without it the
# provider creates a key on first run and the pairing code is compared by a person.
mkdir "$W/import"
cp "$W/provider.toml" "$W/signer.asc" "$W/relay-ca.pem" "$W/attestation-root.pem" "$W/client.pem" "$W/import/"

echo "== UI test on '$SIM'"
TEST_RUNNER_SAMPLE_SIGNER_IMPORT="$W/import" \
xcodebuild -project apps/apple/RelayApprover.xcodeproj -scheme SampleSigner \
  -destination "$DEST" \
  -only-testing:SampleSignerUITests \
  test >"$W/xcodebuild.log" 2>&1 || {
    grep -E "error|failed|XCTAssert|relay-pkcs11" "$W/xcodebuild.log" | tail -40
    echo "--- approver"; tail -20 "$W/approver.log"; echo "--- relay"; tail -20 "$W/relay.log"
    exit 1
  }
grep -E "Test Case .* passed|Executed" "$W/xcodebuild.log" | tail -3
echo "provider simulator test passed"
