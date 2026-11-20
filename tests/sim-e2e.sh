#!/bin/sh
# Simulator end-to-end test (milestone 5, task 5.5): a real relay on this Mac, the approver app
# in the iOS simulator with relay-ffi's software test card, and `relay-test-approver
# sim-client` as the client. The UI test enrolls, approves the pairing and approves one
# RSA-OAEP decrypt with the PIN; the client checks the plaintext as the provider would.
#
#   tests/sim-e2e.sh [simulator name]     (default: an iPhone on the newest runtime the SDK covers)
# Needs: Xcode, the iOS Rust targets (mise.toml), xcodegen (mise.toml), python3. No YubiKey.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
W=$(mktemp -d)
PORT=${RELAY_PORT:-18443}
SIM=${1:-}
RELAY_PID=""
CLIENT_PID=""
cleanup() {
  [ -n "$CLIENT_PID" ] && kill "$CLIENT_PID" 2>/dev/null || true
  [ -n "$RELAY_PID" ] && kill "$RELAY_PID" 2>/dev/null || true
  if [ -n "${KEEP:-}" ]; then echo "kept $W"; else rm -rf "$W"; fi
}
trap cleanup EXIT INT TERM
# shellcheck source=tests/sim-lib.sh
. "$ROOT/tests/sim-lib.sh"

echo "== build"
cargo build -q -p relay-server -p relay-test-approver -p relayctl
FEATURES=test-card PROFILE=dev apps/apple/build-xcframework.sh
(cd apps/apple && xcodegen -q)

pick_simulator iPhone "$SIM"

echo "== fixtures and relay on https://localhost:$PORT"
start_relay

# The setup link, exactly as a person would make it (checks the live relay first).
target/debug/relayctl app-link --no-input --relay-url "https://localhost:$PORT" \
  --relay-ca "$W/relay-ca.pem" --pgp-secret "$W/signer-secret.asc" --device-id sim-iphone \
  --valid-for 1h >"$W/link.txt"
LINK=$(head -1 "$W/link.txt")
python3 -I - "$W/softcard-a" "$(cat "$W/pin")" >"$W/card.json" <<'PY'
import json, os, sys
d, pin = sys.argv[1], sys.argv[2].strip()
slots = []
for f in sorted(os.listdir(d)):
    if f.startswith("slot-") and f.endswith(".key.pem"):
        s = f[5:-8]
        slots.append({"slot": s, "key_pem": open(os.path.join(d, f)).read(),
                      "cert_pem": open(os.path.join(d, "slot-%s.cert.pem" % s)).read()})
print(json.dumps({"pin": pin, "slots": slots}))
PY

echo "== client (pairs, then submits one decrypt)"
target/debug/relay-test-approver sim-client --config "$W/gate.toml" --timeout-secs 900 >"$W/client.log" 2>&1 &
CLIENT_PID=$!

echo "== UI test on '$SIM'"
TEST_RUNNER_RELAY_TEST_LINK="$LINK" \
TEST_RUNNER_RELAY_TEST_ROOTS="$(cat "$W/attestation-root.pem")" \
TEST_RUNNER_RELAY_TEST_KEYSERVER="http://127.0.0.1:9" \
TEST_RUNNER_RELAY_TEST_CARD="$(cat "$W/card.json")" \
TEST_RUNNER_RELAY_TEST_PIN="$(tr -d '\n' <"$W/pin")" \
xcodebuild -project apps/apple/RelayApprover.xcodeproj -scheme RelayApprover \
  -destination "$DEST" \
  -only-testing:RelayApproverUITests \
  SWIFT_ACTIVE_COMPILATION_CONDITIONS='$(inherited) DEBUG RELAY_TEST_CARD' \
  test >"$W/xcodebuild.log" 2>&1 || {
    grep -E "error|failed|XCTAssert" "$W/xcodebuild.log" | tail -30
    echo "--- client"; cat "$W/client.log"; echo "--- relay"; tail -20 "$W/relay.log"
    exit 1
  }

if wait "$CLIENT_PID"; then
  CLIENT_PID=""
  cat "$W/client.log"
  echo "simulator end-to-end passed"
else
  CLIENT_PID=""
  echo "client failed:"; cat "$W/client.log"; exit 1
fi
