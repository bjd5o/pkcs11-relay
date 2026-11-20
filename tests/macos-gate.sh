#!/usr/bin/env bash
# Milestone 7 gate, part A, natively on a Mac: the milestone 3 checks (tests/m3-gate.sh) with
# pkcs11-tool, OpenSSL 3 + pkcs11-provider and ssh-keygen against the provider, through a
# relay and three test approvers running as local processes. No Docker. Needs the project
# Flox environment for the callers:
#   flox activate -- tests/macos-gate.sh
#   MOD=dist/librelay_pkcs11-aarch64-apple-darwin.dylib flox activate -- tests/macos-gate.sh
# Without MOD it builds and tests target/debug/librelay_pkcs11.dylib. KEEP=1 keeps the work
# directory (fixtures, logs). The `ssh -I` check is skipped: there is no test sshd here.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
PORT=${PORT:-18443}
W=$(mktemp -d "${TMPDIR:-/tmp}/macos-gate.XXXXXX")
PIDS=()
cleanup() {
  # ${PIDS[@]+…}: an empty array is "unbound" under set -u in macOS's bash 3.2.
  for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  if [ -n "${KEEP:-}" ]; then echo "kept $W"; else rm -rf "$W"; fi
}
trap cleanup EXIT INT TERM

for tool in pkcs11-tool openssl ssh-keygen; do
  command -v "$tool" >/dev/null || { echo "$tool not found: run inside 'flox activate'" >&2; exit 2; }
done

echo "== build"
cargo build -q -p relay-server -p relay-test-approver
if [ -z "${MOD:-}" ]; then
  cargo build -q -p relay-pkcs11
  MOD=target/debug/librelay_pkcs11.dylib
fi
MOD="$(cd "$(dirname "$MOD")" && pwd)/$(basename "$MOD")"
echo "module: $MOD"

# OpenSSL finds pkcs11-provider through OPENSSL_MODULES; Flox puts it under $FLOX_ENV.
if [ -z "${OPENSSL_MODULES:-}" ] && [ -n "${FLOX_ENV:-}" ] && [ -d "$FLOX_ENV/lib/ossl-modules" ]; then
  export OPENSSL_MODULES="$FLOX_ENV/lib/ossl-modules"
fi

echo "== fixtures, relay on https://localhost:$PORT, approvers A (approve), B (deny), C (stale)"
target/debug/relay-test-approver gen-fixtures --out "$W" --root "$W" \
  --relay-url "https://localhost:$PORT" --pairing-cidrs 127.0.0.0/8 2>/dev/null
RELAY_LISTEN=127.0.0.1:$PORT RELAY_DATA_DIR=$W/relay-data \
  target/debug/relay-server --config "$W/relay.toml" serve >"$W/relay.log" 2>&1 &
PIDS+=($!)
i=0
until curl -fs --cacert "$W/relay-ca.pem" "https://localhost:$PORT/healthz" >/dev/null; do
  i=$((i + 1)); [ $i -gt 50 ] && { echo "relay did not start"; cat "$W/relay.log"; exit 1; }
  sleep 0.2
done
target/debug/relay-test-approver run --config "$W/approver-a.toml" --auto-approve >"$W/approver-a.log" 2>&1 &
PIDS+=($!)
target/debug/relay-test-approver run --config "$W/approver-b.toml" --deny --delay 3 --long-poll >"$W/approver-b.log" 2>&1 &
PIDS+=($!)
target/debug/relay-test-approver run --config "$W/approver-c.toml" --auto-approve --expired-attestation >"$W/approver-c.log" 2>&1 &
PIDS+=($!)

echo "== milestone 3 checks"
status=0
MOD="$MOD" FIX="$W" SSHD="" sh tests/m3-gate.sh || status=$?
if [ "$status" -ne 0 ]; then
  echo "== relay log (last 40 lines)"; tail -40 "$W/relay.log"
fi
exit "$status"
