# Shared by the simulator tests (tests/sim-e2e.sh, tests/sim-provider.sh); source it after
# setting W (work directory) and PORT. Needs Xcode, python3 and curl.

# pick_simulator PREFIX [NAME]: sets DEST (an xcodebuild destination) and SIM (a description).
# Target the simulator by id: a name alone means "that name on the newest runtime", and fails
# when the device exists only on an older one (iPhone 17 Pro on iOS 26 next to iOS 27). Without
# a name, take the first device whose name starts with PREFIX on the newest iOS runtime this
# Xcode's SDK covers.
pick_simulator() {
  if [ -n "${2:-}" ]; then
    DEST="platform=iOS Simulator,name=$2"
    SIM=$2
    return
  fi
  SDK=$(xcrun --sdk iphonesimulator --show-sdk-version)
  PICK=$(xcrun simctl list devices available -j | python3 -I -c '
import json, sys
sdk = tuple(int(x) for x in sys.argv[1].split("."))
prefix = sys.argv[2]
best = None
for rt, devs in json.load(sys.stdin)["devices"].items():
    name = rt.rsplit(".", 1)[-1]
    if not name.startswith("iOS-"):
        continue
    parts = name[4:].split("-")
    if not all(p.isdigit() for p in parts):
        continue  # device-specific runtimes such as iOS-27-2-iPhone19-4
    ver = tuple(int(p) for p in parts)
    found = [d for d in devs if d["name"].startswith(prefix)]
    if found and ver <= sdk and (best is None or ver > best[0]):
        best = (ver, found[0])
if best:
    print(best[1]["udid"], best[1]["name"], "(iOS " + ".".join(map(str, best[0])) + ")")
' "$SDK" "$1")
  if [ -z "$PICK" ]; then
    echo "no available $1 simulator for the iOS $SDK SDK; available devices:"
    xcrun simctl list devices available | tail -30
    exit 1
  fi
  DEST="platform=iOS Simulator,id=${PICK%% *}"
  SIM=${PICK#* }
}

# start_relay: fixtures in $W (paths inside them point at $W) and a relay on
# https://localhost:$PORT; sets RELAY_PID.
start_relay() {
  target/debug/relay-test-approver gen-fixtures --out "$W" --root "$W" \
    --relay-url "https://localhost:$PORT" --pairing-cidrs 127.0.0.0/8 2>/dev/null
  RELAY_LISTEN=127.0.0.1:$PORT RELAY_DATA_DIR=$W/relay-data \
    target/debug/relay-server --config "$W/relay.toml" serve >"$W/relay.log" 2>&1 &
  RELAY_PID=$!
  i=0
  until curl -fs --cacert "$W/relay-ca.pem" "https://localhost:$PORT/healthz" >/dev/null; do
    i=$((i + 1)); [ $i -gt 50 ] && { echo "relay did not start"; cat "$W/relay.log"; exit 1; }
    sleep 0.2
  done
}
