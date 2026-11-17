#!/bin/sh
# Build RelayFFI.xcframework (iOS device, iOS simulator, macOS on Apple silicon) from relay-ffi,
# plus its Swift bindings, into apps/apple/Generated (git-ignored).
#
#   apps/apple/build-xcframework.sh                 # release
#   PROFILE=dev apps/apple/build-xcframework.sh     # debug, faster
#   FEATURES=test-card apps/apple/build-xcframework.sh   # with the simulator test card
set -eu
cd "$(dirname "$0")/../.."
PROFILE=${PROFILE:-release}
case $PROFILE in dev) DIR=debug ;; *) DIR=$PROFILE ;; esac
FEATURE_ARGS=""
[ -n "${FEATURES:-}" ] && FEATURE_ARGS="--features $FEATURES"
OUT=apps/apple/Generated
export IPHONEOS_DEPLOYMENT_TARGET=17.0 MACOSX_DEPLOYMENT_TARGET=14.0

TARGETS="aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin"
for t in $TARGETS; do
  # shellcheck disable=SC2086
  cargo build -p relay-ffi --lib --profile "$PROFILE" --target "$t" $FEATURE_ARGS
done

rm -rf "$OUT"
mkdir -p "$OUT/bindings" "$OUT/headers"
cargo run -q -p relay-ffi --features bindgen --bin uniffi-bindgen -- generate \
  --library "target/aarch64-apple-darwin/$DIR/librelay_ffi.dylib" \
  --language swift --out-dir "$OUT/bindings"
cp "$OUT/bindings/relay_ffiFFI.h" "$OUT/headers/"
cp "$OUT/bindings/relay_ffiFFI.modulemap" "$OUT/headers/module.modulemap"

ARGS=""
for t in $TARGETS; do
  ARGS="$ARGS -library target/$t/$DIR/librelay_ffi.a -headers $OUT/headers"
done
# shellcheck disable=SC2086
xcodebuild -create-xcframework $ARGS -output "$OUT/RelayFFI.xcframework" >/dev/null
echo "built $OUT/RelayFFI.xcframework and $OUT/bindings/relay_ffi.swift"
