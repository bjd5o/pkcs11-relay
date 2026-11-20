#!/bin/sh
# Build RelayPKCS11.xcframework (iOS device, iOS simulator on Apple silicon) from relay-pkcs11's
# static library, with the OASIS PKCS#11 headers and a module map (Provider/include), into
# apps/apple/Generated (git-ignored). An app links this or RelayFFI, never both: two Rust
# static libraries in one binary give duplicate std symbols.
#
#   apps/apple/build-provider-xcframework.sh                 # release
#   PROFILE=dev apps/apple/build-provider-xcframework.sh     # debug, faster
set -eu
cd "$(dirname "$0")/../.."
PROFILE=${PROFILE:-release}
case $PROFILE in dev) DIR=debug ;; *) DIR=$PROFILE ;; esac
OUT=apps/apple/Generated
FW=$OUT/RelayPKCS11.xcframework
# Never leave an older framework behind if this build fails. RelayFFI's files stay.
rm -rf "$FW" "$OUT/provider-headers"

# Host-side proc macros first, without the deployment-target variable (see build-xcframework.sh).
env -u IPHONEOS_DEPLOYMENT_TARGET -u MACOSX_DEPLOYMENT_TARGET \
  cargo build -p relay-pkcs11 --lib --profile "$PROFILE"

TARGETS="aarch64-apple-ios aarch64-apple-ios-sim"
for t in $TARGETS; do
  IPHONEOS_DEPLOYMENT_TARGET=17.0 cargo build -p relay-pkcs11 --lib --profile "$PROFILE" --target "$t"
done

# Only the headers and the module map go into the framework, not the README.
mkdir -p "$OUT/provider-headers"
cp apps/apple/Provider/include/*.h apps/apple/Provider/include/module.modulemap "$OUT/provider-headers/"

ARGS=""
for t in $TARGETS; do
  ARGS="$ARGS -library target/$t/$DIR/librelay_pkcs11.a -headers $OUT/provider-headers"
done
# shellcheck disable=SC2086
xcodebuild -create-xcframework $ARGS -output "$FW" >/dev/null
echo "built $FW"
