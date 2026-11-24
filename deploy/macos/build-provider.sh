#!/usr/bin/env bash
# Build librelay_pkcs11.dylib for Apple silicon Macs, macOS 13 and newer (Intel Macs aren't
# supported):
#   deploy/macos/build-provider.sh
#   CODESIGN_IDENTITY="Developer ID Application: …" deploy/macos/build-provider.sh
# Output: dist/librelay_pkcs11-aarch64-apple-darwin.dylib. Without CODESIGN_IDENTITY it keeps
# an ad hoc signature; with it, it is signed for notarization (hardened runtime, secure
# timestamp). The identity comes from the keychain and never from the repo.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
target=aarch64-apple-darwin
name=librelay_pkcs11.dylib
out="dist/librelay_pkcs11-$target.dylib"
mkdir -p dist
# Host-side proc macros first, without the deployment-target variable: with it set, release
# proc-macro dylibs come out malformed ("mis-aligned LINKEDIT"; see
# apps/apple/build-xcframework.sh).
env -u MACOSX_DEPLOYMENT_TARGET cargo build --release --locked -p relay-pkcs11 --lib
MACOSX_DEPLOYMENT_TARGET=13.0 cargo build --release --locked -p relay-pkcs11 --lib --target "$target"
cp "target/$target/release/$name" "$out"
# Callers dlopen the module by path; @rpath only matters for tools that link it.
install_name_tool -id "@rpath/$name" "$out"
if [ -n "${CODESIGN_IDENTITY:-}" ]; then
  codesign --force --options runtime --timestamp --sign "$CODESIGN_IDENTITY" "$out"
else
  # install_name_tool invalidates the linker's signature, and arm64 code must be signed.
  codesign --force --sign - "$out"
fi
codesign -dvv "$out" 2>&1 | grep -E '^(Authority|Signature|CodeDirectory)' || true
echo "built $out"
