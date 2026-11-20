#!/usr/bin/env bash
# Build the universal (arm64 + x86_64) librelay_pkcs11.dylib for macOS 13 and newer:
#   deploy/macos/build-provider.sh
#   CODESIGN_IDENTITY="Developer ID Application: …" deploy/macos/build-provider.sh
# Output: dist/librelay_pkcs11-macos-universal.dylib, plus one file per slice
# (dist/librelay_pkcs11-aarch64-apple-darwin.dylib, …-x86_64-apple-darwin.dylib) for the
# release archives. Without CODESIGN_IDENTITY the dylib keeps the linker's ad-hoc
# signature; with it, it is signed for notarization (hardened runtime, secure timestamp).
# The identity comes from the keychain and never from the repo.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
export MACOSX_DEPLOYMENT_TARGET=13.0
targets=(aarch64-apple-darwin x86_64-apple-darwin)
name=librelay_pkcs11.dylib
mkdir -p dist
slices=()
for t in "${targets[@]}"; do
  cargo build --release --locked -p relay-pkcs11 --target "$t"
  out="dist/librelay_pkcs11-$t.dylib"
  cp "target/$t/release/$name" "$out"
  # Callers dlopen the module by path; @rpath only matters for tools that link it.
  install_name_tool -id "@rpath/$name" "$out"
  slices+=("$out")
done
universal=dist/librelay_pkcs11-macos-universal.dylib
lipo -create "${slices[@]}" -output "$universal"
for f in "$universal" "${slices[@]}"; do
  if [ -n "${CODESIGN_IDENTITY:-}" ]; then
    codesign --force --options runtime --timestamp --sign "$CODESIGN_IDENTITY" "$f"
  else
    # install_name_tool and lipo invalidate the linker's signature; arm64 needs one.
    codesign --force --sign - "$f"
  fi
done
lipo -info "$universal"
codesign -dv "$universal" 2>&1 | grep -E '^(Authority|Signature|CodeDirectory)' || true
echo "built $universal"
