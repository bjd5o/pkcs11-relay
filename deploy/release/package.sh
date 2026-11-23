#!/usr/bin/env bash
# Package provider builds as GitHub release assets for mise's github: backend
# (docs/milestone-7.md, Distribution):
#   deploy/release/package.sh v0.7.0 <dir>
# <dir> holds the builds under the names CI and deploy/macos/build-provider.sh give them:
#   librelay_pkcs11-{x86_64,aarch64}-{gnu,musl}.so            (CI `provider` job artifacts)
#   librelay_pkcs11-aarch64-apple-darwin.dylib                (signed and notarized; no Intel Macs)
# Output in dist/release/<version>/: one relay-pkcs11-<version>-<target>.tar.gz per build,
# each holding lib/librelay_pkcs11.{so,dylib}, plus SHA256SUMS. mise picks the archive by
# the OS and CPU in its name. Missing builds are skipped with a warning; a macOS dylib that
# isn't Developer ID signed is refused, so an unsigned one never ships.
set -euo pipefail
version="${1:?usage: deploy/release/package.sh <version, e.g. v0.7.0> <dir with builds>}"
src="${2:?usage: deploy/release/package.sh <version> <dir with builds>}"
case "$version" in v[0-9]*) ;; *) echo "version must look like v0.7.0" >&2; exit 2 ;; esac
root="$(cd "$(dirname "$0")/../.." && pwd)"
out="$root/dist/release/$version"
rm -rf "$out"
mkdir -p "$out"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# build file -> Rust target triple
pairs=(
  "librelay_pkcs11-x86_64-gnu.so x86_64-unknown-linux-gnu"
  "librelay_pkcs11-aarch64-gnu.so aarch64-unknown-linux-gnu"
  "librelay_pkcs11-x86_64-musl.so x86_64-unknown-linux-musl"
  "librelay_pkcs11-aarch64-musl.so aarch64-unknown-linux-musl"
  "librelay_pkcs11-aarch64-apple-darwin.dylib aarch64-apple-darwin"
)
made=0
for pair in "${pairs[@]}"; do
  file=${pair% *}; target=${pair#* }
  if [ ! -f "$src/$file" ]; then
    echo "warning: $src/$file not found; no $target archive" >&2
    continue
  fi
  case "$file" in
    *.dylib)
      if ! codesign -dvv "$src/$file" 2>&1 | grep -q '^Authority=Developer ID Application'; then
        echo "$src/$file is not Developer ID signed; run deploy/macos/build-provider.sh with CODESIGN_IDENTITY, then notarize.sh" >&2
        exit 1
      fi
      lib=librelay_pkcs11.dylib ;;
    *) lib=librelay_pkcs11.so ;;
  esac
  d="$work/$target/lib"
  mkdir -p "$d"
  cp "$src/$file" "$d/$lib"
  archive="relay-pkcs11-$version-$target.tar.gz"
  # Fixed owner and no macOS extended attributes, so archives don't carry local details.
  COPYFILE_DISABLE=1 tar -C "$work/$target" --uid 0 --gid 0 --uname root --gname root -czf "$out/$archive" lib
  echo "packed $archive"
  made=$((made + 1))
done
[ "$made" -gt 0 ] || { echo "no builds found in $src" >&2; exit 1; }
(cd "$out" && shasum -a 256 relay-pkcs11-*.tar.gz >SHA256SUMS)
echo "wrote $made archive(s) and SHA256SUMS to $out"
echo "publish: gh release create $version $out/*"
