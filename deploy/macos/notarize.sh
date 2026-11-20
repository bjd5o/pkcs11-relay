#!/usr/bin/env bash
# Notarize Developer ID-signed provider dylibs (docs/milestone-7.md, "Signing and
# notarization"). Brian runs this locally; it needs the Developer ID Application certificate
# in the keychain and a notarytool keychain profile, created once with:
#   xcrun notarytool store-credentials relay-notary --apple-id <id> --team-id <team> --password <app-specific password>
# Usage, after CODESIGN_IDENTITY="Developer ID Application: …" deploy/macos/build-provider.sh:
#   deploy/macos/notarize.sh dist/librelay_pkcs11-*.dylib
# NOTARY_PROFILE picks another profile name. Fails unless Apple's status is Accepted. A bare
# dylib can't be stapled; Gatekeeper looks the ticket up online the first time it loads.
set -euo pipefail
profile="${NOTARY_PROFILE:-relay-notary}"
[ $# -gt 0 ] || { echo "usage: deploy/macos/notarize.sh <signed dylib>..." >&2; exit 2; }
for f in "$@"; do
  info=$(codesign -dv --verbose=4 "$f" 2>&1) || { echo "$f: not signed" >&2; exit 1; }
  echo "$info" | grep -q '^Authority=Developer ID Application' \
    || { echo "$f: not signed with a Developer ID Application certificate" >&2; exit 1; }
  echo "$info" | grep -q 'flags=.*runtime' \
    || { echo "$f: no hardened runtime (sign with --options runtime)" >&2; exit 1; }
done
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/relay-pkcs11"
cp "$@" "$work/relay-pkcs11/"
zip="$work/relay-pkcs11.zip"
ditto -c -k --keepParent "$work/relay-pkcs11" "$zip"
echo "submitting $# file(s) with keychain profile $profile (takes a few minutes)"
xcrun notarytool submit "$zip" --keychain-profile "$profile" --wait --output-format json >"$work/result.json"
id=$(plutil -extract id raw "$work/result.json")
status=$(plutil -extract status raw "$work/result.json")
echo "submission $id: $status"
xcrun notarytool log "$id" --keychain-profile "$profile" "$work/log.json" >/dev/null && cat "$work/log.json"
[ "$status" = "Accepted" ] || { echo "notarization failed: $status" >&2; exit 1; }
for f in "$@"; do
  spctl -a -t open --context context:primary-signature -v "$f"
done
echo "notarized: $*"
