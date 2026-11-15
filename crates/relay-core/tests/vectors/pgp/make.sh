#!/usr/bin/env bash
# Regenerates the OpenPGP interop vectors with real gpg, in a throwaway GNUPGHOME.
# Run after `cargo test -p relay-core --test gen_vectors -- --ignored` (which rewrites the
# manifests). Never touches the user's keyring or any card.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
fixture="$here/../fixture"
export GNUPGHOME="$(mktemp -d)"
trap 'gpgconf --kill all >/dev/null 2>&1 || true; rm -rf "$GNUPGHOME"' EXIT
# Every key and signature is made at the fixture's issued_at, 2026-11-15T00:00:00Z.
G=(gpg --batch --quiet --pinentry-mode loopback --passphrase '' --faked-system-time '20261115T000000!')

"${G[@]}" --quick-gen-key 'relay test signer <signer@test.invalid>' ed25519 sign never
"${G[@]}" --quick-gen-key 'relay test rsa <rsa@test.invalid>' rsa3072 cert never
rsa_fpr=$("${G[@]}" --with-colons --list-keys rsa@test.invalid | awk -F: '/^fpr/ {print $10; exit}')
"${G[@]}" --quick-add-key "$rsa_fpr" rsa3072 sign never
"${G[@]}" --quick-gen-key 'relay test other <other@test.invalid>' ed25519 sign never

"${G[@]}" --armor --export signer@test.invalid > "$here/signer-ed25519.asc"
"${G[@]}" --armor --export rsa@test.invalid > "$here/signer-rsa-subkey.asc"

sign() { "${G[@]}" --yes --digest-algo SHA256 "$@"; }
m="$fixture/manifest.json"
sign -u signer@test.invalid --armor --detach-sign -o "$here/manifest.json.asc" "$m"
sign -u signer@test.invalid --detach-sign -o "$here/manifest.json.sig" "$m"
sign -u rsa@test.invalid --armor --detach-sign -o "$here/manifest.json.subkey.asc" "$m"
sign -u signer@test.invalid --armor --textmode --detach-sign -o "$here/manifest.json.text.asc" "$m"
"${G[@]}" --yes --digest-algo SHA1 -u rsa@test.invalid --armor --detach-sign -o "$here/manifest.json.sha1.asc" "$m"
sign -u other@test.invalid --armor --detach-sign -o "$here/manifest.json.wrongkey.asc" "$m"
sign -u signer@test.invalid -u other@test.invalid --armor --detach-sign -o "$here/manifest.json.double.asc" "$m"
sign -u signer@test.invalid --armor --detach-sign -o "$here/manifest-v2.json.asc" "$fixture/manifest-v2.json"
sign -u signer@test.invalid --armor --detach-sign -o "$here/manifest-v1-alt.json.asc" "$fixture/manifest-v1-alt.json"

gpg --version | head -1 > "$here/GENERATED_WITH"
echo "wrote OpenPGP vectors to $here"
