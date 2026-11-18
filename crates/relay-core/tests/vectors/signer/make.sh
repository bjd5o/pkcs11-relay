#!/usr/bin/env bash
# Regenerates the signer-status vectors (wire-format §11.4) with real gpg, in a throwaway
# GNUPGHOME and at faked times. Never touches the user's keyring or any card.
#
# Times: keys are made at 2026-11-15T00:00:00Z (1794700800). Keys with an expiry get one day.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
export GNUPGHOME="$(mktemp -d)"
trap 'gpgconf --kill all >/dev/null 2>&1 || true; rm -rf "$GNUPGHOME"' EXIT
T0='20261115T000000!'
T1='20261115T120000!'
g() { local t=$1; shift; gpg --batch --quiet --pinentry-mode loopback --passphrase '' --faked-system-time "$t" "$@"; }
fpr() { g "$T0" --with-colons --list-keys "$1" | awk -F: '/^fpr/ {print $10; exit}'; }
export_key() { g "$T1" --armor --export "$1" > "$here/$2"; }

# 1. A plain signing key, no expiry.
g "$T0" --quick-gen-key 'usable <usable@test.invalid>' ed25519 sign never
export_key usable@test.invalid usable.asc

# 2. Expires one day after creation; then the same key renewed for a year (newer self-signature).
g "$T0" --quick-gen-key 'expiring <expiring@test.invalid>' ed25519 sign 1d
export_key expiring@test.invalid expiring.asc
g "$T1" --quick-set-expire "$(fpr expiring@test.invalid)" 1y
export_key expiring@test.invalid renewed.asc

# 3. Revoked with the revocation certificate gpg wrote at creation.
g "$T0" --quick-gen-key 'revoked <revoked@test.invalid>' ed25519 sign never
rf="$(fpr revoked@test.invalid)"
sed 's/^:-----BEGIN/-----BEGIN/' "$GNUPGHOME/openpgp-revocs.d/$rf.rev" | g "$T1" --import
export_key revoked@test.invalid revoked.asc

# 4. A certify-only primary with a signing subkey that expires after one day.
g "$T0" --quick-gen-key 'subkey <subkey@test.invalid>' ed25519 cert never
g "$T0" --quick-add-key "$(fpr subkey@test.invalid)" ed25519 sign 1d
export_key subkey@test.invalid subkey-expiring.asc

# 5. A certify-only primary whose only signing subkey is revoked.
g "$T0" --quick-gen-key 'subrev <subrev@test.invalid>' ed25519 cert never
g "$T0" --quick-add-key "$(fpr subrev@test.invalid)" ed25519 sign never
printf 'key 1\nrevkey\ny\n0\n\ny\nsave\n' | g "$T1" --command-fd 0 --status-fd 2 --edit-key subrev@test.invalid >/dev/null 2>&1
export_key subrev@test.invalid subkey-revoked.asc

# 6. A certify-only primary with no signing subkey.
g "$T0" --quick-gen-key 'certonly <certonly@test.invalid>' ed25519 cert never
export_key certonly@test.invalid cert-only.asc

gpg --version | head -1 > "$here/GENERATED_WITH"
echo "wrote signer vectors to $here"
