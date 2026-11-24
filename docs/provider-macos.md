# The provider on macOS

`librelay_pkcs11.dylib` is the PKCS#11 module that callers such as `pkcs11-tool`, OpenSSL and OpenSSH load. It holds no private keys: each sign or decrypt goes through the relay to an approver app, where you approve it and the YubiKey does the operation. This page covers installing it on an Apple silicon Mac (Intel Macs aren't supported), where its config goes, and which programs will and won't load it. The design is in `docs/spec.md`; the milestone plan is `docs/milestone-7.md`.

## Install

Pick one. Each puts the same module on disk; only the path differs.

**Flox** (built from source on your machine, a minute or two the first time):

```sh
flox install github:bjd5o/pkcs11-relay/v0.7.0#relay-pkcs11
# module: $FLOX_ENV/lib/librelay_pkcs11.dylib
```

Or in a manifest, under `[install]`: `relay-pkcs11.flake = "github:bjd5o/pkcs11-relay/v0.7.0"`.

**Nix:**

```sh
nix profile install github:bjd5o/pkcs11-relay/v0.7.0#relay-pkcs11
# module: ~/.nix-profile/lib/librelay_pkcs11.dylib
```

**mise** (downloads the signed and notarized release build):

```sh
mise use -g github:bjd5o/pkcs11-relay@0.7.0
# module: "$(mise where github:bjd5o/pkcs11-relay)/lib/librelay_pkcs11.dylib"
```

**By hand:** download `relay-pkcs11-v0.7.0-aarch64-apple-darwin.tar.gz` and `SHA256SUMS` from the GitHub release, check it with `shasum -a 256 -c SHA256SUMS --ignore-missing`, and unpack it anywhere. The dylib is notarized, so a browser download loads without a Gatekeeper prompt (macOS checks the ticket online the first time).

The Nix and Flox build needs macOS 14 or newer; the release build needs macOS 13 or newer.

## Configuration

The module reads one TOML file, whose fields are in `docs/spec.md` ("Configuration"). It looks for it in this order and uses the first one it finds:

1. The file named by `RELAY_PKCS11_CONFIG`, if that variable is set. If the file doesn't exist, the module stops there and lists no slots, rather than trying the other paths.
2. `$XDG_CONFIG_HOME/relay-pkcs11/provider.toml`, or `~/.config/relay-pkcs11/provider.toml` when `XDG_CONFIG_HOME` is unset.
3. `~/Library/Application Support/relay-pkcs11/provider.toml`.

Files are never merged: the first one found is the whole config, and the log warns about any later one it ignored. Paths inside the file must be absolute.

For most people, `~/.config/relay-pkcs11/provider.toml` is the place: shells and GUI apps both find it, without any environment variable. GUI apps launched from the Dock or Finder don't see variables set in your shell startup files, so use `RELAY_PKCS11_CONFIG` only for shells and scripts, or set it for GUI apps with `launchctl setenv RELAY_PKCS11_CONFIG /path/to/provider.toml` (until the next login).

The module logs to stderr at `warn` by default. Set `log_path` and `log_level = "info"` in the config to see which file it read and, on the first run, the pairing code to compare in the approver app.

## Use it

In these examples, `MOD` is the module path from "Install".

**pkcs11-tool** (OpenSC):

```sh
pkcs11-tool --module "$MOD" -L                       # slots, one per token in the manifest
pkcs11-tool --module "$MOD" -O                       # keys
pkcs11-tool --module "$MOD" --sign -m ECDSA-SHA256 --id 03 -i msg -o msg.sig
```

The sign call waits until you approve it in the approver app, up to the config's `timeout_secs`.

**OpenSSL 3** with `pkcs11-provider`:

```sh
export PKCS11_PROVIDER_MODULE="$MOD"
openssl pkeyutl -provider pkcs11 -provider default -sign \
  -inkey 'pkcs11:token=<token label>;object=<key label>;type=private' -in digest -out digest.sig
```

**OpenSSH:** `ssh-keygen -D "$MOD"` prints the public keys; `ssh -I "$MOD" host`, or `PKCS11Provider` in `~/.ssh/config`, signs in with them.

## What won't load it

Apps that enforce library validation load only code signed by Apple or by their own developer, so they refuse this module whatever its signature. That covers most Apple-signed GUI apps (Safari, Mail, Keychain Access) and many App Store apps. Command-line tools, OpenSSL 3 with `pkcs11-provider`, and OpenSSH from Nix or Flox load it.

Apple's own `/usr/bin/ssh` loads PKCS#11 modules through `ssh-pkcs11-helper`; whether it accepts this one is checked in the milestone 7 gate and recorded here afterwards.

Making the keys visible to every app would need a CryptoTokenKit extension, which is outside the MVP.

## Releasing (maintainer)

1. Tag the release on `main` and let CI build the Linux modules (`provider` job artifacts).
2. On the Mac, with the Developer ID certificate in the keychain and the `Relay Notary` profile saved (`docs/milestone-7.md`, "Signing and notarization"):

   ```sh
   CODESIGN_IDENTITY="Developer ID Application: …" deploy/macos/build-provider.sh
   deploy/macos/notarize.sh dist/librelay_pkcs11-aarch64-apple-darwin.dylib
   ```

3. Put the CI `.so` files next to those in `dist/`, then `deploy/release/package.sh v0.7.0 dist` and `gh release create v0.7.0 dist/release/v0.7.0/*`.
4. Check `mise use github:bjd5o/pkcs11-relay@0.7.0` on macOS and Linux, and `flox install github:bjd5o/pkcs11-relay/v0.7.0#relay-pkcs11`.
