# Milestone 4 gate: runbook for YubiKey <serial>

This device holds key material that must not be overwritten or reset. Every command marked
**[CARD]** touches the YubiKey. Each one runs only after Brian approves that exact command.
Commands that need the PIN or the management key are run by Brian in his own terminal, so the
PIN and management key never pass through Claude.

- Serial: <serial> (`export RELAY_TEST_YUBIKEY_SERIAL=<serial>` for relayctl and the approver)
- Management key: AES-256. yubikey 0.8 cannot authenticate with it, so ykman generates the
  keys, not `relayctl key generate`.
- Slots: only 85–89. No other slot is written.

## Slot plan

| Slot | Role | Algorithm | PIN | Touch | CKA_ID | Label |
|---|---|---|---|---|---|---|
| 85 | attest | P-256 | once | always | 10 | attest |
| 86 | sign | P-256 | once | never | 01 | hw-sign |
| 87 | auth | P-256 | once | never | 02 | hw-auth |
| 88 | encrypt | RSA-2048 | once | never | 03 | hw-unseal |
| 89 | sign | Ed25519 | once | never | 04 | hw-sign-ed25519 |

Slot 89 is optional. It exercises a key that only ykman can generate (firmware 5.7+).

## 1. Check the slots are empty [CARD, read-only]

`ykman piv keys generate` overwrites a slot **without asking**, so this check must come first.
None of these commands needs a PIN.

```sh
ykman --device <serial> piv info
for s in 85 86 87 88 89; do echo "== $s"; ykman --device <serial> piv keys info $s; done
```

Continue only if every slot reports no key and `piv info` shows no certificate in 85–89.

## 2. Generate the keys [CARD, writes, Brian runs: management key and PIN]

Run each pair only for a slot that step 1 showed to be empty.

```sh
D="ykman --device <serial> piv"
$D keys generate --algorithm ECCP256 --pin-policy ONCE --touch-policy ALWAYS 85 attest.pem
$D certificates generate --subject "CN=relay attest" 85 attest.pem
$D keys generate --algorithm ECCP256 --pin-policy ONCE --touch-policy NEVER 86 hw-sign.pem
$D certificates generate --subject "CN=relay hw-sign" 86 hw-sign.pem
$D keys generate --algorithm ECCP256 --pin-policy ONCE --touch-policy NEVER 87 hw-auth.pem
$D certificates generate --subject "CN=relay hw-auth" 87 hw-auth.pem
$D keys generate --algorithm RSA2048 --pin-policy ONCE --touch-policy NEVER 88 hw-unseal.pem
$D certificates generate --subject "CN=relay hw-unseal" 88 hw-unseal.pem
$D keys generate --algorithm ED25519 --pin-policy ONCE --touch-policy NEVER 89 hw-sign-ed25519.pem
$D certificates generate --subject "CN=relay hw-sign-ed25519" 89 hw-sign-ed25519.pem
```

## 3. Build the manifest from the PEM files (no card)

`--public-key` reads the files from step 2, so this step does not open the card.

```sh
relayctl manifest init --manifest gate-m4/manifest.json
relayctl manifest add --manifest gate-m4/manifest.json --public-key attest.pem --role attest --label attest --id 10 --token yubikey-<serial>
# ...and the same for 86–89 with the roles, IDs and labels above
```

## 4. Sign the manifest with the OpenPGP card [CARD, OpenPGP applet, Brian runs: PIN and touch]

```sh
relayctl manifest sign --manifest gate-m4/manifest.json --gpg-key <KEY-ID> --verify-with gate-m4/signer.asc
```

## 5. Relay and approver

- The relay runs locally with the gate TLS material (no card).
- **[CARD]** `relay-test-approver run --pcsc --config gate-m4/approver-hw.toml` (`pcsc_serial = <serial>`,
  `attest_slot = "85"`, and `pin_file` written by Brian with mode 0600).
  - At startup the approver reads every slot's certificate (read-only) to map manifest keys to slots.
  - It verifies the PIN once (a rejected PIN stops it) and signs its attestation with slot 85 (touch).
  - After that, every approved request is one PIN verify and one private-key operation on 86–89.

## 6. Client checks [each one triggers a card operation through the approver]

These are the same checks as milestone 3, run against `target/debug/librelay_pkcs11.dylib`:

- ECDSA-SHA256 with `hw-sign`
- raw ECDSA with `hw-auth`
- RSA-OAEP decryption with `hw-unseal`
- EdDSA with `hw-sign-ed25519`
- refusals (role and mechanism)

OpenSSL verifies every signature.
