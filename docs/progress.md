# Progress

Update this file as tasks finish. Each milestone's gate is defined in `docs/milestones-1-4.md`.

## Milestone 1: protocol and core

- [x] Cargo workspace and CI skeleton (fmt, clippy, test)
- [x] `docs/wire-format.md` written and reviewed by Brian (pairing endpoints finalised in milestone 2)
- [x] `relay-core::wire` (deterministic CBOR types; modules `cbor`, `attestation`, `request`, `response`)
- [x] `relay-core::keys` (fingerprints, SPKI, roles)
- [x] `relay-core::manifest` (OpenPGP verification, freshness)
- [x] `relay-core::attestation`
- [x] `relay-core::request` / `response` (five-step verification)
- [x] `relay-core::seal` (HPKE)
- [x] `relay-core::piv` and `padding` (OAEP and PKCS#1 v1.5 padding vendored from `rsa` 0.10)
- [x] `relay-core::content` (hex-and-hash view)
- [x] `relay-softcard`
- [x] Test vectors, including `gpg`-made OpenPGP signatures (a signature made on a YubiKey OpenPGP card comes in milestone 4)
- [x] Fuzz targets (`mise run fuzz <target>`; each ran 60 s on 2026-11-15 with no crashes)
- [x] Gate passed (2026-11-15): `cargo test -p relay-core`, with a named negative test for every core-detectable failure row (`tests/failure_table.rs`, `tests/manifest_pgp.rs`)

## Milestone 2: relay and test approver

- [x] `relay-server` API, auth, registries, pairing (endpoints in `docs/wire-format.md` §10)
- [x] Pending queue, long-poll, WebSocket
- [x] Audit log, rate limits, health and metrics, admin subcommands
- [x] ntfy and no-op notifiers (APNs/FCM stubs behind `Notifier`)
- [x] `relay-test-approver` (softcard; `--pcsc` in milestone 4)
- [x] Fixture generator (`relay-test-approver gen-fixtures`)
- [x] `deploy/Dockerfile.relay` (static musl, distroless, non-root; arm64 on colima; amd64 in GitHub Actions, where the integration job builds it)
- [x] Gate passed (2026-11-15): `docker compose -f deploy/compose.test.yml up --build --exit-code-from client` exits 0 on colima, and the same gate runs in-process in `cargo test`. Passes in GitHub Actions on amd64 (first run 2026-11-16).

## Milestone 3: provider on Linux

- [x] Front-end spike and decision recorded (own front end on `cryptoki-sys`)
- [x] Discovery and role enforcement
- [x] Sign and decrypt through the relay, response verification; `C_Encrypt` in software
- [x] Client pairing from the provider
- [x] glibc and musl builds; p11-kit module file (aarch64 glibc and musl built and loaded locally; all four built in GitHub Actions since 2026-11-16, x86_64 not yet loaded by a client outside the amd64 Docker gate; musl needs `libgcc` at run time)
- [x] `deploy/compose.test.yml` and `tests/` scripts
- [x] Relay terminates TLS (axum-server); test clients trust a private CA
- [x] In-process provider test through the C function table (`crates/relay-pkcs11/tests/module.rs`)
- [x] Gate passed (2026-11-15): `docker compose -f deploy/compose.test.yml up --build --exit-code-from client` exits 0 on colima (arm64), running the milestone 2 and 3 gates: `pkcs11-tool`, OpenSSL `pkcs11-provider`, `ssh -I`. Passes in GitHub Actions on amd64 (2026-11-16).

## Between milestones 3 and 4 (Brian's requests, 2026-11-15)

- [x] Confidentiality-operation content never stored outside RAM: relay audit log fixed; disk-scan test in `crates/relay-pkcs11/tests/module.rs`
- [x] ECC encryption: ECDH via `C_DeriveKey` on P-256, P-384 and X25519; `CKD_NULL` and `CKD_SHA256_KDF`; derived keys extractable or not, by template; AES-GCM with non-extractable derived keys
- [x] P-384 signing (`CKM_ECDSA_SHA384`, `CKM_ECDSA`) and Ed25519 signing (`CKM_EDDSA`) for `sign` and `auth` keys
- [x] Tests: softcard round trips against software ECDH, X9.63 and signature checks; `crates/relay-pkcs11/tests/ecc.rs`; the Docker gate adds `pkcs11-tool` ECDH (P-256, P-384), ECDSA-SHA384 and EdDSA checks. X25519 has no third-party PKCS#11 caller in Debian trixie (`pkcs11-tool` cannot parse its peer keys; `pkcs11-provider` 1.0 rejects `CKK_EC_MONTGOMERY`), so only the in-process test covers it

## Milestone 4: relayctl and real hardware

- [x] `relay-pcsc`: PC/SC `CardTransport` behind the `RELAY_TEST_YUBIKEY_SERIAL` interlock, selecting the reader by PIV serial
- [x] `relayctl key generate|list|export` (generate: RSA-2048, P-256, P-384 with yubikey 0.8 and a 3DES management key; other algorithms print ykman commands, see decisions)
- [x] `relayctl manifest init|add|remove|show|sign|verify` (sign through `gpg --detach-sign`, so an OpenPGP card works through gpg-agent, or a software rPGP key)
- [x] `relayctl attest sign`
- [x] `relayctl relay clients|devices|audit` (wraps `relay-server admin`)
- [x] `relay-test-approver run --pcsc` (`pcsc_serial` in the config)
- [x] Tests without hardware: manifest round trip, rollback and tamper checks, attestation through the softcard, one-PIN-attempt rule, gpg signing in a throwaway `GNUPGHOME` (`crates/relayctl/tests/flows.rs`); fatal startup PIN (`crates/relay-test-approver/tests/e2e.rs`)
- [x] `relay-test-approver run --pin-stdin`: the PIN is read without echo and never written to disk
- [x] Gate passed (2026-11-16) on Brian's Mac (macOS, Apple silicon) with YubiKey <serial>, slots 85–89, run by Brian per `docs/m4-gate.md`:
  - Keys: attest P-256, hw-sign P-256, hw-auth P-256, hw-unseal RSA-2048, hw-sign-ed25519 Ed25519. They were generated with ykman, because the card's management key is AES-256 (see decisions).
  - The manifest was built with `relayctl manifest add` from the PEM files, signed through gpg by Brian, and checked with `relayctl manifest verify`.
  - The local relay ran with TLS. `relay-test-approver --pcsc --pin-stdin` attested with slot 85.
  - The provider ran as a macOS `.dylib` under opensc `pkcs11-tool`, paired, and listed one token with four keys.
  - ECDSA-SHA256 (hw-sign), raw ECDSA (hw-auth), RSA-OAEP decryption (hw-unseal) and EdDSA (hw-sign-ed25519) all succeeded, and OpenSSL verified each result. The role and mechanism refusals returned the expected codes.
  - Not covered by this gate: `relayctl key generate` on hardware (needs a 3DES management key) and `relayctl attest sign` on hardware. The softcard tests cover both.

## Milestone 5: Apple approver app (plan: `docs/milestone-5.md`)

Part A:
- [x] 5.0 The relay serves the signed manifest (`/v1/manifest`, `.asc`); the provider and test approver trust the relay CA for it. The Docker gate fetches it this way.
- [x] 5.1 `relay-approver`: the engine (checks, approval view, PIN and operation in one card session, sealing, signing, renewal during approvals, pairing with locally derived codes, key map) and a blocking relay client. The test approver now runs on it.
- [x] Separate relay-auth key (wire-format §8.4): the device key, which requires a biometric per signature, signs only responses, denials and the auth-key binding.
- [x] 5.2 `relay-ffi` (UniFFI 0.32.2): `DeviceKey` and `CardChannel` foreign traits, an `Approver` object, saved state. `RelayFFI.xcframework` covers iOS, the simulator and Apple silicon macOS.
- [x] 5.3 App skeleton: SwiftUI multiplatform (XcodeGen), Setup, Enrollment, Approval, Pairing and Status screens, Secure Enclave keys, storage; `relayctl app-config` writes the setup file.
- [x] 5.4 NFC `CardChannel` (CoreNFC, ISO 7816). Builds; not yet run on a device.
- [x] 5.5 Simulator end-to-end test (`tests/sim-e2e.sh`), passing locally (2026-11-17). A relay runs on the Mac; the app in the iOS simulator uses relay-ffi's software test card; an XCUITest enrolls, approves the pairing and approves an RSA-OAEP decrypt with the PIN; `relay-test-approver sim-client` verifies the plaintext as the provider would. CI job `apple` (macos-15) passes too (first run 2026-11-17).
- [ ] Gate on Brian's iPhone over NFC with YubiKey <serial>

Hardware attestation of attest keys (design `docs/hw-attestation.md`, approved 2026-11-17):
- [x] Spec, wire-format §9.2/§9.4 and decisions updated
- [x] relay-core: `verify_piv_attestation` (rustls-webpki path validation under `Yubico Attestation Root 1`, the PIV branch, key binding, Yubico extensions, firmware 5.7.4+), unit tests and golden vectors (`tests/vectors/hw-attestation`)
- [x] Manifest field `hardware_attestation` and `HardwarePolicy` in `verify_manifest`: required on attest keys by default, touch `always`, PIN policy not `never`, the whole manifest invalid on bad evidence (`tests/manifest_hw.rs`)
- [x] relay-core PIV `GET ATTESTATION` and the `F9` certificate; the softcard attests generated keys from a synthetic hierarchy and refuses imported ones
- [x] `relayctl manifest add --serial S --slot XX --role attest` reads and verifies the chain (read-only), `--attestation-chain` for chains gathered elsewhere, `show`/`verify` print serial, firmware and policies; `app-config --no-hardware-attestation`
- [x] `[hardware_attestation]` (`require`, test-only `roots_file`) in the provider, the test approver and the relay; the app's setup file carries the same; the engine reports an attest key attested on another card
- [x] Relay: verifies the manifest it serves, advertises and routes only manifest keys from devices whose attestation a manifest attest key signed (window not checked, so expired devices can renew), rejects registrations otherwise, and advertises nothing while the manifest is invalid (`relay-server` `trust` tests)
- [x] Fixtures: the attest key carries a synthetic chain; the m3 gate checks that a manifest whose attest key shows touch `never` gives zero slots
- [ ] Real cards: Brian imports the operation keys onto both YubiKeys, generates an attest key on each, then `relayctl manifest add --role attest` per card (per-command approval)

Signed setup links (design `docs/setup-link.md`, approved 2026-11-17):
- [x] Spec, wire-format (§5.1 step 5, §9.2, §10, new §11) and decisions updated
- [x] Manifest device policy: `require_hardware_attestation` and `max_attestation_window_secs` (default 7 days) in the signed manifest; `AttestationWindowTooLong` on the attestation row; the engine refuses longer windows and renews early when the maximum drops; `relayctl manifest set`; config `require` removed
- [x] relay-core: setup links (`poh://setup?…`, fixed form, signature over the bytes before `&sig=`, id = SHA-256 of those bytes), `signer_status` (revocation and expiry across copies, only verifying signatures count), relay CA pin check; tests and golden vectors, gpg-made signer vectors (`tests/vectors/signer`)
- [x] Relay: `/v1/relay-ca.pem`, `/v1/manifest-signer.asc`; new device ids (also after revocation) admitted only by a setup link signed by its own manifest signer, in time, naming the device and unused (`used_setup_links` stores the signed-bytes hash); signer watch (file every minute, keys.openpgp.org every 15 minutes, fail open, revocation persisted); while unusable it lists no keys, cancels pending requests and refuses client and device calls with 503 `ManifestSignerUnusable` (`relay-test-approver` `tests/setup_and_signer.rs`)
- [x] `relayctl app-link`: prompts or flags, checks the live relay and the signer's status, signs through gpg or a software key, prints the URL and QR code (`qrcode =0.14.1`), `--svg`, `--replace`; `relayctl app-config` removed
- [x] `relay-ffi::setup_from_link` (with `relay-approver::setup`): time window, pinned CA, signer fingerprint, link signature, keyserver identity and status, manifest; the FFI flow test sets up this way
- [x] App: `poh://` URL scheme, confirm screen (fingerprint, identity or warning, link times, device, window picker), file import removed
- [x] Docker gate: a revoked signer makes the relay list no keys (checked last)
- [ ] Spec wording: the new Failure handling row says "Zero slots"; the provider actually keeps the manifest's slots and lists no keys in them (question for Brian)

