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
- [x] `deploy/Dockerfile.relay` (static musl, distroless, non-root; built and run on arm64 only so far, amd64 not yet built)
- [x] Gate passed (2026-11-15): `docker compose -f deploy/compose.test.yml up --build --exit-code-from client` exits 0 on colima, and the same gate runs in-process in `cargo test`. Not yet run in GitHub Actions (no remote).

## Milestone 3: provider on Linux

- [x] Front-end spike and decision recorded (own front end on `cryptoki-sys`)
- [x] Discovery and role enforcement
- [x] Sign and decrypt through the relay, response verification; `C_Encrypt` in software
- [x] Client pairing from the provider
- [x] glibc and musl builds; p11-kit module file (aarch64 glibc and musl built and loaded locally; x86_64 only in the CI matrix, which has not run yet; musl needs `libgcc` at run time)
- [x] `deploy/compose.test.yml` and `tests/` scripts
- [x] Relay terminates TLS (axum-server); test clients trust a private CA
- [x] In-process provider test through the C function table (`crates/relay-pkcs11/tests/module.rs`)
- [x] Gate passed (2026-11-15): `docker compose -f deploy/compose.test.yml up --build --exit-code-from client` exits 0 on colima (arm64), running the milestone 2 and 3 gates: `pkcs11-tool`, OpenSSL `pkcs11-provider`, `ssh -I`. Not yet run in GitHub Actions.

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
