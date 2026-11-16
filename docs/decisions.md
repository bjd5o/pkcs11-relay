# Decisions

Decisions taken where `docs/spec.md` was silent or had to change. Newest last; never rewrite an entry, supersede it.

Format: `## YYYY-MM-DD: title`, then context, decision and consequences in a few lines.

## 2026-11-15: Defaults for unspecified wire details

Context: the spec fixes message fields and verification order but not encodings.
Decision: adopt the defaults table in `docs/milestones-1-4.md` (fingerprints, CBOR, signed bytes, HPKE suite, relay auth, pairing code) unless milestone 1 finds a reason to change one.
Consequences: `docs/wire-format.md` is written from that table and reviewed before the core is built.

## 2026-11-15: No real consumer service in CI or the proof of concept

Context: the original plan used an OpenBao container as the end-to-end check.
Decision: gates use third-party PKCS#11 callers instead: `pkcs11-tool`, OpenSSL 3 with `pkcs11-provider`, and `ssh -I`.
Consequences: OpenBao stays the motivating consumer in the spec, but nothing in CI depends on it.

## 2026-11-15: Manifest keys carry their public key

Context: the spec's manifest lists only a fingerprint per key and the attestation statement only `attest_key_fingerprint`, so `verify_attestation` had no public key to check the statement's signature with.
Decision (approved by Brian): every manifest entry carries `public_key` (base64 DER SPKI); `verify_manifest` checks `fingerprint` and `algorithm` against it. The provider uses the manifest's copy of each key; the relay's advertisement only says which manifest keys are reachable.
Consequences: the attestation verifier needs nothing beyond the manifest. `docs/spec.md` is unchanged; `docs/wire-format.md` §9.2 has the field.

## 2026-11-15: Responses carry an optional reason code

Context: the Failure handling table says the provider logs the reason for a signed error, but the response had no field for one.
Decision (approved by Brian): optional `reason` text code, only with `denied` or `error`, covered by `device_sig`; codes in `docs/wire-format.md` §6.1. Return codes stay as the table says.
Consequences: the reason is logged, never trusted beyond "an attested device said so".

## 2026-11-15: Relay auth carries a nonce

Context: Ed25519 is deterministic, so identical calls in the same second would carry identical signatures and be rejected as replays.
Decision (approved by Brian): `X-Relay-Nonce` (16 random bytes) is part of the relay-auth signed bytes; the relay rejects a (key, nonce) pair seen in the last 120 s.
Consequences: `docs/wire-format.md` §8. The defaults table's signed-bytes line is superseded by that section.

## 2026-11-15: Strict encodings and narrow algorithm choices

Context: the spec leaves encoding details open.
Decision: as listed at the end of `docs/wire-format.md`: RSA exponent 65537 only, uncompressed P-256 points only, OAEP SHA-256/MGF1-SHA256 only, request `input` capped at 32 KiB, one OpenPGP signature packet of type `0x00` with SHA-256 or stronger, signer-key expiry ignored, `responded_at` informational, attestation embedded as a byte string, integer manifest timestamps, strict decoding everywhere.
Consequences: anything outside these is rejected; loosening one is a new decision.

## 2026-11-15: Tooling through flox and mise

Context: the machine's tools come from the default flox environment (`~/.dotfiles/zdotdir/zsh/flox`), and its current Docker context is a remote host.
Decision: `mise.toml` pins Rust 1.93.0 with rustfmt and clippy, and sets `DOCKER_CONTEXT=colima`; gpg and the docker CLIs come from the flox environment (mise has no gpg package).
Consequences: every docker command in this project runs on the local colima VM, never on the remote context.

## 2026-11-15: Response check 5 runs after opening the result

Context: the spec's check 5 (a signature result verifies against the hardware key) needs the sealed result opened, but the spec says to open after all five checks.
Decision (approved by Brian): checks 1–4, then open and zero the reply key, then check 5; a failure there zeroes the plaintext and returns `CKR_DEVICE_ERROR`.
Consequences: nothing is decrypted before the attestation and device signature have been verified. `docs/wire-format.md` §6.2.

## 2026-11-15: Pairing code is a diceware phrase of at least 50 bits

Context: the defaults table's 40-bit base32 code is hard to compare and somewhat weak against an attacker who sees the code and grinds keys within the pending window.
Decision (Brian): four words from the EFF large wordlist (7 776 words, about 51.7 bits), derived from the first 8 bytes of SHA-256 over the client SPKI. The minimum is 50 bits.
Consequences: supersedes the "Pairing code" row of the defaults table. The wordlist is vendored into `relay-core` (to be downloaded with Brian's OK). `docs/wire-format.md` §10.1.

## 2026-11-15: OAEP decoding and PKCS#1 v1.5 signature padding vendored from rsa 0.10

Context: the spec puts OAEP decoding and DigestInfo padding around the card's raw RSA in `relay-core`, but `rsa` 0.10 keeps both `pub(crate)` and no other audited crate exposes them. CLAUDE.md forbids custom cryptography.
Decision (Brian): copy `rsa` 0.10's OAEP decoding (`decrypt_inner`, MGF1) and `pkcs1v15_sign_pad` into `relay_core::padding`, with attribution (MIT OR Apache-2.0). Adapt it to `subtle` for constant-time operations (`subtle` added as a direct dependency) and restore the RFC 8017 leading-zero-byte check, also in constant time. Cross-test against `rsa`'s own OAEP encryption and PKCS#1 v1.5 verification. Ask upstream to expose these under `hazmat`.
Consequences: an OAEP decoding failure is reported exactly like any other card failure (`status = error`, `reason = card_error`), so the relay never sees a distinguishable padding oracle. Human approval already makes each oracle query cost an approval.

## 2026-11-15: Milestone 1 implementation choices

Context: details the spec, the milestone doc and the wire format left to implementation.
Decision:
- `relay-core` has a `test-util` feature exposing `Manifest::from_json_unverified` and reply-key import/export, for tests, vectors and fuzzing only. No production crate enables it.
- `ManifestDraft` (an editable manifest that serialises to validated JSON) lives in the core, so `relayctl manifest add|remove` and the fixture generator share the manifest validation.
- The golden-vector fixture's private keys are committed under `crates/relay-core/tests/vectors/fixture/`. They are throwaway test keys and protect nothing.
- OpenPGP vectors are made by `tests/vectors/pgp/make.sh` with gpg 2.4 in a temporary `GNUPGHOME`, with `--faked-system-time` set to the fixture's `issued_at`. A YubiKey OpenPGP card signature is added in milestone 4.
- PIV ECDSA takes a 32-byte digest: a longer input is truncated to its leftmost 32 bytes (FIPS 186-4) and a shorter one is left-padded with zeros (the same integer).
- `Manifest::tokens()` (one slot per token) ignores tokens that contain only `attest` keys, since those are never exposed.
- `fuzz/` sits outside the workspace with `libfuzzer-sys` 0.4.13. CI only compile-checks it on stable.
Consequences: none on the wire format.

## 2026-11-15: ECC `encrypt` keys deferred

Context: Brian asked whether `encrypt` keys could be EC as well as RSA.
Decision (Brian): defer until after the MVP. PKCS#11 has no `C_Decrypt` for EC keys. The equivalent is ECDH through `C_DeriveKey` (`CKM_ECDH1_DERIVE`), which needs a `derive` operation, secret-key session objects and KDF parameters, and the motivating consumer (OpenBao's seal) supports only RSA-OAEP and AES-GCM.
Consequences: `encrypt` stays RSA-only with `CKM_RSA_PKCS_OAEP`. Adding ECDH later means a spec change, a new wire `op`, the card's ECDH command and `C_DeriveKey` in the provider. The role and mechanism checks all live in `relay_core::mechanism`.

## 2026-11-15: Milestone 2 implementation choices

Context: details the spec and milestone doc left open for the relay and the test approver.
Decision:
- **Pairing endpoints:** `POST /v1/clients/{id}/approval` (device-authenticated, naming the pending key's fingerprint and the approved keys) and `GET /v1/clients/self` (the client polls its status). The approved keys come from the manifest and need not be on the approving device, so one approval can cover keys on several devices. Bodies are in `docs/wire-format.md` §10.
- **Device registration is open** (no admin step), as the spec's enrollment flow implies. It is bounded by `max_devices`, rate limits, and a device id staying bound to its first key until `admin devices revoke`. A rogue device gains nothing: clients reject unattested responses.
- **The relay serves plain HTTP.** TLS is terminated by a reverse proxy, one of the two options the spec allows. Whether the relay should terminate TLS itself is decided in milestone 3, when the provider's TLS trust settings are built.
- **Relay hygiene checks are in the core:** `request::verify_for_relay` and `response::verify_for_relay`, called by the server.
- **Software OpenPGP signing is in the core** (`PgpSecretKey`): the fixture generator uses it, and `relayctl` will use it when no card is involved. rPGP 0.21 needs a `rand_core` 0.6 RNG, so the core names `rand_core` 0.6.4 directly (already in the tree through `pgp`).
- **The fixture generator is `relay-test-approver gen-fixtures`,** not `relayctl dev`, so the shipped admin CLI does not depend on the test-only softcard.
- **Fixtures model three devices:** A approves and pairs the client, B denies after a delay, C has an expired attestation. All share one attest key, and each operates its own keys. That gives every negative path a distinct key.
- **The test approver enters the PIN before every operation, and stops after one wrong PIN** (CLAUDE.md hardware safety). Requests that fail checks get a signed denial with reason `policy` (`expired` for expired requests).
- **`sqlx` 0.8.6, not 0.9:** 0.9 needs rustc 1.94 and `mise.toml` pins 1.93.
- **TLS clients (`reqwest`) use rustls with `ring`,** not aws-lc-rs, so static musl builds need only `cc`.
- **`tower-http` was approved but is not used:** axum's own body limit covers the need.
Consequences: wire-format §10 is final for the MVP relay API.

## 2026-11-15: PKCS#11 front end written on cryptoki-sys, not forked from native-pkcs11

Context: milestone 3's first task is a spike: fork google/native-pkcs11's front end, or write one on `cryptoki-sys` types.
Findings: native-pkcs11 0.2.27 has no `catch_unwind` at any export (CLAUDE.md requires it everywhere). It exposes a single slot, and its `Backend` trait is shaped around keychain search. `C_Decrypt*` are stubbed. It uses the `pkcs11-sys` bindings and pulls in `cached`, `tracing-journald` and a keychain backend. Forking would mean rewriting most of its session and object logic anyway.
Decision: a small front end of our own in `relay-pkcs11`, on `cryptoki-sys` 0.5.0. That crate has committed bindings keyed by OS and architecture, so it covers Linux glibc and musl on x86_64 and aarch64, and macOS.
Consequences: we own the C ABI module (the only `unsafe` in the workspace). native-pkcs11 informs the structure but no code is copied.

## 2026-11-15: Relay TLS trust is a CA file only, for the MVP

Context: the spec offers "CA file, or a pinned SPKI hash". `ureq` 3 supports trust anchors in its stable API, but an SPKI pin needs a custom rustls verifier, which `ureq` only allows through its unstable `unversioned` connector API.
Decision (Brian): the provider ships `relay_ca_file` (PEM trust anchors) only. SPKI-hash pinning is a later addition. The relay terminates TLS itself (`axum-server`, rustls with `ring`), when given `tls_cert` and `tls_key`.
Consequences: a client trusts exactly the CAs in its file. The test fixtures make a private CA and a relay certificate for `relay`, `localhost` and `127.0.0.1`.

## 2026-11-15: The provider implements C_Encrypt in software; spec updated

Context: the spec's role table exposes `encrypt` public keys with `CKA_ENCRYPT`, saying encryption runs in software, but its function table did not list `C_Encrypt`. OpenBao's seal may call it.
Decision (Brian): `C_EncryptInit` / `C_Encrypt` with `CKM_RSA_PKCS_OAEP` (SHA-256) on the public object of an `encrypt` key, using the `rsa` crate's OAEP encryption through `relay_core::padding::encrypt_oaep_sha256`. No request and no approval are involved. Brian also approved updating `docs/spec.md` with every departure approved so far: manifest public keys, reason codes, the relay-auth nonce, check-5 order, the diceware pairing code, the pairing endpoints, relay trust as a CA file for the MVP, C_Encrypt, and ECC `encrypt` deferred.
Consequences: `docs/spec.md` now matches `docs/wire-format.md` on these points.

## 2026-11-15: Milestone 3 implementation choices

Context: details that came up while building the provider and running third-party callers.
Decision:
- **Two client rate limits at the relay.** `client_requests_per_minute` (default 30) counts only submitted requests, which is what bounds approval prompts. `client_calls_per_minute` (default 600) covers discovery and long-polls. A single limit counting every call starved ordinary `pkcs11-tool` runs.
- **`C_SignUpdate` accepts raw mechanisms too** (`CKM_ECDSA`, `CKM_RSA_PKCS`). They are single-part in PKCS#11, but `pkcs11-tool` retries a failed `C_Sign` as Update/Final. Refusing that retry hid the real error (for example `CKR_FUNCTION_REJECTED`) behind `CKR_FUNCTION_NOT_SUPPORTED`. Length limits still apply when the request is built, and each retry is a new request, as the spec allows.
- **Slots are the manifest's tokens.** A slot shows only the keys the relay also lists. Slot ids are stable, ordered by token name.
- **One exported symbol.** The module exports only `C_GetFunctionList`, and the other 67 entries are reachable through the table. The 41 unsupported entries are stubs generated from cryptoki-sys's `CK_C_*` types.
- **Linux builds.** glibc builds come from Debian bookworm (glibc 2.36 baseline). musl builds come from Alpine, linked dynamically against musl (`-C target-feature=-crt-static`), because a statically linked musl target cannot produce a `cdylib`. The musl module therefore needs Alpine's `libgcc` package at run time (`libgcc_s.so.1`, the unwinder behind `catch_unwind`). `-static-libgcc` does not help, because Rust's unwind crate links `gcc_s` explicitly. Dropping the dependency would mean `panic=abort` with `-Zbuild-std`, which loses the panic guard CLAUDE.md requires. Both are built natively for x86_64 and aarch64 in CI, and locally with `deploy/build-provider.sh`.
- **p11-kit registration** is `deploy/relay-pkcs11.module`, installed to `/usr/share/p11-kit/modules/`, with `trust-policy: no`.
Consequences: none on the wire format.
