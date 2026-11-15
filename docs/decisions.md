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
