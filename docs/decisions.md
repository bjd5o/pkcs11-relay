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

## 2026-11-15: Confidentiality-operation content never leaves RAM

Context: Brian asked to make sure the content of encryption and decryption requests is never stored outside RAM, audit logs included. An audit found that the relay's SQLite audit log stored full decrypt requests (the ciphertext), the device-signed responses (the sealed plaintext), and the raw bodies of rejected requests. No other component writes content: the provider caches only the manifest, the key list and its client key, and the logs carry only metadata.
Decision (Brian): for every operation other than `sign`, the audit log keeps metadata plus SHA-256 hashes of the input, request and response, never their bytes. Rejected request bodies are never stored, only their hash. Sign requests and responses are still kept in full, as the spec's audit design intends. `docs/spec.md` is updated.
Consequences: `crates/relay-pkcs11/tests/module.rs` scans every file the relay (including SQLite's WAL), the approvers and the provider write, and fails if any plaintext or ciphertext window appears. It catches the old behaviour. Residual risk, not addressed: process memory can reach swap or a core dump on any host. Mitigating that needs `mlock` and core-dump limits, which require `unsafe` outside the provider, or host configuration such as encrypted swap.

## 2026-11-15: ECC encryption and P-384 signing (supersedes "ECC encrypt keys deferred")

Context: Brian asked for ECC encryption before milestone 4.
Decision (Brian):
- **Curves.** `encrypt` keys may be RSA, P-256, P-384 or X25519, reusing the `encrypt` role. EC `encrypt` keys work through ECDH: `CKM_ECDH1_DERIVE` in `C_DeriveKey`, a new wire `op = "derive"`, and PIV `GENERAL AUTHENTICATE` with tag `85` on the card. P-384 is also allowed for `sign` (`CKM_ECDSA_SHA384`) and `auth` (`CKM_ECDSA`).
- **KDFs.** `CKD_NULL` (the raw shared secret, truncated to the requested length) and `CKD_SHA256_KDF` (ANSI X9.63 with SHA-256 and optional shared data) both run on the approver after the card operation.
- **The derived key is chosen by template.** The derived value comes back sealed to the reply key, like an RSA decrypt result, and becomes a session-only secret-key object in the provider's RAM.
  - With `CKA_EXTRACTABLE` true and `CKA_SENSITIVE` false, the consumer can read `CKA_VALUE`.
  - Otherwise the value stays inside the provider. For `CKK_AES` keys, the consumer uses it only through `CKM_AES_GCM` in the provider's `C_Encrypt` / `C_Decrypt`.
  - `CKA_TOKEN = TRUE` is refused. Objects are zeroized when destroyed or when their session closes.
- **Dependencies (approved):** `p384` 0.14.0, `x25519-dalek` 3.0.0, `aes-gcm` 0.11.1 and `ansi-x963-kdf` 0.1.0.
Consequences: `docs/spec.md` and `docs/wire-format.md` gain the new algorithms, mechanisms and the `derive` operation. Device and attest keys stay P-256.

## 2026-11-15: Ed25519 sign and auth keys

Context: Brian asked for Ed25519 signing and authentication.
Decision: Ed25519 hardware keys may hold `sign` or `auth`, with `CKM_EDDSA` as pure Ed25519 over the whole message. `CK_EDDSA_PARAMS` asking for Ed25519ph or a context is refused with `CKR_MECHANISM_PARAM_INVALID`. On the card it is PIV algorithm `0xE0` (YubiKey firmware 5.7+). Check 5 verifies with `verify_strict`. Key objects use `CKK_EC_EDWARDS`, and X25519 keys `CKK_EC_MONTGOMERY`; `CKA_EC_PARAMS` holds the RFC 8410 OID and `CKA_EC_POINT` a DER OCTET STRING of the 32-byte key. No new dependency: `ed25519-dalek` was already used for client keys.
Consequences: because EdDSA signs the whole message, `auth` Ed25519 keys receive full messages, not digests, and so do `sign` keys.

## 2026-11-15: ECDH errors and KDF truncation

Context: details of the ECDH implementation.
Decision: an ECDH peer key that is malformed, the wrong length or off the curve is a mechanism-parameter error (`CKR_MECHANISM_PARAM_INVALID`), since PKCS#11 passes it in `CK_ECDH1_DERIVE_PARAMS`. `CKD_NULL` with a shorter requested length keeps the leading bytes of the shared secret. A derived generic secret defaults to extractable and not sensitive. A derived AES key defaults to non-extractable and sensitive, with `CKA_ENCRYPT` / `CKA_DECRYPT` true, and requires `CKA_VALUE_LEN` of 16, 24 or 32.
Consequences: `crates/relay-pkcs11/tests/ecc.rs` covers each rule.

## 2026-11-15: Milestone 4 card access (yubikey 0.8, relay-pcsc)

Context: the spec names the `yubikey` crate for enrollment. Its 0.9 release candidate needs an `rsa` feature that rsa 0.10.0 removed, so it cannot share the workspace's rsa. Brian chose 0.8.0 stable.
Decision: relayctl uses `yubikey` 0.8.0 only for administrative operations: management-key authentication, key generation and writing a self-signed certificate. 0.8 generates RSA-2048, P-256 and P-384 keys only, and authenticates only with 3DES management keys. For RSA-4096, Ed25519 and X25519 keys, or a card whose management key is AES (the default on firmware 5.7 and later), relayctl prints the `ykman piv keys generate` / `certificates generate` commands instead and imports the result with `relayctl manifest add --serial --slot`. Its certificate API uses the older RustCrypto generation (p256 0.13, p384 0.13, x509-cert 0.2.5), already in the tree through pgp, pulled in as renamed workspace dependencies `p256-013`, `p384-013` and `x509-cert-02`. No types cross into relay-core: after generation, relayctl reopens the card and reads the public key through relay-core's PIV layer. Every other card operation (listing, export, attestation signing, approver operations) goes through relay-core's PIV layer over a new `relay-pcsc` crate (`pcsc` 2.9), which implements `CardTransport`. `relay_pcsc::open` refuses unless `RELAY_TEST_YUBIKEY_SERIAL` is set and equals the requested serial, and then connects only to the reader whose PIV `GET SERIAL` returns that serial.
Consequences: in milestone 4, keys of the other algorithms are generated with ykman. A later `yubikey` release that builds with rsa 0.10 can replace this (relayctl's `keygen.rs` is the only user). A rejected PIN stops relayctl and the test approver after one attempt: the approver treats a rejected startup PIN as fatal rather than retrying startup, and refuses all further operations after a rejected PIN during operation.

## 2026-11-17: Milestone 5 plan

Context: open points in the Apple approver app, settled in `docs/milestone-5.md`.
Decision (Brian):
- The Secure Enclave device key carries `.biometryCurrentSet`, with one Face ID per approval reused for the signature. Requests that fail checks are denied with a signature when the user next opens the app, or they expire.
- The Xcode project is generated by XcodeGen; the team ID lives in a git-ignored `Local.xcconfig`.
- The relay serves the signed manifest at `GET /v1/manifest` and `/v1/manifest.asc` (spec updated).
- Part A and the iPhone gate come first, then iPad and Mac card access and APNs.

Decision (proposed by Claude, accepted with the plan):
- The approver flow moves from `relay-test-approver` into a shared `relay-approver` crate wrapped by `relay-ffi`.
- Networking and TLS trust stay in Rust (`ureq`).
- PIN, card operation and sealing run in one Rust call, so plaintext never crosses the FFI.

## 2026-11-17: Card sessions: exclusive access, then no PIN left verified

Context: on macOS every smart-card client goes through CryptoTokenKit. `relay-pcsc` connected in shared mode without transactions, and the test approver kept its connection open. Another program could interleave commands between our `VERIFY` and the operation, and could use a PIN-policy-`once` key afterwards without the PIN, because PIV keeps the PIN verified until the card is reset.
Decision (Brian approved the fix): `CardTransport` gains `session(f)` and relay-core has `piv::in_session`. Every PIN verification and the operations that follow it run inside one session.
- **PC/SC:** the session reconnects, begins a transaction, rechecks the card's serial, runs `f` and ends with `SCARD_RESET_CARD`.
- **Softcard:** a session ends with a reset, and the card counts sessions so tests can check them.
- **gpg conflict:** a sharing violation is reported as "card busy" with the gpg fix (`pcsc-shared` or `gpgconf --kill scdaemon`), because gpg's scdaemon holds the card exclusively by default.

Consequences: relayctl (list, export, attest) and the test approver (key discovery, attestation, every operation) use sessions. Not yet verified on hardware: whether macOS's PC/SC layer honors `SCARD_RESET_CARD` at the end of a transaction. A one-command check against slots 85–89 needs Brian's approval.

## 2026-11-17: Separate relay-auth key for devices (spec updated)

Context: the device key signs every relay HTTP call as well as responses. With `.biometryCurrentSet` on the Secure Enclave key, every long-poll would need Face ID.
Decision (Brian): devices may register a separate P-256 relay-auth key.
- The device key signs `relay-pkcs11/auth-key/v1 || 0 || device_id || 0 || fingerprint(auth_key)` once at enrollment. Registrations carry `auth_key` and `auth_key_sig`, and are signed by the auth key.
- The relay verifies the binding (`relay_core::relay_auth::verify_auth_key_binding`) and from then on authenticates the device's calls by the auth key.
- Without an auth key, the device key authenticates as before; the test approver works this way.

Consequences:
- Relay `devices` table: new `auth_key` and `auth_fingerprint` columns, with a migration that fills them from the device key for existing rows.
- wire-format §8.4 and §10 and spec updated.
- Clients are unaffected: responses still carry the device-key signature and its attestation.
- `relay-test-approver/tests/app_flow.rs` runs the app path against a real relay: blocking client, separate auth key, pairing and one request.

## 2026-11-17: Hardware attestation of attest keys (spec updated)

Context: clients trusted an `attest` key only because the PGP-signed manifest listed it. Nothing showed it was generated on a YubiKey or that touch is enforced on it. Brian plans to generate the operation keys offline, import them onto two interchangeable YubiKeys, and generate one attest key on each card. The design is in `docs/hw-attestation.md`.
Decision (Brian approved the design):
- **Manifest:** keys may carry `hardware_attestation`, a YubiKey PIV attestation chain. It is required on `attest` keys by default; `require = false` turns that off explicitly.
- **Accepted chains:** only firmware 5.7.4 and later, under `Yubico Attestation Root 1`. Minimum firmware is 5.7.4.
- **Policy:** the attest key must have touch `always` and a PIN policy other than `never`. Any bad evidence invalidates the whole manifest.
- **Verifier:** path validation uses `rustls-webpki` (=0.103.17, already in the provider and iOS trees through rustls). `x509-cert` reads the Yubico extensions. Both live in relay-core.
- **No serial pinning,** on clients or on the relay. Pushing serials to every client costs more than the protection against a stolen PGP key is worth. On the relay, pinning adds nothing while the relay also serves the manifest.
- **Relay:** it verifies the manifest it serves, filters `GET /v1/keys` through it, and rejects device registrations whose attestation does not verify. If the manifest is invalid it advertises nothing and logs why. Providers still verify everything.

Consequences:
- The serial is inside the leaf certificate, so the published manifest names the card serials. Real chains are never committed; tests use a synthetic hierarchy in relay-softcard.
- Existing fixtures and gate manifests need chains, or `require = false`.
- The relay checks only who signed a device's attestation, not its window (`relay_core::attestation::verify_attestation_signer`). Renewal happens during an approval, so a relay that dropped expired devices would never let them renew. Clients still reject expired attestations (Failure handling row unchanged).

## 2026-11-17: Signed setup links, manifest device policy, relay watches the signer (spec updated)

Context: the app was configured by copying a `setup.json`. Brian wants a QR code from `relayctl` instead. The design is in `docs/setup-link.md`, which Brian approved and edited.
Decision (Brian):
- **Setup link:** `relayctl app-link` prints a `poh://setup?…` link and its QR code. The link pins the relay CA (SPKI hash) and the manifest signer (fingerprint), names the device, carries `iat`/`exp` (default 15 minutes, at most 7 days) and is signed by the manifest signer over everything before `&sig=`. `qrcode =0.14.1` (relayctl only, no default features, `svg`) renders it.
- **App:** it rejects a link outside its time window, checks both pins and the signature, and refuses a signer key that is revoked or expired, from the relay's copy or keys.openpgp.org's. It shows the signer identity keys.openpgp.org verified, or explains why it could not. No privacy note on that screen. The file import and `relayctl app-config` go away.
- **Manifest:** `require_hardware_attestation` moves from client and app configs into the manifest. A new `max_attestation_window_secs` (default 7 days) caps every attestation window; each device chooses its own at setup.
- **One link, one device:** the link fixes the device id. A device id the relay does not hold, including a revoked one, registers only with a setup link, which the relay checks (signed by its own manifest signer, signer usable, in time, same device id, unused).
- **Single-use links (Brian's edits to the design):** `used_setup_links` stores the SHA-256 of the link's signed bytes only, never the signature, so a second valid signature over the same bytes cannot make a used link new. The device record and the audit log store the same hash.
- **Relay watches the signer key:** from its file (every minute) and keys.openpgp.org (every 15 minutes). While the key is revoked or expired, it advertises no keys, cancels pending requests and refuses client and device calls. It fails open when the keyserver is unreachable. A seen revocation persists until the signer key changes.

Consequences: new Failure handling row (signer revoked or expired, seen by the relay); `AttestationWindowTooLong` joins the attestation row; wire-format §5.1 step 5, §9.2 fields, §10 and a new §11.
- Correction (Brian, 2026-11-18): the new Failure handling row first said "Zero slots". The provider builds slots from the manifest's tokens and fills them from the relay's key list, so with the signer unusable it keeps the slots and lists no keys in them. The row now says "Slots without keys"; the provider is unchanged.

## 2026-11-18: Milestone 5 Part B design (USB card access and APNs)

Context: plan items 5.6 and 5.7. The design is in `docs/milestone-5b.md`.
Decision (Brian):
- **USB card access:** one Swift `TKSmartCard` (CryptoTokenKit) transport for Mac, iPad and USB-C iPhone. It replaces the plan's `relay-pcsc` on the Mac.
- **PIN state:** CryptoTokenKit has no card reset, so every session ends with `VERIFY` P1=`FF` (NIST SP 800-73-4, reset security status). It is confirmed on the YubiKey 5C Nano before it is relied on, each command approved by Brian.
- **APNs:** reqwest's `http2` feature is enabled (h2 was already in the tree). The relay signs ES256 tokens with relay-core's P-256 signing.
- **Gate:** the USB-C iPad is part of the Part B gate.
- **Setup picker:** 15- and 30-minute attestation windows are added.

