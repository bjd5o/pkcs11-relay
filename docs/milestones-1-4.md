# Milestones 1–4: work breakdown

This phase builds everything except the GUI apps: the shared core, the relay, the Linux/macOS PKCS#11 provider, a headless test approver, and the `relayctl` admin CLI, ending with a real YubiKey in the loop. The source of truth for behavior is `docs/spec.md`; this file turns its "Implementation plan (MVP)" into tasks, fixes the details the spec leaves open, and defines each gate.

No real consumer service (OpenBao or similar) is needed for CI or the proof of concept. Every gate is checked with third-party PKCS#11 callers: `pkcs11-tool` (OpenSC), OpenSSL 3 through `pkcs11-provider`, and OpenSSH (`ssh -I`).

## Cargo workspace

```
pkcs11-relay/
  Cargo.toml                 # workspace; all dependency versions pinned here
  crates/
    relay-core/              # wire format, verification, crypto, PIV over APDUs  (#![forbid(unsafe_code)])
    relay-softcard/          # software PIV card behind CardTransport, for tests only
    relay-pkcs11/            # cdylib + staticlib PKCS#11 provider (the only crate allowed `unsafe`)
    relay-server/            # axum relay, SQLite registries, Dockerfile in deploy/
    relay-test-approver/     # headless approver: device key + softcard or PC/SC card, auto-approve for CI
    relayctl/                # admin CLI: YubiKey keys, manifest, attestation, relay admin
  fuzz/                      # cargo-fuzz targets for every relay-core parser
  deploy/
    Dockerfile.relay
    compose.test.yml         # relay + test approver + client container running pkcs11-tool
  tests/                     # integration scripts used by compose and CI
  docs/
    spec.md                  # architecture + MVP plan (exported from the design doc)
    milestones-1-4.md        # this file
    wire-format.md           # written in milestone 1
    decisions.md             # every decision taken where the spec was silent
    progress.md              # status checklist, kept current
```

`relay-ffi` (UniFFI) and the apps are out of scope for this phase; keep `relay-core`'s public API UniFFI-friendly (owned types, no lifetimes or generics in the public surface, errors as enums) so it can be wrapped later without changes.

## Details the spec leaves open: proposed defaults

Use these unless something better turns up while implementing; record any change in `docs/decisions.md` and tell the user.

| Topic | Default |
|---|---|
| Key fingerprint | `sha256:` + lowercase hex of SHA-256 over the DER SubjectPublicKeyInfo |
| Timestamps | Unix seconds, unsigned 64-bit |
| Request ids | 16 random bytes |
| CBOR | RFC 8949 core deterministic encoding (§4.2.1), text-string map keys equal to the spec's field names, `v = 1` |
| Signed bytes | `context_string \|\| 0x00 \|\| deterministic_CBOR(map without the signature field)` |
| Context strings | `relay-pkcs11/request/v1`, `relay-pkcs11/attestation/v1`, `relay-pkcs11/response/v1`, `relay-pkcs11/relay-auth/v1` |
| `request_hash` | SHA-256 of the request envelope's exact CBOR bytes as sent, including `client_sig` |
| Signature encodings | ECDSA P-256 as raw `r \|\| s` (64 bytes); Ed25519 as 64 bytes; the algorithm is implied by the key |
| Client identity key | Ed25519 by default; P-256 accepted |
| Device key | ECDSA P-256 (Secure Enclave constraint); in the test approver, a software P-256 key |
| Attest key | ECDSA P-256 in a retired PIV slot (`82`–`95`), touch `always` on real hardware |
| HPKE for results | RFC 9180 base mode, DHKEM(P-256, HKDF-SHA256) `0x0010`, HKDF-SHA256 `0x0001`, AES-256-GCM `0x0002`; `info = "relay-pkcs11/result/v1" \|\| req_id`; `aad = req_id` |
| Manifest | JSON file plus a detached OpenPGP signature over the file's exact bytes (`manifest.json.asc`, armored, or `.sig`, binary). Verify the signature before parsing JSON. Reject unknown roles, duplicate fingerprints, `valid_until <= issued_at`, and keys whose `algorithm` does not match their public key |
| Manifest freshness | Reject `version` lower than the cached copy; equal version with different bytes is an error; reject when `now > valid_until + skew` |
| Pairing code | Base32 (RFC 4648, no padding) of the first 40 bits of the client key fingerprint, shown as `XXXX-XXXX` |
| Relay authentication | Every authenticated HTTP call carries `X-Relay-Key` (fingerprint), `X-Relay-Time`, `X-Relay-Signature` over `relay-auth/v1 \|\| 0x00 \|\| method \|\| 0x00 \|\| path \|\| 0x00 \|\| time \|\| 0x00 \|\| SHA-256(body)`; the relay rejects a skew over 60 s and replays within the window |
| Clock skew tolerance | 60 s, configurable |
| Provider config | TOML at `$RELAY_PKCS11_CONFIG`; when unset, the first of the XDG and Application Support paths (milestone 7, `docs/milestone-7.md` "Config file lookup"). Fields as in the spec's provider configuration table |
| Slots | One slot per `token` in the manifest; slot IDs stable across restarts (ordered by token name) |

Things that must stay exactly as the spec says: one role per key, roles and labels from the manifest only, the five-step response verification order, the Failure handling table's return codes, and context-string domain separation on every signature.

## Milestone 1: protocol and core

Deliverables:

1. `docs/wire-format.md`: every message (request, attestation statement, response, manifest), field types, CBOR layout, signed-bytes construction, HPKE parameters, fingerprint format, relay-auth headers, with one worked example each. **Show it to the user before implementing the core.**
2. `relay-core` modules:
   - `wire`: serde types for every message; encode/decode with deterministic-CBOR enforcement (decoding rejects non-canonical input).
   - `keys`: fingerprints, SPKI parsing (RSA 2048/4096, P-256, Ed25519), role and algorithm enums.
   - `manifest`: `verify_manifest(bytes, signature, signer, cached, now, skew) -> Result<Manifest>`.
   - `attestation`: build and `verify_attestation(statement, manifest, now, skew)`.
   - `request` / `response`: build, sign, `verify_request` (approver side), `verify_response(response, request_bytes, manifest, now, skew)` implementing the spec's five checks in order, then `open_result`.
   - `seal`: HPKE seal/open for results; reply key generation with `zeroize`.
   - `piv`: APDU builders and parsers for `SELECT`, `VERIFY`, `GENERAL AUTHENTICATE` (RSA raw decrypt, RSA raw sign, ECDSA sign), `GET DATA` (certificate objects); a `CardTransport` trait (`transmit(apdu) -> response`), including chained responses (`61xx`) and `6Cxx` handling.
   - `padding`: OAEP-SHA256 decode after raw RSA, PKCS#1 v1.5 DigestInfo encoding for SHA-256, DER-to-raw ECDSA conversion.
   - `content`: hex-and-hash view plus requester claims (decoders come later).
   - `error`: one error enum whose variants map one-to-one to the Failure handling rows.
3. `relay-softcard`: a software PIV card implementing `CardTransport` for the subset above (RSA 2048 raw ops, P-256 sign, certificate objects, PIN with retry counter), loaded from PEM files.
4. Test vectors in `crates/relay-core/tests/vectors/` (valid and invalid cases for every message) and a test that runs them; property tests for CBOR round trips.
5. `fuzz/` targets: CBOR messages, manifest JSON, OpenPGP signature, APDU responses.
6. OpenPGP test vectors produced with real `gpg` (including a signature made on a YubiKey OpenPGP card if available), checked in, so rPGP interop is tested.

Gate: `cargo test -p relay-core` passes, and every row of the spec's Failure handling table that the core can detect has a named negative test (manifest invalid, rolled back, expired; attestation invalid, expired, wrong signer; response signer mismatch, binding mismatch; role violation; mechanism not allowed).

## Milestone 2: relay and test approver

Deliverables:

1. `relay-server`: every endpoint in the spec's Relay API table; relay-auth verification; client and device registries and pairing in SQLite (WAL); in-memory pending queue with TTL, one response per request id, duplicate-id rejection; long-poll for providers, WebSocket for connected approvers; audit log (full request plus device-signed outcome); rate limits; `/healthz`, `/metrics`; `relay-server admin` subcommands (list, revoke, export audit).
2. Push: an ntfy sender and a no-op/log sender. APNs and FCM senders are stubbed behind a `Notifier` trait and implemented in milestones 5–6.
3. `relay-test-approver`: registers a device (software P-256 device key), obtains an attestation from an attest key on the softcard, advertises keys, long-polls or holds a WebSocket, verifies requests exactly as the apps will, performs the operation through `CardTransport` (softcard by default, PC/SC with `--pcsc`), seals and signs responses. Flags: `--auto-approve`, `--deny`, `--delay`, `--expired-attestation` (for negative tests).
4. `deploy/Dockerfile.relay`: static musl build into `gcr.io/distroless/static`, multi-arch `amd64`/`arm64`, non-root, `/data` volume.
5. Fixture generator (`cargo xtask fixtures` or a `relayctl dev` subcommand): creates a throwaway PGP key, softcard keys for every role, a signed manifest, and the configs used by compose.

Gate: in CI, request → approval → response completes against the relay in Docker, plus negative paths: expired request, denial, duplicate id, unpaired client, unattested device.

## Milestone 3: provider on Linux

Deliverables:

1. Front-end decision (short spike first): fork google/native-pkcs11's front end, or write a small front end on `cryptoki-sys` types. Known facts about native-pkcs11 from the design review: Apache-2.0; `C_Decrypt*` are stubbed as not supported; its keychain backend assumes token keys are Secure Enclave EC keys. Record the choice in `docs/decisions.md`.
2. `relay-pkcs11` implementing the spec's function and mechanism tables: discovery from relay keys ∩ verified manifest; role enforcement; requests signed with the client key; the five-step response verification; one approval per operation (cache the result for the length-query second call); `CKF_OS_LOCKING_OK`; no threads or I/O before `C_Initialize`; re-initialize after `fork()`; blocking HTTP (`ureq` + `rustls`); `catch_unwind` at every exported function, mapping panics to `CKR_GENERAL_ERROR`.
3. Client pairing from the provider side: first run generates the client key, registers as pending, logs the pairing code; operations fail cleanly until approved.
4. Builds: `x86_64` and `aarch64`, glibc and musl; a p11-kit module file.
5. `deploy/compose.test.yml`: relay, test approver, and a client container that runs the scripts in `tests/`.

Gate (all in CI, through the test approver):

- `pkcs11-tool --module librelay_pkcs11.so -L` and `-O` list exactly the trusted keys with manifest labels and IDs, and no `attest` key.
- `pkcs11-tool --sign` succeeds with a `sign` key (`ECDSA-SHA256`, `SHA256-RSA-PKCS`) and an `auth` key (`ECDSA`, `RSA-PKCS`); signatures verify with OpenSSL against the exported public keys.
- `pkcs11-tool --decrypt -m RSA-PKCS-OAEP --hash-algorithm SHA256 --mgf MGF1-SHA256` recovers data encrypted with OpenSSL to the `encrypt` key.
- Role violations are refused locally (`CKR_KEY_FUNCTION_NOT_PERMITTED`), and a denial returns `CKR_FUNCTION_REJECTED`.
- OpenSSL 3 with `pkcs11-provider` signs through the provider, and `ssh -I` authenticates to a test sshd with an `auth` key.

## Milestone 4: relayctl and real hardware

Deliverables:

1. `relayctl key generate|list|export` on a real YubiKey over PC/SC (`yubikey` crate): one role per slot, PIN and touch policy flags, self-signed certificate, prints the fingerprint. Refuses to overwrite an occupied slot without `--force` and an interactive confirmation.
2. `relayctl manifest add|remove|show|sign|verify`: `sign` increments `version`, sets `valid_until`, writes the detached signature using the OpenPGP card through `gpg` (or rPGP with an OpenPGP-card backend); `verify` uses exactly the core's client-side check.
3. `relayctl attest sign`: signs a device attestation with the `attest` key on the card (offline-attest-key flow).
4. `relay-test-approver --pcsc`: performs operations and attestation with the real card.

Gate (manual, on the user's Mac with a real YubiKey): keys generated with `relayctl`, a manifest signed with the user's OpenPGP card, the test approver using the real card, and the same `pkcs11-tool` sign, auth and decrypt operations as milestone 3 succeed. The provider can be built as a macOS `.dylib` for this run; packaging and notarization belong to milestone 7.

Hardware safety rules for this milestone:

- Never touch a YubiKey unless `RELAY_TEST_YUBIKEY_SERIAL` is set and matches; tests skip otherwise.
- Never change the PIN, PUK or management key, and never reset the PIV applet, automatically. Print the command for the user instead.
- Use dedicated slots for testing (for example retired slots `90`–`95`) unless the user names others.
- Stop after one failed PIN attempt instead of retrying.

## Out of scope for this phase

GUI apps and `relay-ffi`; APNs and FCM senders; macOS notarization and the iPadOS XCFramework (milestone 7); content decoders beyond hex-and-hash; `revoked_devices`; relay high availability.
