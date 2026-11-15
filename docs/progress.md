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
- [x] Fuzz targets (compile-checked on stable; not yet run: needs nightly and `cargo-fuzz`)
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
- [~] Discovery and role enforcement (written, compiles; not yet exercised by any test)
- [~] Sign and decrypt through the relay, response verification (written, compiles; untested)
- [~] Client pairing from the provider (written; untested)
- [ ] glibc and musl builds; p11-kit module file
- [ ] `deploy/compose.test.yml` and `tests/` scripts
- [x] Relay terminates TLS (axum-server); test clients trust a private CA
- [ ] Next: in-process provider test through the C function table, then client image (pkcs11-tool, pkcs11-provider, ssh) and compose gate
- [ ] Gate passed (`pkcs11-tool`, OpenSSL `pkcs11-provider`, `ssh -I`)

## Milestone 4: relayctl and real hardware

- [ ] `relayctl key`
- [ ] `relayctl manifest` (sign with OpenPGP card)
- [ ] `relayctl attest sign`
- [ ] `relay-test-approver --pcsc`
- [ ] Gate passed on Brian's Mac with a real YubiKey
