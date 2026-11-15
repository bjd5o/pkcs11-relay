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

- [ ] `relay-server` API, auth, registries, pairing
- [ ] Pending queue, long-poll, WebSocket
- [ ] Audit log, rate limits, health and metrics, admin subcommands
- [ ] ntfy and no-op notifiers
- [ ] `relay-test-approver`
- [ ] Fixture generator
- [ ] `deploy/Dockerfile.relay` (multi-arch, distroless)
- [ ] Gate passed

## Milestone 3: provider on Linux

- [ ] Front-end spike and decision recorded
- [ ] Discovery and role enforcement
- [ ] Sign and decrypt through the relay, response verification
- [ ] Client pairing from the provider
- [ ] glibc and musl builds; p11-kit module file
- [ ] `deploy/compose.test.yml` and `tests/` scripts
- [ ] Gate passed (`pkcs11-tool`, OpenSSL `pkcs11-provider`, `ssh -I`)

## Milestone 4: relayctl and real hardware

- [ ] `relayctl key`
- [ ] `relayctl manifest` (sign with OpenPGP card)
- [ ] `relayctl attest sign`
- [ ] `relay-test-approver --pcsc`
- [ ] Gate passed on Brian's Mac with a real YubiKey
