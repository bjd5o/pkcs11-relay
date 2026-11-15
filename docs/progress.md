# Progress

Update this file as tasks finish. Each milestone's gate is defined in `docs/milestones-1-4.md`.

## Milestone 1: protocol and core

- [x] Cargo workspace and CI skeleton (fmt, clippy, test)
- [ ] `docs/wire-format.md` written and reviewed by Brian
- [ ] `relay-core::wire` (deterministic CBOR types)
- [ ] `relay-core::keys` (fingerprints, SPKI, roles)
- [ ] `relay-core::manifest` (OpenPGP verification, freshness)
- [ ] `relay-core::attestation`
- [ ] `relay-core::request` / `response` (five-step verification)
- [ ] `relay-core::seal` (HPKE)
- [ ] `relay-core::piv` and `padding`
- [ ] `relay-core::content` (hex-and-hash view)
- [ ] `relay-softcard`
- [ ] Test vectors, including `gpg`-made OpenPGP signatures
- [ ] Fuzz targets
- [ ] Gate passed

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
