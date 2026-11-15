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
