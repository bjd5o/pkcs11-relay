# pkcs11-relay

Approval-gated PKCS#11. A PKCS#11 provider that holds no private keys forwards each sign or decrypt through a relay to an approver app, which shows the request, takes the PIN locally and runs the operation on a YubiKey. Clients trust keys only through a PGP-signed manifest, and responses only through device keys that a manifest-listed `attest` key vouched for. The relay is never trusted.

## Read first

1. `docs/spec.md`: architecture and MVP implementation plan. This is the source of truth for behavior.
2. `docs/milestones-1-4.md`: the current phase. It covers tasks, defaults for details the spec leaves open, and the gate for each milestone.
3. `docs/progress.md`: what is done. Update it whenever a task finishes.
4. `docs/decisions.md`: decisions taken where the spec was silent. Append to it; don't rewrite history.

If the code and the spec disagree, or the spec is ambiguous in a way that matters for security, stop and ask Brian rather than guessing. Never change `docs/spec.md` without asking.

## Workspace

Cargo workspace with crates under `crates/`: `relay-core`, `relay-softcard`, `relay-pkcs11`, `relay-server`, `relay-test-approver`, `relayctl`. Also `fuzz/`, `deploy/` (Dockerfile and compose) and `tests/` (integration scripts). Pin every dependency version in the root `Cargo.toml` under `[workspace.dependencies]`.

## Commands

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
docker compose -f deploy/compose.test.yml up --build --exit-code-from client   # integration gate
pkcs11-tool --module target/debug/librelay_pkcs11.dylib -L                      # manual check on macOS (brew install opensc)
```

## Rules

- **All security checks live in `relay-core`.** Other crates call its `verify_*` functions and never re-implement parsing, signing or verification.
- **No custom cryptography.** Use RustCrypto or other audited crates for primitives, and rPGP for OpenPGP.
- **`#![forbid(unsafe_code)]` in every crate except `relay-pkcs11`.** There, keep `unsafe` inside the C ABI module, with a `SAFETY:` comment on each block.
- **The provider must never unwind across FFI.** Use `catch_unwind` at every exported function and map panics to `CKR_GENERAL_ERROR`. Start no threads, sockets or file I/O before `C_Initialize`. Don't use an async runtime inside the provider.
- **Verification functions take time as a parameter.** No `SystemTime::now()` inside `relay-core` checks.
- **Every signature uses its context string,** as listed in `docs/milestones-1-4.md`. Verify the manifest signature before parsing its JSON.
- **Zeroize secrets:** reply private keys, PINs, plaintext results.
- **Never log PINs, private keys or operation results.** Requests may be logged; they contain only ciphertext, digests or messages to be signed.
- **Every row of the spec's Failure handling table needs a test** that produces exactly that outcome and return code.
- **Hardware safety.** Never touch a YubiKey unless `RELAY_TEST_YUBIKEY_SERIAL` is set and matches. Never overwrite a slot without `--force` plus interactive confirmation. Never change the PIN, PUK or management key, or reset the applet, automatically. Stop after one failed PIN attempt.
- **Ask before adding a dependency** that isn't in the spec's technology table or the milestone doc.
- **Commits:** small, one task each, imperative subject line.

## Environment

- Brian's machine is macOS on Apple silicon, with Rust via rustup and Docker through colima. Linux provider targets are `x86_64` and `aarch64`, each for glibc and musl.
- Brian is a senior engineer. Be direct, show diffs or design docs before large irreversible steps, and summarize at the end of each milestone: what was built, gate results, open questions.
