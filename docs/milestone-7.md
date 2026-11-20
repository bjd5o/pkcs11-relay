# Milestone 7: provider on macOS and iPadOS, work breakdown

Status: **draft for Brian's review (2026-11-20).** Nothing here is built yet.

This phase ships `relay-pkcs11` for Apple platforms: a universal `.dylib` for macOS and a static library in an XCFramework for iPadOS, with a small iPad sample app. `docs/spec.md` remains the source of truth: "PKCS#11 provider (`relay-pkcs11`)", "Per platform" and "Milestones" item 7. This file turns those into tasks, sets defaults for what the spec leaves open, and defines the gate.

**Spec gate:** `pkcs11-tool` signs on macOS; the sample app signs on an iPad.

## What already exists and what is missing

The provider is one crate with `crate-type = ["cdylib", "staticlib", "rlib"]`, so `cargo build` already produces `librelay_pkcs11.dylib` and `librelay_pkcs11.a` on a Mac. Its in-process tests (`cargo test -p relay-pkcs11`, with the relay and the test approver in the same process) pass on macOS today. What is missing:

- **Host name.** `discovery::host_name` reads `/proc/sys/kernel/hostname` or `/etc/hostname`, then `$HOSTNAME`. None of those exists for a typical macOS or iPadOS process, so requests claim `unknown`. It needs `gethostname(3)`.
- **Packaging.** No universal build, no signing, no notarization, no Homebrew formula, no XCFramework for the provider, no PKCS#11 header for Swift callers.
- **macOS in CI.** CI builds the provider only for Linux, and runs the third-party callers (`pkcs11-tool`, OpenSSL, `ssh`) only in the Linux container.
- **A caller on iPadOS.** No app links the provider; the approver app must not, since it already links its own Rust static library (`RelayFFI`).

Nothing in `relay-core` changes. The provider's checks and runtime rules (no threads, sockets or files before `C_Initialize`; `catch_unwind` at every export; no async runtime) apply unchanged on both platforms.

## Layout added in this phase

```
deploy/macos/
  build-provider.sh        # cargo for aarch64- and x86_64-apple-darwin, lipo, codesign (when an identity is given)
  notarize.sh              # zip, notarytool submit --wait, check the result; Brian runs it locally
  relay-pkcs11.rb          # Homebrew formula template (the tap itself is a separate repo, see Decisions)
apps/apple/
  build-provider-xcframework.sh   # librelay_pkcs11.a for ios and ios-sim, headers, xcodebuild -create-xcframework
  Provider/include/        # PKCS#11 headers and module map for Swift (see Dependencies)
  SampleSigner/            # iPad sample app (a second target in project.yml)
tests/
  macos-gate.sh            # m3-gate checks run natively on a Mac: relay + test approver binaries, no Docker
```

## Details the spec leaves open: defaults

| Topic | Default | Why |
| --- | --- | --- |
| Host name | `gethostname(3)` through `libc`, called in the C ABI module (the only place `unsafe` is allowed), before the `/proc` and `/etc` fallbacks; the config's `host` still wins | Works on Linux, macOS and iPadOS alike; on iPadOS it returns the device's local name, which is what the approval screen should show |
| macOS file name and location | `librelay_pkcs11.dylib`, the name Cargo gives it and the one used in CLAUDE.md. Homebrew installs it to `$(brew --prefix)/lib/librelay_pkcs11.dylib` | Same stem as the Linux `.so`; Homebrew's prefix differs between Apple silicon and Intel, so docs use `brew --prefix` |
| Minimum macOS | 13.0 (`MACOSX_DEPLOYMENT_TARGET=13.0`) for both slices | Covers every Mac Apple still updates; the approver app needs 14, but the provider doesn't use anything newer than 13 |
| Install name | `@rpath/librelay_pkcs11.dylib` | Callers load it by path through `dlopen`, so the install name only matters for tools that link it; `@rpath` is the safe choice |
| Signing | Developer ID Application, hardened runtime (`codesign --options runtime --timestamp`). The identity comes from Brian's keychain and is never in the repo | Required for notarization; the team id stays out of the public repo, as for the app |
| Notarization | `notarytool submit` of a zip holding the dylib, with a keychain profile Brian creates once (`xcrun notarytool store-credentials`). Local only, not in CI | A bare dylib can't be stapled, so Gatekeeper checks the ticket online the first time; Homebrew installs aren't quarantined anyway. CI would need the Apple credentials as secrets, which isn't worth it for the MVP |
| CI artifact | An unsigned universal dylib from a `macos-15` job, plus `lipo -info` and the native gate script | Proves both slices build and the arm64 slice works with third-party callers; signing stays with Brian |
| x86_64 slice | Built in CI; run once by hand under Rosetta (`arch -x86_64 pkcs11-tool …` with an x86_64 OpenSC) during the gate | No Intel Mac at hand; GitHub's Intel runners are being retired |
| Config on macOS | Unchanged: `RELAY_PKCS11_CONFIG`. Docs show it for shells and `launchctl setenv` for GUI apps | The spec says config comes from that variable; a default path would change the spec (see Still open) |
| Library validation | Documented, not worked around: apps with library validation (most Apple-signed GUI apps) refuse the module; command-line tools, OpenSSL 3 with `pkcs11-provider` and Homebrew's OpenSSH load it. Apple's `/usr/bin/ssh` is checked during the gate and the result written down | Spec: "Apps that enforce library validation will not load any third-party module" |
| iPadOS library | `librelay_pkcs11.a` for `aarch64-apple-ios` and `aarch64-apple-ios-sim`, in `RelayPKCS11.xcframework` with the PKCS#11 headers and a module map, so Swift calls `C_GetFunctionList` directly | The spec's "standard PKCS#11 C API"; the simulator slice lets the sample app run in CI |
| Config on iPadOS | The sample app writes `provider.toml` in its container with absolute paths there, then calls `setenv("RELAY_PKCS11_CONFIG", …)` before `C_Initialize` | No provider change and no new config channel; the same rule as everywhere else |
| Getting the config onto the iPad | The sample app imports a folder from Files: `provider.toml`, `signer.asc`, `relay-ca.pem`. It rewrites the paths in `provider.toml` to its container | No new format to design or sign. A setup link for clients would need its own wire format; that's post-MVP |
| Client identity key on iPadOS | A software key file in the app container, created by the provider on first run, as on Linux, with complete file protection | The provider already does this; a Secure Enclave client key would need a new signer interface in the provider (post-MVP) |
| Pairing code on iPadOS | The sample app sets `log_path` in its container, `log_level = "info"`, and shows the log's last lines, which carry the pairing code | The provider already logs the code; nothing new is exposed |
| Sample app scope | One screen: import config, list slots and keys (`C_GetSlotList`, `C_FindObjects`), sign a typed message with a chosen key (`C_SignInit` / `C_Sign`), verify the signature in Swift with the public key from `CKA_EC_POINT` / `CKA_MODULUS` (CryptoKit or `SecKey`), show the provider log | Enough to show the standard API works and that a third party could integrate it; no decrypt UI (sign is the gate) |
| Calls off the main thread | The sample app runs every PKCS#11 call on a background task: `C_Sign` blocks until approval, up to `timeout_secs` | The provider is blocking by design |
| Two Rust static libraries | The sample app links only `RelayPKCS11`, never `RelayFFI` | Two Rust staticlibs in one binary give duplicate `std` symbols |

## Tasks

### Part A: macOS dylib (the first half of the gate)

1. **Host name.** `gethostname` in the C ABI module with a `SAFETY:` comment; `discovery::host_name` calls it before the file fallbacks. Unit test: the result isn't empty and isn't `unknown` on macOS and Linux CI.
2. **Universal build.** `deploy/macos/build-provider.sh`: release builds for both Darwin targets with the deployment target set, `lipo -create`, `install_name_tool -id`, and `codesign` when `CODESIGN_IDENTITY` is set. Output `dist/librelay_pkcs11-macos-universal.dylib`.
3. **Native gate script.** `tests/macos-gate.sh` runs the existing `relay-server` and `relay-test-approver` binaries on the Mac with the fixtures `relay-test-approver gen-fixtures` already writes, then the same checks as `tests/m3-gate.sh` that don't need Linux: `pkcs11-tool` list, sign (EC and RSA), decrypt, denial and expiry return codes, OpenSSL 3 through `pkcs11-provider`, `ssh-keygen -D`. Shared check helpers move to `tests/lib.sh` so the two scripts don't drift.
4. **CI job `provider-macos`** on `macos-15`: `brew install opensc openssl@3 pkcs11-provider`, build the universal dylib, `lipo -info` shows both slices, run `tests/macos-gate.sh` against the arm64 slice, upload the dylib.
5. **Signing and notarization.** `deploy/macos/notarize.sh`: zip, `notarytool submit --wait --keychain-profile`, fail unless the status is `Accepted`, print the log URL. Brian runs it; it needs his Developer ID certificate and keychain profile.
6. **Homebrew formula.** `deploy/macos/relay-pkcs11.rb`: installs the notarized dylib from a GitHub release asset, with its SHA-256, plus a `caveats` block on `RELAY_PKCS11_CONFIG` and library validation. Publishing it needs a tap repo (see Decisions).
7. **Docs.** A macOS section in the user docs: install, config, `pkcs11-tool`, OpenSSL, OpenSSH, what refuses to load it and why.

### Part B: iPadOS XCFramework and sample app (the second half)

8. **XCFramework.** `apps/apple/build-provider-xcframework.sh`: `librelay_pkcs11.a` for `aarch64-apple-ios` and `aarch64-apple-ios-sim`, the headers and module map, `xcodebuild -create-xcframework`. Output in `apps/apple/Generated` (git-ignored), like `RelayFFI`.
9. **Sample app.** A `SampleSigner` target in `project.yml`, iPadOS 17, with the scope above. The PKCS#11 calls sit in one Swift file, as a third-party integrator would write them.
10. **Simulator test.** An XCUITest, run by a new `tests/sim-provider.sh`: a relay and a test approver run on the Mac with the softcard fixtures, the sample app in the iOS simulator imports a fixture config, pairs (the test approver approves the pairing), signs, and verifies the signature. It joins the `apple` CI job.
11. **Gate on the iPad.** The sample app on Brian's iPad signs with `hw-sign` after an approval. Steps are in "Gate".

## Gate (manual, plus CI)

CI, on every change:
- `provider-macos`: the universal dylib builds, both slices are present, and `tests/macos-gate.sh` passes against the arm64 slice.
- `apple`: the sample app signs in the simulator, and the signature verifies.

Manual, on Brian's hardware, against the `gate-m5` relay:
1. **macOS:** the notarized universal dylib, installed from the formula (or from `dist/` before the tap exists). `pkcs11-tool --module … --sign -m ECDSA-SHA256 --id 03` with `hw-sign` on a Mac shell, approved in the Mac approver app with the YubiKey; the signature verifies with OpenSSL against the public key read through the provider. Also once under `arch -x86_64` with an x86_64 OpenSC, if Rosetta and that build are available.
2. **macOS callers:** note whether OpenSSL 3 with `pkcs11-provider`, Homebrew's `ssh` and Apple's `/usr/bin/ssh` load the module. Write the result down; not a pass or fail.
3. **iPadOS:** the sample app on the iPad imports a client config, pairs (code compared in an approver app, grant signed with the YubiKey), signs a message with `hw-sign` after an approval on the Mac, and verifies the signature.

## Work estimate

| Part | Size |
| --- | --- |
| Host name, universal build, native gate script, CI job | Small to medium; most of it is shell and CI |
| Signing, notarization, formula | Small for me; needs Brian's certificate and keychain profile |
| XCFramework, headers, sample app, simulator test | Medium; the simulator test reuses most of `tests/sim-e2e.sh` |
| Gate | One sitting with the Mac and the iPad |

## Dependencies to approve

- **`libc`** (Rust crate) as a direct dependency of `relay-pkcs11`, for `gethostname`. It is already in `Cargo.lock` through other crates; pin it in `[workspace.dependencies]`. The alternative is the `gethostname` crate, which is a safe wrapper over the same call but one more crate.
- **PKCS#11 headers** for Swift: vendor the OASIS PKCS#11 3.1 headers (`pkcs11.h`, `pkcs11t.h`, `pkcs11f.h`), which OASIS publishes for implementers to redistribute, into `apps/apple/Provider/include`. The alternative is a minimal header I write with only the functions and types the sample app uses; smaller, but every integrator would want the real one anyway.
- **CI tools:** Homebrew's `opensc`, `openssl@3` and `pkcs11-provider` on the macOS runner, as the Linux image already has them.

## Decisions for Brian

1. **Homebrew tap.** The formula needs a public tap repo (for example `bjd5o/homebrew-relay`) and GitHub release assets for the notarized dylib. Create them in this milestone, or keep the formula in `deploy/macos` and install from `dist/` for the gate?
2. **Developer ID.** Is there a Developer ID Application certificate in your keychain for this team, or does it need creating? Notarization also needs an app-specific password or an App Store Connect API key for `notarytool`.
3. **Config fallback on macOS.** GUI apps don't see shell environment variables. Should the provider also look at a default path (for example `~/Library/Application Support/relay-pkcs11/provider.toml`) when `RELAY_PKCS11_CONFIG` is unset? That changes the spec's "Config read at `C_Initialize` from the file named by `RELAY_PKCS11_CONFIG`", so it's your call; my default is no change for the MVP.
4. **The two dependencies above:** `libc` or `gethostname`; vendored OASIS headers or a minimal one.
5. **Order.** Part A first (macOS, which also improves CI), then Part B. Or both together?

## Still open

- Whether Apple's `/usr/bin/ssh` (through `ssh-pkcs11-helper`) loads a Developer ID-signed module. Checked in the gate; the docs say whatever we find.
- A CryptoTokenKit persistent-token extension, so every app on macOS and iPadOS sees the relay keys, stays post-MVP (spec "MVP scope").
