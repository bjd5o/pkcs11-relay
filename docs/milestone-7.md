# Milestone 7: provider on macOS and iPadOS, work breakdown

Status: **second draft, with Brian's answers from 2026-11-19.** Nothing here is built yet.

This phase ships `relay-pkcs11` for Apple platforms: a universal `.dylib` for macOS, distributed through Flox and as a release asset, and a static library in an XCFramework for iPadOS, with a small iPad sample app. `docs/spec.md` remains the source of truth: "PKCS#11 provider (`relay-pkcs11`)", "Per platform" and "Milestones" item 7. This file turns those into tasks, sets defaults for what the spec leaves open, and defines the gate.

**Spec gate:** `pkcs11-tool` signs on macOS; the sample app signs on an iPad.

## What already exists and what is missing

The provider is one crate with `crate-type = ["cdylib", "staticlib", "rlib"]`, so `cargo build` already produces `librelay_pkcs11.dylib` and `librelay_pkcs11.a` on a Mac. Its in-process tests (`cargo test -p relay-pkcs11`, with the relay and the test approver in the same process) pass on macOS today. What is missing:

- **Host name.** `discovery::host_name` reads `/proc/sys/kernel/hostname` or `/etc/hostname`, then `$HOSTNAME`. None of those exists for a typical macOS or iPadOS process, so requests claim `unknown`.
- **Config without an environment variable.** GUI apps on macOS don't see shell variables, so `RELAY_PKCS11_CONFIG` alone is awkward there.
- **Packaging.** No universal build, no Flox package, no signing or notarization, no XCFramework for the provider, no PKCS#11 header for Swift callers.
- **macOS in CI.** CI builds the provider only for Linux, and runs the third-party callers (`pkcs11-tool`, OpenSSL, `ssh`) only in the Linux container.
- **A caller on iPadOS.** No app links the provider; the approver app must not, since it already links its own Rust static library (`RelayFFI`).

Nothing in `relay-core` changes. The provider's checks and runtime rules (no threads, sockets or files before `C_Initialize`; `catch_unwind` at every export; no async runtime) apply unchanged on both platforms. The config lookup below reads files only inside `C_Initialize`.

## Layout added in this phase

```
.flox/
  env/manifest.toml        # project environment: test callers (opensc, openssl, pkcs11-provider, openssh)
                           # and the [build.relay-pkcs11] package
deploy/macos/
  build-provider.sh        # cargo for aarch64- and x86_64-apple-darwin, lipo, codesign (when an identity is given)
  notarize.sh              # zip, notarytool submit --wait, check the result; Brian runs it locally
apps/apple/
  build-provider-xcframework.sh   # librelay_pkcs11.a for ios and ios-sim, headers, xcodebuild -create-xcframework
  Provider/include/        # OASIS PKCS#11 3.1 headers and a module map for Swift
  SampleSigner/            # iPad sample app (a second target in project.yml)
tests/
  lib.sh                   # check helpers shared by m3-gate.sh and macos-gate.sh
  macos-gate.sh            # m3-gate checks run natively on a Mac: relay + test approver binaries, no Docker
```

The project environment is separate from the default Flox environment that already provides mise, rustup, gpg and docker. The Rust toolchain stays with mise (`mise.toml`); the project environment adds only what the gate scripts call and the package build.

## Config file lookup

Brian asked for `$XDG_CONFIG_HOME/relay-pkcs11/provider.toml` first, falling back to Application Support, modeled on Ghostty.

**What Ghostty does** (docs at ghostty.org/docs/config; `src/os/xdg.zig` and `src/config/file_load.zig`):
- It checks `$XDG_CONFIG_HOME/ghostty/config.ghostty` (or the older `config`), then on macOS `~/Library/Application Support/com.mitchellh.ghostty/config.ghostty` (or `config`).
- It loads **every** file that exists, in that order, and later files override earlier ones, key by key. The macOS file therefore beats the XDG one.
- If `XDG_CONFIG_HOME` is unset or empty, it uses `$HOME/.config`. It doesn't reject a relative value; a later assertion requires an absolute path.
- It treats a missing, empty or non-regular file as absent.
- A GUI-launched Ghostty doesn't see shell variables, so in practice it uses `~/.config` unless `XDG_CONFIG_HOME` is set through `launchctl`.

**What the provider does**, the same paths and the same XDG handling, but **the first file found wins, with no merging**:

1. `$RELAY_PKCS11_CONFIG`, if set and not empty. If it names a file that doesn't exist, that's an error (zero slots), not a fall-through, so a typo is never silently replaced by another config.
2. `$XDG_CONFIG_HOME/relay-pkcs11/provider.toml`, if `XDG_CONFIG_HOME` is set to an absolute path; otherwise `$HOME/.config/relay-pkcs11/provider.toml`. A relative `XDG_CONFIG_HOME` is ignored, as the XDG spec says.
3. On Apple platforms only: `$HOME/Library/Application Support/relay-pkcs11/provider.toml`.
4. Nothing found: zero slots. The log names every path it checked.

If `HOME` is unset, steps 2 and 3 are skipped. The lookup runs on Linux too (steps 1, 2 and 4), so the code has one path everywhere.

**Why not merge as Ghostty does.** Ghostty's settings are cosmetic. This file holds the manifest signer, the relay CA, the cache paths and the client key path. A merge could pair one file's `manifest_signer` with another file's `manifest_url`, and the log would have to explain which file set which key. First-found-wins makes one file the whole config, and the log names it. A file at a later step isn't read once an earlier one is found. The log warns about it, so a stale copy in Application Support doesn't confuse anyone.

**Trust.** The default paths are in the user's home directory. Anyone who can write there can already set `RELAY_PKCS11_CONFIG` in the user's shell startup files, so the lookup gives no new attack surface. The provider still trusts only the manifest signer named in the file, as it does today.

**iPadOS.** `HOME` is the app's container, so step 3 resolves to the container's `Library/Application Support`. The sample app writes its imported config there and sets no environment variable, which also tests the lookup.

## Spec change (approved 2026-11-19)

Brian approved the change. `docs/spec.md` now names the default paths in its "Configuration" paragraph and in milestone 2's config item. The "Provider config" row of `docs/milestones-1-4.md` points here, and `docs/decisions.md` records it ("Default provider config paths").

## Distribution through Flox

Brian doesn't use Homebrew; the dylib ships as a Flox package instead. What the Flox docs say (flox.dev, read 2026-11-19), and what follows from it:

- **Build.** A manifest build, `[build.relay-pkcs11]` in `.flox/env/manifest.toml`: `cargo build --release -p relay-pkcs11`, then copy the library to `$out/lib/`. In an activated environment it shows up at `$FLOX_ENV/lib/librelay_pkcs11.dylib` (`.so` on Linux), so docs use `--module "$FLOX_ENV/lib/librelay_pkcs11.dylib"`. `sandbox = "off"` (the default) so cargo can fetch crates. A pure build would need vendored crates, and on macOS Flox's pure sandbox still allows network access anyway.
- **Toolchain inside the build.** A manifest build runs with the environment's `[install]` packages on `PATH`. The build installs `rustup` from the catalog. Flox's fresh clone doesn't run mise, so the build needs the pinned version from a file `rustup` reads: `rust-toolchain.toml`, which mise also honours (Decisions, item 4).
- **Publish.** `flox publish relay-pkcs11` needs a clean git tree on a branch pushed to its remote, with full history. Flox clones the repo and builds it again from scratch. Publishing needs a free FloxHub account.
- **Who can install it.** A package in a personal catalog can be installed **only by its owner**. Sharing with anyone else needs a Flox organization, which is a paid Flox for Teams feature. The docs don't describe public packages. For the MVP, the personal catalog covers Brian's own Macs; other people use the release asset below. See Decisions.
- **One build per system.** `flox publish` builds on the machine that runs it, and the docs don't describe cross-building. Brian's Mac publishes `aarch64-darwin`. `x86_64-darwin` and the Linux systems would need a machine or CI runner of each kind, and CI would need a FloxHub token as a secret. MVP: `aarch64-darwin` only; the others are listed under "Still open".
- **Signing.** A Flox install isn't quarantined, and Apple's arm64 linker already ad-hoc signs the dylib. That is enough for `pkcs11-tool`, OpenSSL and OpenSSH. A Developer ID signature doesn't help with library validation either: such apps accept only Apple's code or their own team's. So the Flox package builds from source and carries the linker's ad-hoc signature. The gate checks it with `codesign -dv` on the published result, in case Flox's build step changes it.

**Release asset** (for people outside Brian's catalog): the universal dylib from `deploy/macos/build-provider.sh`, signed with Developer ID and notarized, attached to a GitHub release with its SHA-256. A browser download is quarantined, so the signature and notarization ticket matter here. A bare dylib can't be stapled, so Gatekeeper checks the ticket online the first time it loads.

## Signing and notarization

The only code-signing identity in Brian's keychain is **Apple Development**, not Developer ID Application (`security find-identity -v -p codesigning`, 2026-11-19). Apple Development certificates can't be notarized. Steps, done once:

1. **Create the certificate.** Xcode → Settings → Accounts → the team → Manage Certificates → + → **Developer ID Application**. Only the team's Account Holder can create one. On a personal team, that's Brian. The private key stays in the login keychain; export a `.p12` backup to somewhere safe.
2. **Create a notarization credential.** Either an app-specific password (account.apple.com → Sign-In and Security → App-Specific Passwords) or an App Store Connect API key (Users and Access → Integrations, role Developer). The API key is easier to revoke; either works.
3. **Save it in the keychain:** `xcrun notarytool store-credentials relay-notary --apple-id <id> --team-id <team> --password <app-specific password>` (or `--key`, `--key-id`, `--issuer` for an API key). The profile name `relay-notary` is the only thing scripts refer to; the team id and credentials never enter the repo.
4. **Per release:** `CODESIGN_IDENTITY="Developer ID Application: …" deploy/macos/build-provider.sh`, then `deploy/macos/notarize.sh dist/librelay_pkcs11-macos-universal.dylib`. The script zips the dylib, runs `notarytool submit --keychain-profile relay-notary --wait`, prints the log, and fails unless the status is `Accepted`. Expect a few minutes per submission.
5. **Check:** `codesign -dv --verbose=4` shows the Developer ID authority and `flags=0x10000(runtime)`. `spctl -a -t open --context context:primary-signature -v` on the dylib reports `accepted` with source `Notarized Developer ID`.

The release asset is the only artifact that needs this. If Brian wants to skip it for the MVP, the gate can run entirely on the Flox build. See Decisions.

## Details the spec leaves open: defaults

| Topic | Default | Why |
| --- | --- | --- |
| Host name | The `gethostname` crate, called from `discovery::host_name` before the `/proc` and `/etc` fallbacks; the config's `host` still wins | Brian's choice: the crate's name says why it's there, where `libc` could be for anything. It's a safe wrapper, so no `unsafe` is added. On iPadOS it returns the device's local name, which is what the approval screen should show |
| Config location | The lookup in "Config file lookup" | Brian's choice, after Ghostty, with first-found-wins |
| macOS file name and location | `librelay_pkcs11.dylib`; `$FLOX_ENV/lib/` when installed through Flox | Same stem as the Linux `.so` |
| Minimum macOS | 13.0 (`MACOSX_DEPLOYMENT_TARGET=13.0`) for both slices | Covers every Mac Apple still updates; the approver app needs 14, but the provider doesn't use anything newer than 13 |
| Install name | `@rpath/librelay_pkcs11.dylib` | Callers load it by path through `dlopen`, so the install name only matters for tools that link it |
| Signing | Flox package: the linker's ad-hoc signature. Release asset: Developer ID Application, hardened runtime (`codesign --options runtime --timestamp`), identity from Brian's keychain | See "Distribution through Flox" |
| Notarization | Release asset only, local, through the `relay-notary` keychain profile; not in CI | CI would need Apple credentials as secrets, which isn't worth it for the MVP |
| CI artifact | An unsigned universal dylib from a `macos-15` job, plus `lipo -info` and the native gate script | Proves both slices build and the arm64 slice works with third-party callers |
| CI tools on macOS | The project Flox environment (`flox activate -- tests/macos-gate.sh`), installed on the runner with Flox's GitHub action | The same tools Brian uses locally; no Homebrew anywhere |
| x86_64 slice | Built in CI; run once by hand under Rosetta during the gate, if an x86_64 `pkcs11-tool` is at hand | No Intel Mac; GitHub's Intel runners are being retired |
| Library validation | Documented, not worked around: apps with library validation (most Apple-signed GUI apps) refuse the module; command-line tools, OpenSSL 3 with `pkcs11-provider` and Nix's OpenSSH load it. Apple's `/usr/bin/ssh` is checked during the gate and the result written down | Spec: "Apps that enforce library validation will not load any third-party module" |
| iPadOS library | `librelay_pkcs11.a` for `aarch64-apple-ios` and `aarch64-apple-ios-sim`, in `RelayPKCS11.xcframework` with the PKCS#11 headers and a module map, so Swift calls `C_GetFunctionList` directly | The spec's "standard PKCS#11 C API"; the simulator slice lets the sample app run in CI |
| PKCS#11 headers | The OASIS PKCS#11 3.1 headers (`pkcs11.h`, `pkcs11t.h`, `pkcs11f.h`), vendored into `apps/apple/Provider/include` | Every integrator wants the real header; OASIS publishes them for redistribution |
| Config on iPadOS | The sample app writes `provider.toml` to `Library/Application Support/relay-pkcs11/` in its container, with absolute paths there; no environment variable | Uses the default lookup, so it's tested on the device too |
| Getting the config onto the iPad | The sample app imports a folder from Files: `provider.toml`, `signer.asc`, `relay-ca.pem`. It rewrites the paths in `provider.toml` to its container | No new format to design or sign. A setup link for clients would need its own wire format; that's post-MVP |
| Client identity key on iPadOS | A software key file in the app container, created by the provider on first run, as on Linux, with complete file protection | A Secure Enclave client key would need a new signer interface in the provider (post-MVP) |
| Pairing code on iPadOS | The sample app sets `log_path` in its container, `log_level = "info"`, and shows the log's last lines, which carry the pairing code | The provider already logs the code |
| Sample app scope | One screen: import config, list slots and keys (`C_GetSlotList`, `C_FindObjects`), sign a typed message with a chosen key (`C_SignInit` / `C_Sign`), verify the signature in Swift with the public key from `CKA_EC_POINT` / `CKA_MODULUS` (CryptoKit or `SecKey`), show the provider log | Enough to show the standard API works and that a third party could integrate it; no decrypt UI (sign is the gate) |
| Calls off the main thread | The sample app runs every PKCS#11 call on a background task: `C_Sign` blocks until approval, up to `timeout_secs` | The provider is blocking by design |
| Two Rust static libraries | The sample app links only `RelayPKCS11`, never `RelayFFI` | Two Rust staticlibs in one binary give duplicate `std` symbols |

## Tasks

Brian wants Parts A and B in parallel. Part 0 changes the provider, which both parts depend on, so it lands first. After that, A and B touch separate files, except `.github/workflows/ci.yml`. A adds the `provider-macos` job, and B extends the `apple` job, so whichever merges second rebases.

### Part 0: provider changes (first, small)

1. **Host name.** Add `gethostname` to `[workspace.dependencies]` and `relay-pkcs11`; `discovery::host_name` calls it before the file fallbacks. Unit test: the result isn't empty and isn't `unknown` on macOS and Linux CI.
2. **Config lookup.** `config::locate(env)` returns the path to read, or the list of paths it tried. It takes the environment as a parameter, so tests don't touch the process environment. `C_Initialize` uses it. Tests: each step wins over the later ones; an empty or relative `XDG_CONFIG_HOME` falls back to `~/.config`; a missing `RELAY_PKCS11_CONFIG` file is an error, not a fall-through; no file gives zero slots and logs every path tried; a shadowed file gets a warning.

### Part A: macOS dylib (the first half of the gate)

3. **Universal build.** `deploy/macos/build-provider.sh`: release builds for both Darwin targets with the deployment target set, `lipo -create`, `install_name_tool -id`, and `codesign` when `CODESIGN_IDENTITY` is set. Output `dist/librelay_pkcs11-macos-universal.dylib`. Adds `x86_64-apple-darwin` to the targets in `mise.toml`.
4. **Project Flox environment.** `.flox/env/manifest.toml` with `opensc`, `openssl`, `pkcs11-provider` and `openssh` for the gate, and the `[build.relay-pkcs11]` package. `flox build relay-pkcs11` produces `result-relay-pkcs11/lib/librelay_pkcs11.dylib`; check it with `codesign -dv` and `pkcs11-tool --module … -I`.
5. **Native gate script.** `tests/macos-gate.sh` runs the existing `relay-server` and `relay-test-approver` binaries on the Mac with the fixtures `relay-test-approver gen-fixtures` already writes, then the same checks as `tests/m3-gate.sh` that don't need Linux: `pkcs11-tool` list, sign (EC and RSA), decrypt, denial and expiry return codes, OpenSSL 3 through `pkcs11-provider`, `ssh-keygen -D`. Shared check helpers move to `tests/lib.sh` so the two scripts don't drift. Run as `flox activate -- tests/macos-gate.sh`.
6. **CI job `provider-macos`** on `macos-15`: install Flox, build the universal dylib, `lipo -info` shows both slices, run `tests/macos-gate.sh` against the arm64 slice inside the project environment, upload the dylib.
7. **Publish to Flox.** Brian runs `flox publish relay-pkcs11` from a clean, pushed `main` once Part A is merged, for `aarch64-darwin`. Needs his FloxHub account.
8. **Signing and notarization** (if kept; see Decisions). `deploy/macos/notarize.sh` as in "Signing and notarization". Brian creates the certificate and keychain profile; I write the script and the release checklist.
9. **Docs.** A macOS section in the user docs: install through Flox (or the release asset), where the config goes, `pkcs11-tool`, OpenSSL, OpenSSH, what refuses to load it and why.

### Part B: iPadOS XCFramework and sample app (the second half)

10. **XCFramework.** `apps/apple/build-provider-xcframework.sh`: `librelay_pkcs11.a` for `aarch64-apple-ios` and `aarch64-apple-ios-sim`, the vendored headers and a module map, `xcodebuild -create-xcframework`. Output in `apps/apple/Generated` (git-ignored), like `RelayFFI`.
11. **Sample app.** A `SampleSigner` target in `project.yml`, iPadOS 17, with the scope above. The PKCS#11 calls sit in one Swift file, as a third-party integrator would write them.
12. **Simulator test.** An XCUITest, run by a new `tests/sim-provider.sh`: a relay and a test approver run on the Mac with the softcard fixtures, the sample app in the iOS simulator imports a fixture config, pairs (the test approver approves the pairing), signs, and verifies the signature. It joins the `apple` CI job.
13. **Gate on the iPad.** The sample app on Brian's iPad signs with `hw-sign` after an approval. Steps are in "Gate".

## Gate (manual, plus CI)

CI, on every change:
- `provider-macos`: the universal dylib builds, both slices are present, and `tests/macos-gate.sh` passes against the arm64 slice.
- `apple`: the sample app signs in the simulator, and the signature verifies.

Manual, on Brian's hardware, against the `gate-m5` relay:
1. **macOS:** the provider installed with `flox install <brian>/relay-pkcs11` into an environment. With `provider.toml` in `~/.config/relay-pkcs11/` and no `RELAY_PKCS11_CONFIG`, run `pkcs11-tool --module "$FLOX_ENV/lib/librelay_pkcs11.dylib" --sign -m ECDSA-SHA256 --id 03` with `hw-sign`. Approve it in the Mac approver app with the YubiKey. The signature verifies with OpenSSL against the public key read through the provider. If notarization is kept, also once with the notarized release asset, downloaded through a browser so it's quarantined. Also once under `arch -x86_64`, if an x86_64 `pkcs11-tool` is available.
2. **macOS callers:** note whether OpenSSL 3 with `pkcs11-provider`, Nix's `ssh` and Apple's `/usr/bin/ssh` load the module. Write the result down; not a pass or fail.
3. **iPadOS:** the sample app on the iPad imports a client config, pairs (code compared in an approver app, grant signed with the YubiKey), signs a message with `hw-sign` after an approval on the Mac, and verifies the signature.

## Work estimate

| Part | Size |
| --- | --- |
| Host name, config lookup | Small |
| Universal build, Flox environment and package, native gate script, CI job | Small to medium; most of it is shell and CI |
| Signing, notarization | Small for me; needs Brian's new certificate and keychain profile |
| XCFramework, headers, sample app, simulator test | Medium; the simulator test reuses most of `tests/sim-e2e.sh` |
| Gate | One sitting with the Mac and the iPad |

## Dependencies (approved 2026-11-19)

- **`gethostname`** (Rust crate) as a direct dependency of `relay-pkcs11`, pinned in `[workspace.dependencies]`.
- **OASIS PKCS#11 3.1 headers**, vendored into `apps/apple/Provider/include`.
- **Flox catalog packages** for the project environment: `opensc`, `openssl`, `pkcs11-provider`, `openssh`, `rustup`.

## Settled with Brian (2026-11-19)

- **Distribution:** Flox instead of Homebrew; no formula or tap.
- **Config:** XDG path first (default `~/.config`), then Application Support, after Ghostty. The first file found wins, instead of Ghostty's merge, for the reasons in "Config file lookup". The spec change was approved.
- **Host name:** the `gethostname` crate.
- **Order:** Parts A and B in parallel, after Part 0.

## Decisions for Brian

1. **Who needs the macOS dylib besides you?** Flox's personal catalog installs only for its owner, and sharing needs a paid organization. If it's only you for the MVP, the personal catalog is enough. Is a notarized release asset worth doing now for other people? Doing it means creating the Developer ID certificate and a notary credential (steps above). Not doing it drops tasks 8 and the release-asset gate step.
2. **Rust version file.** Move the pinned toolchain from `mise.toml` to `rust-toolchain.toml` so the Flox build and mise read one version? mise picks it up either way.

## Still open

- Whether Apple's `/usr/bin/ssh` (through `ssh-pkcs11-helper`) loads the module. Checked in the gate; the docs say whatever we find.
- Whether Nix's `openssh` on macOS is built with PKCS#11 support. If it isn't, the gate's ssh check uses Apple's.
- Whether Flox's build step leaves the linker's signature alone. Checked in task 4.
- Flox packages for `x86_64-darwin` and the Linux systems. They need a publishing machine or CI runner for each, plus a FloxHub token in CI. After the MVP.
- A CryptoTokenKit persistent-token extension, so every app on macOS and iPadOS sees the relay keys, stays post-MVP (spec "MVP scope").
