# Milestone 5: Apple approver app, work breakdown

This phase builds the approver app for iPhone, then runs the same target on iPad and Mac. `docs/spec.md` remains the source of truth: "Approver application", "Approver apps" and "Milestones" item 5. This file turns those into tasks, sets defaults for what the spec leaves open (Brian's decisions of 2026-11-17 included), and defines the gate.

**Spec gate:** a `pkcs11-tool` decrypt on a Linux host completes after an approval on an iPhone over NFC, and an attestation renewal succeeds.

## What already exists and what is missing

The checks are already in `relay-core`. The approver *flow* is not: it lives in `relay-test-approver/src/approver.rs`. That flow checks a request, maps the key to a slot, runs the PIN and the card operation, seals the result, signs the response, and decides when to renew the attestation. The app must not reimplement that flow in Swift (CLAUDE.md: "All security checks live in relay-core"; spec: "platform code never parses or signs protocol messages itself"). So the first task is to move it into a shared crate. The test approver then becomes a thin driver of the same code the app runs, and CI keeps covering it.

## Layout added in this phase

```
crates/
  relay-approver/      # approver engine: request checks → approval view → card op → sealed, signed response;
                       # pairing approval; enrollment; renewal; replay cache; key map. Blocking relay client (ureq).
                       # #![forbid(unsafe_code)]. Used by relay-test-approver and relay-ffi.
  relay-ffi/           # UniFFI wrapper over relay-approver: the DeviceSigner and CardTransport foreign traits
                       # (WakeUp later); a softcard transport behind a `test-card` feature for the simulator.
apps/apple/
  project.yml          # XcodeGen spec; the generated .xcodeproj is not committed
  Local.xcconfig       # git-ignored: DEVELOPMENT_TEAM and bundle-id prefix (the repo is public)
  RelayApprover/       # one SwiftUI multiplatform target: iOS, iPadOS, macOS
  RelayApproverTests/  # XCTest: golden vectors through the Swift bindings; simulator end-to-end with the softcard
  build-xcframework.sh # cargo builds for ios, ios-sim and macOS, uniffi-bindgen, xcodebuild -create-xcframework
```

## Details the spec leaves open: defaults

| Topic | Default | Why |
|---|---|---|
| Rust ↔ Swift | UniFFI in proc-macro mode (no UDL). One `RelayApprover` object; foreign traits `DeviceSigner` and `CardTransport`. Errors are flat enums. | The spec names UniFFI. Proc macros keep the interface next to the Rust code. |
| Where networking runs | In Rust: a blocking `ureq` + rustls relay client in `relay-approver`, with the relay CA from config, called from a Swift background task. While the app is in the foreground it long-polls `/v1/devices/{id}/pending`. | TLS trust and relay authentication then stay in Rust, like the provider. Swift adds no custom `URLSession` trust code. No async runtime is needed. |
| Where the PIN, plaintext and card operation live | Swift collects the PIN and passes it to Rust once. Rust runs `VERIFY`, the operation and the sealing in one call through `CardTransport`. The plaintext result never crosses the FFI. | Decrypt results stay in Rust memory and are zeroized there. Swift `String`s cannot be zeroized reliably, so the PIN lives in Swift for as short a time as possible: `SecureField` → bytes → Rust, then cleared. |
| Card sessions | Every group of commands that belongs together (`SELECT`, `VERIFY`, the operation, a renewal signature) runs inside one `CardTransport::session`. A session holds the card exclusively and leaves no PIN verified when it ends. PC/SC: one transaction that first rechecks the serial and ends with `SCARD_RESET_CARD`. NFC: one tap, since the card loses power afterwards. `TKSmartCard` (iPad): `beginSession`/`endSession`; clearing the PIN state there still needs a method (task 5.6). The Swift trait gets `begin`/`end`, and the FFI adapts them to `session`. | Other programs, including macOS's own PIV token and `SecKey` users, wait instead of interleaving commands, and they cannot reuse our PIN verification. |
| `CardTransport` from Swift | Synchronous `transmit(apdu) -> response` called by Rust on a background thread. The Swift side waits on the async CoreNFC or TKSmartCard callback. | It is the same trait as the softcard and PC/SC, so the PIV code path is unchanged. |
| Device key | CryptoKit `SecureEnclave.P256.Signing.PrivateKey`, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, access control `.privateKeyUsage` + `.biometryCurrentSet` (Brian). Rust passes it the exact signed bytes. The Secure Enclave hashes them with SHA-256 and returns raw `r‖s`. Rust verifies every device signature before posting it. | This matches the existing device-key format. The Secure Enclave refuses to sign without a fresh biometric, so code injected into the app cannot sign forged responses silently (threat-model row "approver device, running malware"). Re-enrolling a finger or face invalidates the key and forces re-enrollment. |
| Relay authentication | A second Secure Enclave key, without a biometric, signs every relay call. The device key vouches for it once at enrollment (wire-format §8.4), and the binding is sent with each registration. | Otherwise every long-poll would need Face ID (Brian, 2026-11-17). |
| Biometric before PIN | One `LAContext` evaluation at the start of each approval. The same context is passed to the signing call (`authenticationContext`), so a single Face ID covers the approval, the response signature and a renewal in the same tap. | Requests that fail the checks are denied with a signature the next time the user opens the app. Until then they expire, and the client gets `CKR_FUNCTION_CANCELED` instead of `CKR_FUNCTION_REJECTED`. |
| NFC flow | Approve → biometric → PIN entry → one NFC session: `SELECT`, `GET SERIAL`, `VERIFY`, the operation, and the renewal signature if due → session ends. The NFC sheet shows progress. | A tap over NFC counts as the touch, so touch `always` on the attest key needs no separate action. One tap per approval, as the spec requires. |
| NFC entitlement | `com.apple.developer.nfc.readersession.formats = [TAG]`; `select-identifiers = [A000000308]` | From the spec. |
| Card access on iPad and Mac | `TKSmartCard` (CryptoTokenKit) raw APDUs on macOS, with the `com.apple.security.smartcard` entitlement. iPad over USB-C: spike first (task 5.6). | The same core PIV path on every platform. No CryptoTokenKit-extension or Security.framework PIN path for now. |
| Setup input | A setup file produced by a new `relayctl app-config` command. It is JSON: relay URL, relay CA PEM, manifest URL, signer public key, device id. It is imported through Files or AirDrop, and the app shows the signer's fingerprint for confirmation. | Typing a PGP key on a phone is impractical, and the file is public material. |
| Manifest URL | The relay serves the signed manifest: `GET /v1/manifest` and `GET /v1/manifest.asc`, from files named in its config (spec change approved by Brian). The app and clients may use it or any other URL, and the app caches the last verified copy. | `file://` does not work on a phone. The relay is untrusted but cannot forge a signed manifest, and rollback is blocked by `version`. |
| Local storage | Application Support files with `NSFileProtectionComplete`: config, the paired-client list, the attestation, the 24 h replay cache, history. History keeps metadata and hashes only, never results. | This follows the rule that confidentiality content never leaves RAM. |
| Wake-up | Part A: none. The user opens the app, which long-polls in the foreground. Part B: APNs (see below). | The gate does not need push. Push needs an Apple Developer team and a `.p8` key on the relay. |
| Approval screen | Spec MVP: client, host, purpose, key label and role, operation, time left. Content is shown as hex and SHA-256, with the requester's claims visually separated. The view model comes from Rust; Swift only renders it. | Swift never interprets protocol fields. |

Unchanged from the spec and milestones 1–4: the five-step response format, context strings, one role per key, no PIN caching, and stopping after one wrong PIN. That last rule now applies to the app too: after a rejected PIN the app refuses further card operations until the user acts again. It never retries on its own.

## Tasks

### Part A: engine, bindings and iPhone over NFC (the gate)

**5.0 Relay serves the manifest.** `manifest_file` and `manifest_signature_file` in the relay config. `GET /v1/manifest` and `/v1/manifest.asc` serve the bytes unchanged, with no authentication. Tests confirm the provider and the test approver accept a manifest served this way. Part of the Docker gate.

**5.1 Extract `relay-approver`.** Move the approver flow out of `relay-test-approver` into a sans-UI engine:

- `check_request` → an `ApprovalView` (or a signed denial for checks that fail);
- `approve(request, pin, card, signer)` → a posted response;
- `deny`;
- `pending_pairings` / `approve_pairing(client, keys)`;
- `enroll(card, pin, window)`;
- `needs_renewal(now)`.

The relay client is blocking (`ureq`), not the test approver's tokio/reqwest client. The test approver keeps its own async driver and calls the engine for every decision. Done when `cargo test --workspace` and the Docker gate pass unchanged.

**5.2 `relay-ffi`.**
- UniFFI exports with the `DeviceSigner` and `CardTransport` foreign traits.
- A `test-card` feature exposes a softcard transport.
- `build-xcframework.sh` builds `aarch64-apple-ios`, `aarch64-apple-ios-sim` and `aarch64-apple-darwin`. x86_64 Mac is left out unless Brian wants it.
- Swift golden-vector tests run every `relay-core/tests/vectors` case through the bindings (spec "Testing").

**5.3 App skeleton.** XcodeGen `project.yml` (XcodeGen pinned in `mise.toml`); SwiftUI multiplatform target with the five spec screens: Setup, Enrollment, Approval, Pairing, Status. Secure Enclave `DeviceSigner`. Storage as in the defaults table. Add `relayctl app-config`.

**5.4 NFC `CardTransport`.** CoreNFC `NFCTagReaderSession` (ISO 7816), session lifecycle, error mapping to the core's `PivError`, and the single-tap approval flow. Also covers enrollment over NFC: list slots, match against the manifest, and get the attestation signed by the attest key.

**5.5 Simulator end-to-end in CI.** A new macOS CI job:
- build the XCFramework;
- start the relay and a Linux client in Docker;
- run the app's UI test in the iOS simulator against the softcard (`test-card` feature, debug builds only);
- the client's `pkcs11-tool` decrypt completes after the UI test taps Approve.

This needs Docker on the macOS runner; if that turns out impractical, the relay runs natively there. The test covers everything except NFC and the Secure Enclave (the simulator signs with a software key behind the same trait).

### Part B: wake-up, iPad and Mac

**5.6 iPad and Mac transports.** Targets: an Apple silicon Mac and a USB-C iPad with a YubiKey 5C. On macOS, reuse `relay-pcsc` (PC/SC runs on top of CryptoTokenKit), which already has sessions with a reset, plus the `com.apple.security.smartcard` entitlement; this replaces a Swift `TKSmartCard` transport on the Mac. iPad over USB-C: first confirm what iPadOS offers. YubiKit uses `TKSmartCard` there on recent iPadOS; check whether we can use it directly or need YubiKit (adding YubiKit needs Brian's approval). Menu-bar presence on macOS (spec).

**5.7 APNs.**
- An APNs sender in `relay-server`: token-based `.p8`, content-free "1 pending request", the per-device token from `POST /v1/devices`.
- The app registers for remote notifications, and tapping a notification opens the pending request.
- The Notification Service Extension that shows a request summary is optional. It would need the device key reachable from the extension (shared keychain group) to authenticate to the relay, so it waits until after the gate.

Part B starts after the iPhone gate passes, and milestone 5 is complete only when Part B is done too.

## Gate (manual, on Brian's iPhone, plus CI)

1. **CI:** `cargo test --workspace`, the Docker gate, Swift golden vectors and the simulator end-to-end test are all green.
2. **Setup:** the relay runs where the iPhone can reach it, on the tailnet. The client is a Linux container running `pkcs11-tool` against the provider (colima counts as the Linux host).
3. **Keys:** the milestone 4 keys on YubiKey <serial> (slots 85–89) and the existing signed manifest.
4. **Build:** the app is installed from Xcode onto Brian's iPhone, using his paid team (from `Local.xcconfig`).
5. **Enrollment:** the iPhone app enrolls with an NFC tap. The attest key in slot 85 signs its attestation, and the app registers `hw-unseal` and the other keys.
6. **Decrypt:** a `pkcs11-tool` RSA-OAEP decrypt with `hw-unseal` succeeds after Approve → Face ID → PIN → NFC tap, and the plaintext matches.
7. **Renewal:** the app is enrolled with a short window (for example 20 minutes), so renewal is due at 15 minutes. After that point, an approval renews the attestation in the same tap. The next response carries the new statement, and the provider accepts it.
8. **Refusals:**
   - a denial on the phone gives `CKR_FUNCTION_REJECTED`;
   - letting the request expire gives `CKR_FUNCTION_CANCELED`;
   - a wrong PIN gives one attempt, a signed error and `CKR_DEVICE_ERROR`, and no further attempt.

Hardware safety: the same rules as milestone 4. Only the user's taps reach the YubiKey from the app. The app never runs card commands without a tap and a PIN the user typed for that approval. It never writes to a slot: enrollment only reads certificates and signs with the attest key.

## Dependencies to approve

- **Rust:** `uniffi` (crate and `uniffi-bindgen`, pinned to the current release); `ureq` is already in the workspace for the provider.
- **Swift:** none for Part A (CryptoKit, CoreNFC, LocalAuthentication are system frameworks). Possibly YubiKit for iPad USB-C (5.6).
- **Tooling:** XcodeGen (via mise, approved); rustup targets `aarch64-apple-ios`, `aarch64-apple-ios-sim`.

## Decisions (Brian, 2026-11-17)

1. **Apple account.** A paid team. Gate builds are installed from Xcode. The team ID and bundle-ID prefix live in the git-ignored `apps/apple/Local.xcconfig`.
2. **Hardware.** The gate YubiKey has NFC. Part B targets a USB-C iPad with a YubiKey 5C and an Apple silicon Mac.
3. **Biometrics.** Enforced by a flag on the Secure Enclave key, with one Face ID per approval reused for the signature.
4. **Xcode project.** XcodeGen.
5. **Manifest.** The relay serves it (spec updated).
6. **Order.** Part A and the gate first, then Part B, before the milestone is done.
