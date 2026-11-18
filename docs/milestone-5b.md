# Milestone 5 Part B: USB card access and push (design)

Status: **approved by Brian on 2026-11-18** (decisions below). It
covers plan items 5.6 and 5.7 in `docs/milestone-5.md`. The iPhone gate's renewal step is still open; Brian chose to
start Part B in parallel (2026-11-18).

## Goal

- **USB card access:** the app runs approvals with a USB-C YubiKey, not only over NFC. This
  covers an Apple silicon Mac, a USB-C iPad, and a USB-C iPhone too (iPhone 15 and later).
- **Push:** the relay wakes the app through APNs when a request is waiting. The app no longer
  has to be open and polling.

## 5.6 USB card access

### What the platforms offer

- **iPadOS and iOS 16+:** CryptoTokenKit's `TKSmartCardSlotManager` gives an app the USB-C
  smart card slots, with the `com.apple.security.smartcard` entitlement. YubiKey 5 series keys
  present a CCID interface, which is what the system's driver needs. Yubico's own SDK uses this
  same API for USB-C on iOS, so we don't need the SDK. Apple's developer forums report it
  working on USB-C iPads, and failing on Lightning.
- **macOS:** the same `TKSmartCardSlotManager`, with the same entitlement, which the macOS
  target already has. macOS also has PC/SC, which `relay-pcsc` uses; on macOS PC/SC is built on
  top of CryptoTokenKit.

### Design

**One Swift transport for every USB card:** a `CardChannel` (the foreign trait relay-ffi
already defines) built on `TKSmartCard`. It replaces the plan's idea of using `relay-pcsc` on
the Mac (question 1).

- **Finding the card:** watch `TKSmartCardSlotManager.default` for slots, take the first card
  that answers `SELECT` of the PIV application, and read its serial (`GET SERIAL`). The engine
  maps manifest keys to slots by fingerprint, as it does over NFC, so either of Brian's
  interchangeable cards works.
- **Sessions:** `begin_session` / `end_session` map to `TKSmartCard.beginSession` /
  `endSession`, which give exclusive access, as the card-session decision requires. Inside a
  session, `transmit` sends APDUs with `TKSmartCard.transmit`.
- **No PIN left verified:** the card-session decision (2026-11-17) requires every session to
  end with no PIN verified. PC/SC does this with `SCARD_RESET_CARD`; `TKSmartCard` has no
  reset call. The transport ends every session with `VERIFY` with P1 = `FF`, which
  NIST SP 800-73-4 defines as "reset the security status" and which costs no PIN attempt. This
  was confirmed on a real YubiKey 5 on 2026-11-18 (question 2; see Decisions). If the YubiKey
  doesn't support it, the fallback is to `SELECT` another application, if that clears the PIV
  state, or to use `relay-pcsc` on the Mac and leave the iPad on CTK.
- **Touch:** with USB, keys whose touch policy requires it blink and wait for a touch. The
  approval screen says "Touch your YubiKey" while the card operation runs. Over NFC, holding
  the key to the phone counts as the touch.
- **Choosing a transport:** at enrollment and at each approval, the app uses a USB key if one
  is connected, and otherwise NFC where the device has it. The Status screen shows which.
  The approval order becomes: tap Approve, then Face ID, then PIN, then the card operation. With
  USB there is no NFC sheet, so the PIN can be typed after the request is shown, with no extra
  tap.
- **Hardware safety:** unchanged. Only operations the person approves reach the card, with
  the PIN they typed. The app never writes to a slot. Enrollment only reads certificates and
  signs with the attest key.

### Mac app

- **Menu-bar presence:** a SwiftUI `MenuBarExtra` with a count of waiting requests and
  shortcuts to the request list, status and Quit. The main window opens for an approval. The app
  keeps running in the menu bar when its window closes.
- **Keys:** the device key and relay-auth key live in the Mac's Secure Enclave, as on iOS.
  Touch ID replaces Face ID.
- **Signing and distribution:** built from Xcode with Brian's paid team, like the iPhone app.
  There is no notarised distribution in this milestone.

## 5.7 APNs

### Relay

- **New notifier** `notify.kind = "apns"`:

  ```toml
  [notify]
  kind = "apns"
  key_file = "/secrets/AuthKey_ABC123.p8"   # the .p8 from the developer account; never in the repo
  key_id = "ABC123"
  team_id = "TEAM12345"
  topic = "<bundle id>"                    # the app's bundle id
  environment = "sandbox"                  # "production" for TestFlight/App Store builds
  ```

- **Sending:** HTTP/2 POST to `api.push.apple.com` (or `api.sandbox.push.apple.com`)
  `/3/device/<token>`, with `apns-push-type: alert`, `apns-priority: 10` and
  `apns-expiration` set to the request's `expires_at`.
- **Payload:** content-free, as the spec requires: `{"aps":{"alert":{"title":"Relay
  Approver","body":"1 pending request"},"sound":"default"}}`. It carries no client, key,
  host or purpose; the app fetches those over its own authenticated connection.
- **Authentication:** an ES256 JWT (`iss` = team id, `iat`), signed with the `.p8` key using
  relay-core's existing P-256 signing. It is cached and refreshed every 30 minutes, inside
  Apple's 20-to-60-minute rule.
- **Token housekeeping:** if APNs answers 410 Unregistered or 400 BadDeviceToken, the relay
  removes that device's push token, keeps the device, and logs it.
- **Dependency:** reqwest's `http2` feature, which uses the `h2` crate. `h2` is already in the
  tree through axum and hyper, so nothing new is downloaded (question 3).
- The `PushTarget::Apns { token }` variant already exists in the device registry; only the
  sender is missing.

### App

- Register for remote notifications. Send the device token in the registration's `push` field
  as `{"kind": "apns", "token": "<hex>"}`, and re-register whenever the token changes.
- Entitlement: `aps-environment` (development for Xcode builds). This needs the push capability
  enabled for the app id in Brian's developer account.
- Tapping a notification opens the app on the Requests tab, which fetches what is pending.
- Out of scope, as the plan said: a Notification Service Extension showing a request summary.
  It would need the relay-auth key shared with the extension, through a keychain group.

### What push changes in the threat model

Nothing for confidentiality: the push carries no content (spec, threat model, "Push provider"
row). Apple learns when requests are waiting, as the spec already says.

## Tests

- **relay-core / relay-server:**
  - The APNs sender against a local HTTP/2 stub: headers, the JWT (verified with the matching
    public key), the content-free body, and token removal on 410.
  - The JWT refresh at 30 minutes.
  - Config validation.
- **relay-ffi:** a fake `CardChannel` that records `end_session`, to check that every session
  ends with the PIN reset.
- **Hardware, each command approved by Brian:**
  - The PIN reset: a `relayctl` check like milestone 4's `check-pin-reset`. It runs one
    `VERIFY`, a signature, `VERIFY` P1=`FF`, then the same signature without a PIN, which must
    fail. It uses a slot whose key has PIN policy `once` and no touch.
  - The Mac app over USB: enrollment and a decrypt with the second YubiKey.
  - If Brian has a USB-C iPad: the same on the iPad.
- **Push:** on Brian's iPhone, with the app in the background, a client request produces a
  notification within a few seconds, and tapping it opens the request.

## Work estimate

About 1 200 lines (Swift about 600, Rust about 600), in roughly this commit order:

1. The PIN reset in relay-core: `piv::reset_security_status`, plus a `relayctl` check
   command.
2. Swift `TKSmartCard` transport; transport choice; touch prompt; approval order for USB.
3. Mac menu-bar app; Touch ID.
4. Relay APNs notifier, with JWT, HTTP/2 and token housekeeping.
5. App push registration and notification handling.
6. Docs: spec (APNs settings), decisions, progress.

## Decisions (Brian, 2026-11-18)

| Question | Decision |
| --- | --- |
| Mac transport | CryptoTokenKit everywhere: one Swift `TKSmartCard` transport for Mac, iPad and USB-C iPhone |
| PIN reset check | Yes. Brian ran it himself on slot 9a (PIN `once`, touch `never`) on 2026-11-18: after `VERIFY` P1=`FF` the card refused to sign without the PIN, so the reset works |
| reqwest `http2` | Yes |
| Part B gate devices | The USB-C iPad is in the gate |
| Attestation window picker | Add 15 and 30 minutes |

## Still open

- Nothing. The APNs key arrived on 2026-11-18 and push works on the iPhone (`docs/progress.md`).

## Sources

- Apple developer forums on `TKSmartCardSlotManager` over USB-C on iPadOS:
  developer.apple.com/forums/thread/725152 and thread/749896.
- Yubico's yubikit-ios README (USB-C via `com.apple.security.smartcard`):
  github.com/Yubico/yubikit-ios.
- NIST SP 800-73-4, Part 2, `VERIFY` with P1 = `FF`.
- Apple, "Sending notification requests to APNs" and "Establishing a token-based connection to
  APNs".
