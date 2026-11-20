# Relay keys in the system keychain (CryptoTokenKit extension)

Status: **draft for Brian's review (2026-11-20).** Nothing here is built. It changes the spec (see "Spec changes"), so it needs Brian's approval before any code, and its first step is a prototype whose results may change the design.

## Goal

Let any app on a Mac, iPhone or iPad use the relay's keys through the system keychain (`SecKeyCreateSignature`, `SecKeyCreateDecryptedData`, `SecKeyCopyKeyExchangeResult`, and identities for TLS client authentication and S/MIME), with every operation still approved by a person, on the PIN and the YubiKey, exactly as today.

The PKCS#11 provider covers command-line tools and anything that loads a module. It can't reach apps that only use the keychain, and on iOS and iPadOS nothing can load a module at all. The spec lists "CryptoTokenKit token extensions for system-wide use on macOS and iPadOS" as out of scope for the MVP; this design brings it in as its own phase.

The iPadOS static library and sample app in milestone 7 Part B stay: an app that links the library can pass the richer request context (purpose, consumer) that the keychain has no way to carry. The extension is for every other app.

## Summary

- The approver app gains a **persistent-token extension**. It exposes one token holding the manifest's `sign`, `auth` and `encrypt` keys, with a certificate for each key that has one in the manifest.
- The extension is a **client**, like the PKCS#11 provider: its own client identity key, paired and granted like any other client. It builds the same signed request envelope, and it verifies the response with the same `relay-core` functions.
- **Two routes for a request:**
  - **Local:** this device's own approver app operates the key. The extension hands the signed request to the app through the shared App Group container, posts a notification, and waits. The person taps the notification, approves in the app (Face ID, PIN, NFC tap or USB), and the app hands back the signed response. No relay leg; the app posts the request and the response to the relay afterwards for the audit log.
  - **Relay:** some other approver operates the key. The extension posts the request to the relay and waits, as the provider does.
- **Nothing new to trust.** A local request is checked by the app's engine exactly as a relayed one is (grant, replay cache, role, rate limit), and a local response is verified by the extension exactly as the provider verifies one. The result travels sealed to a one-time reply key, so no plaintext or signature touches the shared container in the clear.

## Background: how Yubico's extension does the hand-off

Yubico's iOS Authenticator ([Yubico/yubioath-ios](https://github.com/Yubico/yubioath-ios), `TokenExtension/TokenSession.swift`, `Authenticator/Model/TokenRequestViewModel.swift`) shows the hand-off works on iOS over NFC:

1. The system calls the extension's sign or decrypt method. The extension posts a local notification with a foreground action; the data, key object id and algorithm ride in its `userInfo`.
2. The extension blocks, polling the App Group's `UserDefaults` once a second for up to 95 seconds for `signedData`, `decryptedData` or `canceledByUser`.
3. The notification opens the app on a PIN screen. The app connects to the YubiKey (NFC or wired), verifies the PIN, runs the operation, and writes the result to the shared `UserDefaults`.
4. The person switches back to the calling app themselves; there's no automatic return.

CryptoTokenKit calls the sign method several times for one operation, even after an error. Yubico answers repeat calls inside a 100-second window with "cancelled", so only one notification shows.

What this design changes: the shared store holds signed and sealed messages, never a plaintext or a bare signature, and it isn't `UserDefaults` (a plist on disk); repeats are recognised by what was asked, not by a time window; the app shows the full approval screen, not only a PIN field.

## Prototype first

Each item has a pass condition. The design below assumes they pass; where one fails, the fallback is noted.

| # | Question | Pass | If it fails |
| --- | --- | --- | --- |
| P1 | Does a persistent-token extension stay alive, blocked in its sign method, while the calling app is in the background and the person approves in our app? | A Mail or test-app signature completes after a 60 s wait on iPhone (NFC) and iPad (USB-C) | Shorter request expiry; if under ~20 s, the local route is impractical on iOS |
| P2 | How long will callers wait? | Record each caller's limit: Mail, Safari client auth, `ssh` through `ssh-keychain.dylib`, `security`, a test app | Request expiry is set per platform below the shortest useful limit |
| P3 | Why does CryptoTokenKit repeat calls? | Log every call (time, key, algorithm, input digest): same input repeated, different algorithms, or retries after errors | The dedup key below already covers all three; the log tells us which to tune |
| P4 | Can the extension return a bare key (no certificate) that callers like `ssh-keychain.dylib` find? | `ssh -I /usr/lib/ssh-keychain.dylib` lists and uses a key without a certificate | Every exposed key needs a certificate in the manifest |
| P5 | Can the extension post a notification and read the App Group container while the device is locked? | Defines what "locked" does | The extension fails fast with "device locked" instead of waiting |
| P6 | Can the extension reach the relay (long-poll, TLS with the pinned CA) for the full wait? | A relayed signature completes from the extension on each platform | Relay route only from the app (the extension hands off, the app relays) |
| P7 | Does the Mac app come to the front from the notification, and hide itself afterwards so the calling app is in front again? | Both on macOS 14+ | The person switches back by hand, as on iOS |

## Design

### The token

- One token configuration, created by the app with `TKTokenDriver.Configuration`, named after the relay, holding one keychain key item per manifest key with role `sign`, `auth` or `encrypt` (never `attest`), with the manifest's label.
- Each key carries its leaf certificate when the manifest has one (see "Certificates"); the item is then an identity that TLS client authentication and S/MIME can select. Without a certificate the key is a bare key item (P4).
- The app rewrites the configuration whenever it accepts a new manifest: keys added, removed or with new certificates. It also removes the configuration when the app is reset or the feature is turned off.
- The token lists keys the manifest trusts, not keys some approver has advertised. A key no approver currently operates still appears; a request for it fails with "no approver" (see "Errors").
- `attest` keys are never exposed, as in the provider.

### The extension is a client

- **Identity.** At setup the app creates the extension's client identity key: a Secure Enclave P-256 key in a keychain access group shared with the extension, usable without a biometric (approval is the gate, as for the provider's key file). Client id `<device-id>-keychain`.
- **Pairing.** The extension's key pairs through the relay like any client (`POST /v1/clients/pending`). The app recognises its own extension's key, so it skips the code comparison and goes straight to the key and window choice and the YubiKey signature of the grant. Other approvers accept the client with its first request there, as for any client.
- **Shared code.** The provider's client logic (building and signing the request, the one-time reply key, waiting, verifying the response, opening the sealed result) moves from `relay-pkcs11` into a new `relay-client` crate with no C ABI, used by `relay-pkcs11` and by a new `Client` object in `relay-ffi`. The extension links `RelayFFI` (one Rust static library per binary; the app and the extension are separate binaries). No verification is reimplemented.
- **Request context.** CryptoTokenKit doesn't tell the extension which app called it. The extension sends `host` = this device's name, `consumer` = `keychain`, and `purpose` = a setting, default "Keychain on <device name>". The approval screen says the calling app is unknown.

### Which route

For each operation the extension reads the app's key map from the shared container (fingerprints only, written by the app):

1. **Local**, if this device's approver app operates the key (it's in the key map).
2. **Relay** otherwise.

A local request offers "Send to another approver" on the approval screen and in the notification. Taking it, or letting the local wait pass a setting's limit, moves the request to the relay route with a new request (a new id; the old one is cancelled locally). Whether to fall back automatically is a setting (see Decisions); the default is no: an unanswered local request expires.

### The local route

1. The extension builds and signs the request (same envelope, `expires_at` from the per-platform limit) and creates the request's record in the shared store (below). Creating it is atomic, so only one call per operation posts the notification.
2. The notification ("Approve a keychain request: hw-sign") opens the app on the approval screen for that record.
3. The app's engine checks the request as if the relay had delivered it: client signature, grant and acceptance, replay cache, expiry, role and mechanism, rate limit. The approval screen is the usual one, with the "calling app unknown" line. Face ID, PIN and the card operation follow as today; renewal of the attestation or the grant can happen in the same card session.
4. The app writes the signed response to the record and, on macOS, hides itself (P7). On iOS the screen ends with "Done: return to your app".
5. The extension sees the response, verifies it with `verify_response` (attestation, device signature, request binding, the signature check against the hardware key), opens the sealed result in memory with the reply key, zeroizes the reply key, and returns the result to the system.
6. The app posts the request and the response to the relay for the audit log (`POST /v1/audit/local`, below), queued if the relay is unreachable.

A denial or a card error is a signed response like any other, so the extension maps it as the provider does.

### The relay route

The extension submits the request to the relay and waits on the long-poll, as the provider does, bounded by the same per-platform limit. Every approver that operates the key is rung; the first valid response wins. The extension verifies and opens it exactly as above.

### The shared store

A directory in the App Group container, files written with complete file protection. One record per operation, named by `SHA-256(key fingerprint ‖ algorithm ‖ input)`:

| Field | Written by | Content |
| --- | --- | --- |
| `request` | extension | The signed request envelope (input included: a digest, a message to be signed, or a ciphertext) |
| `state` | both | `pending`, `answered`, `cancelled`, `expired` |
| `response` | app | The signed response envelope; the result inside is sealed to the extension's reply key |
| timestamps | both | Created, answered |

Rules:
- **Created atomically** (exclusive create). The call that creates it posts the notification; any other call for the same key, algorithm and input, from the same session, a new session or a restarted extension process, waits on the existing record.
- **Answering repeats.** A repeat while `pending` waits. A repeat within a few seconds of an approved signature gets the same signature (the extension keeps it in memory for that time). A repeat after a decrypt or key exchange was delivered asks again: plaintexts aren't kept for repeats. A repeat after a denial gets the denial until the record expires.
- **Lifetime.** A record lives until the request's `expires_at` plus a short grace, then is deleted by whichever process next looks.
- **Where the logic lives.** The record format and rules are Rust, in `relay-client` (the extension's side) and `relay-approver` (the app's side), exposed through `relay-ffi`; Swift only passes the container path.

Because the store holds only signed requests and sealed responses, reading it gives nothing beyond what the relay already sees on the relay route.

### Certificates

A new optional manifest field, signed with everything else:

| Field | Example | Meaning |
| --- | --- | --- |
| `keys[].certificates` | `["MIIC…", "MIIB…"]` | Optional, on `sign`, `auth` and `encrypt` keys only. DER X.509 certificates, base64: the leaf first, whose SubjectPublicKeyInfo must equal `keys[].public_key`, then any intermediates. At most 4, each at most 8 KiB |

`verify_manifest` checks that each certificate parses, that the leaf's key matches, and the limits; a bad entry makes the manifest invalid, like any schema error. It does not validate the chain: whoever relies on the certificate does that against their own trust store. Certificates are issued by Brian's own CA (or any CA) outside this system; `relayctl manifest add-certificate` adds one. The extension presents the leaf (and the intermediates, for TLS); the provider ignores the field.

Whole certificates, not hashes, because the extension needs the bytes and the manifest is already the trusted channel; a certificate change means re-signing the manifest either way.

### Algorithms

The keychain's algorithms map onto the spec's mechanisms. Roles stay as the spec defines them: a `sign` key must receive the full message so the approver can hash and show it, so it accepts only message algorithms.

| Role | Keychain algorithm | Request |
| --- | --- | --- |
| `sign` | `ecdsaSignatureMessageX962SHA256` / `SHA384`, `rsaSignatureMessagePKCS1v15SHA256` | `CKM_ECDSA_SHA256` / `SHA384`, `CKM_SHA256_RSA_PKCS`, full message |
| `auth` | `ecdsaSignatureDigestX962` (any digest length the curve allows), `ecdsaSignatureRFC4754`, `rsaSignatureDigestPKCS1v15SHA256` / `Raw` | `CKM_ECDSA`, `CKM_RSA_PKCS`, digest or DigestInfo |
| `encrypt` | `rsaEncryptionOAEPSHA256` | `CKM_RSA_PKCS_OAEP` (SHA-256, MGF1-SHA256) |
| `encrypt` | `ecdhKeyExchangeStandard` | `CKM_ECDH1_DERIVE` with `CKD_NULL` |

Anything else is refused by `supports`, so the caller sees the key as unable to do it. Most keychain callers, S/MIME and TLS among them, sign a digest, so their keys are `auth` keys in this model; the approval screen shows only the digest for them, as it does for `auth` keys today. RSA PKCS#1 v1.5 decryption is not supported (see "Still open").

### Errors

| Situation | Returned to the caller |
| --- | --- |
| Signed denial (`user_denied`, `client_*`, `key_not_granted`, `policy`, `expired`) | `TKError.canceledByUser` |
| Signed error (card absent, wrong PIN, PIN blocked, card error) | `TKError.communicationError` |
| No answer before `expires_at` | `TKError.canceledByUser` |
| Response fails verification (attestation, device signature, request binding, signature check) | `TKError.corruptedData`, logged loudly |
| Relay unreachable on the relay route; no approver operates the key | `TKError.communicationError` |
| Algorithm not allowed for the key's role | `supports` returns false; the operation is never attempted |
| Manifest invalid or expired, or this client revoked | The token is emptied: the app removes its keys from the configuration |

## Relay

- **`POST /v1/audit/local`**, relay-auth key of an enrolled, attested device. Body `{"request", "response"}`, base64 CBOR. The relay checks the client signature and grant, and the response's device signature and binding to the request, as it would for a relayed pair (hygiene: it isn't trusted either way), and that the device posting it is the one that signed the response. It stores an audit row with event `local_response`, keeping full bytes for sign operations and only hashes for decrypts and key exchange, as for relayed operations. A replayed pair is refused (409) by `req_id`.
- Nothing else changes: pairing, grants and the relay route use the existing endpoints.

## What changes in the threat model

| Compromised | New exposure | What still stops them |
| --- | --- | --- |
| Any app on a device with the extension | Can ask for operations with every exposed key, as an anonymous keychain caller | Each operation needs a person's approval on the PIN and the YubiKey; the screen says the calling app is unknown; rate limits; the extension can be turned off |
| The approver app (malware in its process) | Already holds the device key; now also sees local requests directly | Unchanged: short attestation windows, the signature check against the hardware key, touch `always` |
| The App Group container (read) | Signed requests and sealed responses | Results are sealed to a reply key that never leaves the extension's memory |
| The App Group container (write) | Could plant a request or a response | A planted request must carry the extension's client signature; a planted response must verify against an attested device key and this request |
| The relay | Can drop or delay local audit posts | Audit was already relay-side; the app keeps its own local history |

Approval fatigue gets worse: any app can now trigger a request at a plausible moment, and the screen can't name it. The defenses stay the same (approve only what you just started; the purpose text; rate limits), and the setting to turn the extension off is the backstop.

## Spec changes

- **Approver application:** the extension, the two routes, the local hand-off, the client identity for `<device-id>-keychain`, and the "calling app unknown" line on the approval screen.
- **Trust manifest:** `keys[].certificates`; wire-format §9.2.
- **Relay:** `POST /v1/audit/local`; wire-format §10.
- **Keys and messages / wire format:** none; the request and response envelopes are unchanged.
- **Threat model:** the rows above.
- **Failure handling:** the extension's rows above, each with a test.
- **Code structure:** the `relay-client` crate.
- **MVP scope and milestones:** move "CryptoTokenKit token extensions for system-wide use on macOS and iPadOS" from "Out, for later" into a new phase after milestone 7.

## Tests

- `relay-core`: manifest certificate checks (parses, leaf key matches, limits, wrong role), golden vectors.
- `relay-client`: the shared store's record rules (atomic create, repeats while pending, after approval, after a decrypt, after a denial; expiry and cleanup), with two processes racing.
- `relay-approver`: a local request is checked exactly like a relayed one; every rejection reason; the response is accepted by `verify_response`.
- `relay-server`: `/v1/audit/local` accepts a valid pair, refuses a mismatched, unsigned, replayed or foreign-device pair, and keeps only hashes for decrypts.
- `relay-ffi`: the whole local route with the softcard and a temporary directory as the store; the relay route against a real relay; the fallback to the relay.
- Simulator: an XCUITest app calls `SecKeyCreateSignature` on the token's key, the test approves in the app, the signature verifies. Whether persistent tokens work in the simulator is part of the prototype; if not, this is a device test.
- One test per new Failure handling row.
- **Gate** (on Brian's hardware):
  1. iPhone, NFC, local route: Mail signs a message with an `auth` key that has a certificate, after an approval on the phone; the signature verifies.
  2. Mac, relay route: `ssh -I /usr/lib/ssh-keychain.dylib` authenticates with `hw-auth`, approved on the phone.
  3. iPad, USB-C, local route: a test app decrypts with `hw-unseal`; the plaintext matches.
  4. The relay's audit log has rows for the local operations, with only hashes for the decrypt.

## Work estimate

| Part | Size |
| --- | --- |
| Prototype (P1–P7) | A few days, mostly on devices |
| `relay-client` extraction, `Client` in `relay-ffi`, the shared store | Medium |
| Extension, token configuration, notification hand-off, settings | Medium to large |
| Manifest certificates, `relayctl`, `/v1/audit/local` | Small to medium |
| Tests, simulator or device tests, gate | Medium |

## Decisions for Brian

1. **Where it goes.** A new phase after milestone 7 (my default), or folded into milestone 7 Part B?
2. **Fallback to the relay.** When the key is local and the person doesn't answer: expire (default), or send to the other approvers automatically after a limit? And should "Send to another approver" exist at all on the local route?
3. **Digest-signing callers.** Mail and TLS sign digests, so their keys must be `auth` keys (digest only on screen). Keep the spec's roles as they are (default), or let a `sign` key accept digests from the keychain?
4. **Pairing the extension.** Skip the code comparison for the app's own extension, since the app created its key (default), or show the code anyway?
5. **Bare keys.** If P4 passes, expose keys without certificates (default: yes, so `ssh` works without a CA), or only identities?
6. **Locked device.** If P5 shows the extension can't work while the device is locked: fail fast (default) or wait for unlock?

## Still open

- **RSA PKCS#1 v1.5 decryption** for S/MIME. Not in the spec, for the padding-oracle reasons discussed on 2026-11-20. Check first whether Mail can decrypt with an elliptic-curve S/MIME certificate (ECDH, which this design supports).
- **System PIN prompt on iOS** (`TKTokenSmartCardPINAuthOperation`), so the PIN never enters our process: a post-MVP investigation already noted in `docs/progress.md`.
- **A local route inside the extension**, without the app hand-off: on the Mac, Face ID from inside the extension worked in Brian's own experiment, and USB smart cards may be reachable from it. It would remove the app switch for USB on the Mac. Later, once the hand-off works everywhere.
- **Returning to the calling app on iOS** automatically: no public API exists. The private one is ruled out.
