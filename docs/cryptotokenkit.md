# Relay keys in the system keychain (CryptoTokenKit extension)

Status: **draft for Brian's review (2026-11-20); first decisions taken the same day** (see Decisions). Nothing here is built. It changes the spec (see "Spec changes"), so it needs Brian's approval before any code, and its first step is a prototype whose results may change the design.

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

Each item has a pass condition. The design below assumes they pass; where one fails, the alternative is noted.

| # | Question | Pass | If it fails |
| --- | --- | --- | --- |
| P1 | Does a persistent-token extension stay alive, blocked in its sign method, while the calling app is in the background and the person approves in our app? | A Mail or test-app signature completes after a 60 s wait on iPhone (NFC) and iPad (USB-C) | Shorter request expiry; if under ~20 s, the local route is impractical on iOS |
| P2 | How long will callers wait? | Record each caller's limit: Mail, Safari client auth, `ssh` through `ssh-keychain.dylib`, `security`, a test app | Request expiry is set per platform below the shortest useful limit |
| P3 | Why does CryptoTokenKit repeat calls? | Log every call (time, key, algorithm, input digest): same input repeated, different algorithms, or retries after errors | The dedup key below already covers all three; the log tells us which to tune |
| P4 | Can a token key item exist without a certificate (`TKTokenKeychainKey` with no certificate, public key and type set directly), and do callers like `ssh-keychain.dylib` find it? | `ssh -I /usr/lib/ssh-keychain.dylib` lists and uses such a key | The app serves a placeholder certificate for keys the manifest gives none (see "Certificates") |
| P5 | While the device is locked, can the extension sign with its client key, write its record (files protected until first unlock) and post a notification that shows on the lock screen? | A background caller's request (a scheduled `ssh` on the Mac, a test app's background task on iOS) is approved after unlocking from the notification | The extension fails fast with "device locked" |
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

- **Identity.** At setup the app creates the extension's client identity key: a Secure Enclave P-256 key in a keychain access group shared with the extension, usable without a biometric (approval is the gate, as for the provider's key file) and accessible after first unlock (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`), so background callers work while the device is locked. Client id `<device-id>-keychain`.
- **Pairing.** The extension's key pairs through the relay like any client (`POST /v1/clients/pending`). The code comparison is what stops a relay from swapping in its own key, so the app does it automatically and more strictly than a person can: it reads the extension's public key from the shared keychain, where it created it, and requires the pending pairing's key to equal it exactly. Then the person chooses keys and window and the YubiKey signs the grant, as for any pairing. Other approvers accept the client with its first request there, as for any client.
- **Shared code.** The provider's client logic (building and signing the request, the one-time reply key, waiting, verifying the response, opening the sealed result) moves from `relay-pkcs11` into a new `relay-client` crate with no C ABI, used by `relay-pkcs11` and by a new `Client` object in `relay-ffi`. The extension links `RelayFFI` (one Rust static library per binary; the app and the extension are separate binaries). No verification is reimplemented.
- **Request context.** CryptoTokenKit doesn't tell the extension which app called it. The extension sends `host` = this device's name, `consumer` = `keychain`, and `purpose` = a setting, default "Keychain on <device name>". The approval screen says the calling app is unknown.

### Which route

For each operation the extension reads the app's key map from the shared container (fingerprints only, written by the app):

1. **Local**, if this device's approver app operates the key (it's in the key map).
2. **Relay** otherwise.

A local request that nobody answers expires; it never falls back to the relay (Brian, 2026-11-20). Locked devices are covered by the protection classes: the notification shows on the lock screen, and unlocking and tapping it opens the approval within the request's expiry.

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

A directory in the App Group container, files protected until first unlock (`completeUntilFirstUserAuthentication`), so a background caller works while the device is locked. That class is acceptable because the files hold only what the relay sees on the relay route: signed requests and sealed responses. One record per operation, named by `SHA-256(key fingerprint ‖ algorithm ‖ input)`:

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

Certificates are issued by Brian's own CA (or any CA) outside this system. Two levels of checking, neither of which decides trust (that stays with whoever relies on the certificate):

- **When adding, `relayctl manifest add-certificate`** checks the whole chain, so a problem shows up before the manifest is signed rather than on first use: every certificate parses; the leaf's key equals the manifest key; each certificate's issuer matches the next one's subject and its signature verifies with the next one's key; every certificate is valid now (refused if expired, a warning if it expires before the manifest's `valid_until`); key usage fits the role (`digitalSignature` for `sign` and `auth`, `keyEncipherment` or `keyAgreement` for `encrypt`), with a warning when no S/MIME or client-auth extended key usage is present. It uses `x509-cert`, already pinned in the workspace.
- **At load, `verify_manifest`** keeps to cheap structural checks: each certificate parses, the leaf's key matches, the limits hold; a bad entry makes the manifest invalid, like any schema error. It doesn't check expiry, so one expired certificate can't invalidate a whole manifest.

The extension presents the leaf (and the intermediates, for TLS) and skips a leaf that has expired; the provider ignores the field.

**Keys without a certificate.** If P4 shows a key item needs a certificate, the app makes a placeholder for each key the manifest gives none: subject "relay-pkcs11 placeholder: <label>", the key's public key, signed by a per-device placeholder key the app creates for this alone (no card operation, no approval). It only carries the public key to callers like `ssh-keychain.dylib`; anything that evaluates trust rejects it. A real certificate in the manifest replaces it.

Whole certificates, not hashes, because the extension needs the bytes and the manifest is already the trusted channel; a certificate change means re-signing the manifest either way.

### Algorithms

The keychain's algorithms map onto the spec's mechanisms. A `sign` key receives the full message so the approver can hash and show it; a key the manifest marks `accepts_digest` also takes digests (below).

| Role | Keychain algorithm | Request |
| --- | --- | --- |
| `sign` | `ecdsaSignatureMessageX962SHA256` / `SHA384`, `rsaSignatureMessagePKCS1v15SHA256` | `CKM_ECDSA_SHA256` / `SHA384`, `CKM_SHA256_RSA_PKCS`, full message |
| `auth` | `ecdsaSignatureDigestX962` (any digest length the curve allows), `ecdsaSignatureRFC4754`, `rsaSignatureDigestPKCS1v15SHA256` / `Raw` | `CKM_ECDSA`, `CKM_RSA_PKCS`, digest or DigestInfo |
| `encrypt` | `rsaEncryptionOAEPSHA256` | `CKM_RSA_PKCS_OAEP` (SHA-256, MGF1-SHA256) |
| `encrypt` | `ecdhKeyExchangeStandard` | `CKM_ECDH1_DERIVE` with `CKD_NULL` |

Anything else is refused by `supports`, so the caller sees the key as unable to do it. RSA PKCS#1 v1.5 decryption is not supported (see "Still open").

**Digests on `sign` keys (proposal, pending Brian's confirmation).** Callers choose the algorithm; a token can only accept or refuse each one, and there is no way to ask a caller to prefer message algorithms. A caller that holds the message and checks what the key supports may pick a message algorithm, but many (the TLS stack, probably Mail's S/MIME) hash first and offer only digest algorithms, and fail if those are refused. So:

- A new optional manifest field `keys[].accepts_digest` (boolean, `sign` keys only, default false). Without it, a `sign` key keeps the spec's rule: full message only.
- With it, the key also accepts the digest mechanisms (`CKM_ECDSA` and `CKM_RSA_PKCS` with a DigestInfo). The approval screen says "This app sent only a digest; the content can't be shown".
- The provider enforces the same field, so a PKCS#11 client can't use the keychain's allowance as a way around the rule.
- The extension's `supports` answers yes to message algorithms on every `sign` key, so a caller that can send the message does.

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
- **Trust manifest:** `keys[].certificates` and, if confirmed, `keys[].accepts_digest`; wire-format §9.2. The provider's role enforcement reads `accepts_digest` too.
- **Relay:** `POST /v1/audit/local`; wire-format §10.
- **Keys and messages / wire format:** none; the request and response envelopes are unchanged.
- **Threat model:** the rows above.
- **Failure handling:** the extension's rows above, each with a test.
- **Code structure:** the `relay-client` crate.
- **MVP scope and milestones:** move "CryptoTokenKit token extensions for system-wide use on macOS and iPadOS" from "Out, for later" into a new phase after milestone 7 (Brian, 2026-11-20).

## Tests

- `relay-core`: manifest certificate checks (parses, leaf key matches, limits, wrong role) and `accepts_digest` (only on `sign` keys; digest mechanisms refused without it), golden vectors.
- `relayctl`: `add-certificate` refuses a broken chain (wrong issuer, bad signature, expired, key mismatch, wrong key usage) and warns as described.
- `relay-client`: the shared store's record rules (atomic create, repeats while pending, after approval, after a decrypt, after a denial; expiry and cleanup), with two processes racing.
- `relay-approver`: a local request is checked exactly like a relayed one; every rejection reason; the response is accepted by `verify_response`.
- `relay-server`: `/v1/audit/local` accepts a valid pair, refuses a mismatched, unsigned, replayed or foreign-device pair, and keeps only hashes for decrypts.
- `relay-ffi`: the whole local route with the softcard and a temporary directory as the store; the relay route against a real relay; an unanswered local request expiring without reaching the relay.
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

## Decisions (Brian, 2026-11-20)

| Question | Decision |
| --- | --- |
| Where it goes | A new phase after milestone 7 |
| Falling back to the relay when a local request isn't answered | No, at least for now: it expires |
| Chain checks for certificates | Validate the whole chain when a certificate is added (`relayctl`), distinct from evaluating trust |
| Pairing the extension | Not skipped: the app compares the pending pairing's key with the key it created, automatically |
| Inverting the hand-off (the extension runs the card operation) | Not for now: the extension can't reach an NFC YubiKey, would need the PIN on iOS, and would need an approval gate other callers can't race. Kept as a later option for USB on the Mac (Still open) |

Still to decide:

1. **`accepts_digest`** as proposed under "Algorithms", or another way to let `sign` keys take digests?
2. **Placeholder certificates** if P4 shows a key item needs one: as proposed under "Certificates"?

## Still open

- **RSA PKCS#1 v1.5 decryption** for S/MIME. Not in the spec, for the padding-oracle reasons discussed on 2026-11-20. Check first whether Mail can decrypt with an elliptic-curve S/MIME certificate (ECDH, which this design supports).
- **System PIN prompt on iOS** (`TKTokenSmartCardPINAuthOperation`), so the PIN never enters our process: a post-MVP investigation already noted in `docs/progress.md`.
- **A local route inside the extension**, without the app hand-off, and the inverted variant where the extension runs the card operation and the app never sees a result: on the Mac, Face ID from inside the extension worked in Brian's own experiment, USB smart cards may be reachable from it, and the system PIN prompt may supply the PIN. It would remove the app switch for USB on the Mac. Each approval would have to be single-use and bound to its request, since the extension can't tell its callers apart. Later, once the hand-off works everywhere.
- **Falling back to the relay** when a local request isn't answered, or a "send to another approver" button: not for now.
- **Returning to the calling app on iOS** automatically: no public API exists. The private one is ruled out.
