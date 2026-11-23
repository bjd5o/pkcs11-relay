# CryptoTokenKit prototype

Answers the open questions in `docs/cryptotokenkit.md` ("Prototype first") before anything real is built. Throwaway code: software keys stand in for the YubiKey, and the shared store holds plain results (the real design holds only signed requests and sealed responses). Not built by CI.

## Targets

- **CTKProto** (iOS, macOS): sets up two software P-256 keys in a keychain group shared with the extension and registers the token. `with-cert` has a self-signed certificate from `make-test-identity.sh`; `bare` has none. It answers handed-off requests (Approve or Deny stands in for the approval screen and the card), shows the call log, and on iOS 26 has the optional NFC smart-card check.
- **CTKProtoToken** (the persistent-token extension): logs every `supports`, sign and key-exchange call with the algorithm and an input hash, then answers in the mode the app set:
  - `handoff`: creates the request's record (exclusive create, keyed on key + algorithm + input), posts a notification, and waits up to "Wait" seconds for the app's answer;
  - `immediate`: signs in the extension, after "Immediate delay" seconds;
  - `network`: makes an HTTPS request to the URL every 5 s for "Wait" seconds, then signs in the extension;
  - `biometric`: reads a Face ID / Touch ID protected item from inside the extension, then signs.
- **CTKCaller** (iOS, macOS): a stand-in third-party app. Finds the token's keys and identities through the keychain, signs (message, digest or RFC 4754 digest) or does a key exchange, now or after a delay (for backgrounding and locking), and checks the result.

## Setup

```sh
cd prototypes/ctk
./make-test-identity.sh you@example.com   # optional address; Mail offers the identity for it
xcodegen && open CTKProto.xcodeproj
```

Signing uses `apps/apple/Config/Local.xcconfig` (team and bundle-id prefix). Xcode's automatic signing registers the app group and the two keychain-sharing app ids the first time. Install **CTKProto** and **CTKCaller** on each device, open CTKProto, allow notifications, and tap **Set up keys and token**. The status should say `token configured: true` and both keys `ok`. All results go in the table at the end, with the log lines that show them (the log is in CTKProto; copy it out with text selection).

## Checks

### P1: the hand-off while the caller is in the background (iPhone, iPad)
Mode `handoff`, Wait 100 s. In CTKCaller: Find token keys, `with-cert`, sign message, **Run now**. The notification appears; wait about 60 s before tapping it, then Approve in CTKProto and switch back to CTKCaller.
- Pass: CTKCaller shows `sign ok after ~60 s, verifies=true`.
- Record: the longest wait that still works (try 60, 90 and 100 s), and whether CTKCaller had to be in front when the answer arrived.

### P2: how long real callers wait
Mode `immediate`, "Immediate delay" stepped up (10, 30, 60, 90, 120 s) until the caller gives up; note its error.
- CTKCaller (each platform).
- Mac: `ssh-keygen -D /usr/lib/ssh-keychain.dylib` lists the keys (no wait involved); then with an agent, `ssh-add -s /usr/lib/ssh-keychain.dylib` and `ssh-keygen -Y sign -f <listed public key file> -n file <somefile>`, which signs through the agent.
- Mail (iPhone, Mac): S/MIME signing needs the `with-cert` identity selected for the address given to `make-test-identity.sh`. Send a signed message to yourself.
- Safari client auth: only if a test server with client-certificate auth is at hand; otherwise skip.

### P3: why calls repeat
Any run of P1 or P2. Count the `sign` lines per caller action in the log, and note whether repeats carry the same `sha256`, a different algorithm, or follow an error. The `supports` lines show which algorithms each caller asks about, in which order.

### P4: a key without a certificate
- `bare` appears in CTKCaller's key list and signs (mode `immediate`).
- Mac: `ssh-keygen -D /usr/lib/ssh-keychain.dylib` lists it.
- Pass: both. The SDK header already says a key item may be made with no certificate ("all properties … must be initialized manually"); this checks that callers find it.

### P5: a locked device
Mode `handoff`. In CTKCaller, **Run after delay** (20 s), then lock the device (iPhone, iPad) or the screen (Mac).
- Pass: the notification shows on the lock screen; unlocking and opening it reaches the approval in CTKProto; CTKCaller later shows `sign ok`.
- Record: if it fails, the log line where (store write, key access, notification). The files use "until first unlock" protection and the keys "after first unlock".

### P6: the network from inside the extension
Mode `network`, Wait 90 s, the default URL (or `https://<mac>:8443/healthz` if the relay's CA is trusted on the device). Run from CTKCaller.
- Pass: `network #n: 200` lines every ~5 s for the whole wait, then `sign ok`.

### P7: the Mac app in front, then back
Mac, mode `handoff`, "Hide after answering" on. Sign from CTKCaller; click the notification.
- Pass: CTKProto comes to the front; after Approve it hides and CTKCaller is in front again.

### P8: Face ID / Touch ID inside the extension
Mode `biometric`. Sign from CTKCaller, on the Mac and on the iPhone.
- Pass: the system biometric prompt appears over the caller and the signature completes. On iOS the extension may not be allowed to prompt; record what happens.

### P9 (optional, Brian runs it; touches the YubiKey): iOS 26 NFC smart cards
iOS 26 added `TKSmartCardSlotManager.createNFCSlot(message:)` and `TKSmartCardTokenRegistrationManager`: a registered card stays in the keychain, and the system opens an NFC slot itself when an operation needs it. If that works with the system's PIV token, the system could drive NFC and the PIN prompt on iPhone, which reopens the inverted hand-off and the system PIN prompt (`docs/cryptotokenkit.md`, "Still open").
1. CTKProto, section "iOS 26 NFC smart card": **Create NFC slot**, tap the YubiKey. Record the log line and the token ids that appear.
2. **Register** the YubiKey's token id (not `…ctk-proto…`).
3. In CTKCaller, **Find token keys**: record which of the card's keys appear (the system PIV token lists slots that hold certificates).
4. Only if a key in slots 85–89 is listed: sign with it from CTKCaller and record whether the system asks for the card over NFC and for the PIN itself. Any operation that needs the PIN is Brian's to run; one PIN attempt, no retries.

## Results

| Check | iPhone | iPad | Mac | Notes |
| --- | --- | --- | --- | --- |
| P1 hand-off in background | | | | |
| P2 caller limits | | | | |
| P3 repeat pattern | | | | |
| P4 bare key | | | | |
| P5 locked | | | | |
| P6 network | | | | |
| P7 front and back | – | – | | |
| P8 biometric in extension | | | | |
| P9 iOS 26 NFC | | – | – | |

### Mac, 2026-11-23 (macOS 27.0.1, no YubiKey attached)

- The token is registered and visible: `TKTokenWatcher` lists `<class id>:ctk-proto`, and `sc_auth identities` lists the `with-cert` identity.
- **The keys were never published, so nothing below tested them.** At setup `secd` rejected the token's items: `UpdateTokenItems … -25303 "attribute toid not found in class keys"`. The app logged success anyway, because writing the configuration reports no error. One bad item rejects the whole set. Suspects, untested: the bare key, or keys without operation `constraints`. CTKProto now selects the items and constraints, and logs `published keys:` two seconds after setup.
- **ssh: no result.** `ssh-keygen -D` ("returned no slots") and the Secure Key route (failure -1) ran with no published keys. `ssh-keychain(8)` does say it serves identities only, RSA through PKCS#11 and P-256 through the Secure Key module, so the limits below still need testing. (`sc_auth list-ctk-identities` covers Apple's own ctkcard, not this token.)
- **CTKCaller found nothing,** for the same reason. `SecItem.h`: every application has access to `kSecAttrAccessGroupToken`; no entitlement is needed, but the query must name the group. `com.apple.token` in `keychain-access-groups` fails Mac provisioning.
- Don't read `pluginkit`'s `-` mark as "turned off": `ctkd` was running Apple's `pivtoken` while it showed `-`. Unplug any YubiKey before listing tokens.
- **P4, bare key: works for a keychain caller.** With operation `constraints` set, `bare` is published and CTKCaller finds it and reaches the extension with it. Without constraints `secd` rejects it (the -25303 above); certificate-backed keys publish either way. A bare key isn't an identity, so callers that look for identities don't see it.
- **P2, plain caller:** CTKCaller's `SecKeyCreateSignature` waited 100.3 s, then got `CryptoTokenKit -4` (the extension's timeout). The extension stayed alive throughout. No signature completed yet.
- **App Group on macOS needs the team-id prefix.** `containermanagerd` rejected the extension's access to `group.…`, so it used default settings and couldn't write the request. The store misread that as "record exists" and posted no notification. Both fixed; not yet rerun.

### Mac, 2026-11-23, after the fixes (no YubiKey attached; `both` with constraints)

- **Published:** both keys and one identity (`with-cert`), in all four query variants.
- **Signing works**, both keys, message algorithm, signatures verify: `immediate` in under 0.1 s; `handoff` approved in CTKProto after 8.5 s (`with-cert`) and 12.3 s (`bare`), returned to the caller within 0.3 s of the approval.
- **P1 on the Mac:** passes for waits of about 12 s approved, and 100 s unapproved (timeout). iPhone and iPad untested.
- **P3:** no repeats with CTKCaller: one `sign` call per action, after two `supports` calls for the same algorithm. Other callers untested.
- **Notifications:** the extension can post (`notification added: ok`). Clicking at least one failed: `usernoted` logged "Failed to find appropriate application to launch for <bundle id>", and the app never logged the click. Extra builds of the app were on disk, which may be the cause; unproven.
- **Not run:** digests, RFC 4754 and key exchange; P2 and P3 with ssh or Mail; P5, P6, P8.
- **P7, second half: passes** (Brian, 2026-11-23): after Approve, CTKProto hid and CTKCaller was in front again. The first half, coming to the front from the notification, depends on the click problem above.
