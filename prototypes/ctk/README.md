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
| P1 hand-off in background | Pass, 67 s | | Pass, 13 s (in front) | Mac: app must post the notification |
| P2 caller limits | | | | |
| P3 repeat pattern | | | | |
| P4 bare key | Pass | | Pass | Keychain caller only; needs constraints |
| P5 locked | Pass (after first unlock) | | | |
| P6 network | Pass, 91 s | | | Public test page, short requests |
| P7 front and back | – | – | | |
| P8 biometric in extension | Pass | | | iOS asked once for Face ID permission, naming CTK Proto |
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
- **Clicking the notification fails on the Mac every time so far** (3 logged clicks), including with a freshly launched single build: `usernoted` takes the request over the extension's connection, then can't match its source id to a launchable app. CTKProto's "App posts the notification" option tests whether an app-posted notification opens it.
- **Notifications on the Mac: the app has to post them.** An app-posted notification opened CTKProto and logged the click (approved after 4.4 s, signature verifies), so P7 passes both ways. Extension-posted ones failed on every logged click, before and after it and with the stray builds unregistered. Cause unknown. So on the Mac the app must be running (or be launched some other way) to show a request.
- **One call at a time:** a second CTKCaller sign made while the first waited reached the extension only after the first finished, 7 s later. Seen once, same caller and key; whether other callers are blocked too is untested.
- **An approval can outlive its caller.** Rebuilding the app replaced the extension mid-wait: CTKCaller got `CryptoTokenKit -7` (token not found) after 56.7 s, but the record stayed, and CTKProto approved it 8.5 s later and ran the operation for nobody. The real design needs a liveness signal from the extension, or must expire a record once its waiter is gone.

### iPhone, 2026-11-23

- **Published:** with `com.apple.token` in CTKProto's iOS entitlements, its check finds `with-cert` (status 0) and `TKTokenWatcher` lists the token. Without it the check returned -34018, which proved nothing.
- **CTKCaller:** its search returned -26276 (`errSecInternal`) and no items. It asked for attributes and key references together; now it asks for them separately. The extension has logged nothing on the iPhone yet, unlike on the Mac. Cause open.
- **iOS asks the person first** (Brian, 2026-11-23): with the split search, iOS prompted to allow CTKCaller access to an item, and after Allow it found the keys. No such prompt was reported on the Mac. Still to record: the prompt's wording, whether it names the calling app, whether it is per key or per token, whether Allow lasts, and what Deny returns. Whether the earlier -26276 was this prompt failing to show is unknown.
- **Baseline:** `immediate`, `with-cert`, message algorithm: the extension signed (72 B).
- **P1, run A: passes.** `handoff`, `with-cert`: the extension posted the notification (`notification added: ok`), tapping it opened CTKProto (`notification opened`, 5.9 s after the call), approved after 11.2 s, answered to the caller after 11.6 s. CTKCaller was in the background for about 6 s and showed the result when Brian switched back. CTKProto was already running (same process as the setup), so a launch from nothing is untested. The Mac's click failure doesn't occur here.
- **P3:** one `sign` per action after two `supports` calls, as on the Mac.
- **Access prompt:** `tokenFor` to `createSession` took 5.5 s on first use, consistent with the prompt, and 3 ms on the next one 3 minutes later, so the permission seems to last at least that long.
- The shared log and store work with the `group.` container on iOS.
- **P1, run B: passes.** With CTKProto swiped away, tapping the notification launched it (new process), the tap was delivered (`notification opened` 6 ms after launch logging), approved after 10.9 s, answered after 11.1 s.
- **P1, run C: the extension waited 67.2 s** and returned the approved signature (`with-cert`; tap at 62.6 s). CTKCaller was in the background for most of the wait (Brian). CTKCaller then showed `sign ok … verifies=true` (Brian). **P1 passes on the iPhone.**
- **P2, run D:** unanswered, the extension timed out at its own 100.0 s; CTKCaller reported `CryptoTokenKit -4` after 111.8 s. The 11.8 s difference is unexplained (CTKCaller suspended in the background until reopened would do it). So the caller's own limit is above 100 s, not yet found.
- **Access prompt:** Brian didn't recognise it when asked later, so treat its wording and meaning as unknown.
- **P1, run C repeated (18:34Z): the log itself shows the background wait.** CTKProto opened 2.7 s after the call and approved at 61.6 s; the extension answered at 62.1 s. So CTKCaller was out of the foreground for about 59 s.
- **P5 (18:39Z):** one sign call; store write and notification succeeded, tap after 7.5 s, approved after 9.6 s, answered after 10.1 s; Brian reports it signed. The notification was on the lock screen before Brian unlocked, so **P5 passes on the iPhone**: the extension read its settings, wrote the record and notified while locked. Only "unlocked once since restart" is covered.
- **P6: passes** for short requests: 18 of 18 returned 200 over 91.2 s from inside the extension, then it signed. Whether CTKCaller was in the background is not recorded, and a single long-poll held open, and the relay's pinned CA, are not tested.
- **P8: passes.** From inside the extension the protected item was read (status 0 after 9.4 s) and the signature completed. iOS showed "Allow CTK Proto to use Face ID?", its one-time permission for the containing app; the item's `.biometryCurrentSet` protection means a Face ID match followed. A later run should show the match alone.
- **P4: passes for a keychain caller.** With constraints, `bare` is published and signs (72 B, `immediate`). No access prompt came for the new key.

### Mac, ssh through `ssh-keychain.dylib`, 2026-11-23 (no YubiKey attached, keys published)

- **PKCS#11 (`ssh-keygen -D`): no slots** for the P-256 keys, with and without `KEYCHAIN_CERTIFICATES`. Fits the man page (RSA only); an RSA identity is untested.
- **Secure Key route (`ssh-keygen -w … -K`): loads both keys, the bare one too**, as `sk-ecdsa-sha2-nistp256@openssh.com`. So `ssh` needs no certificate. The earlier -1 failure was the unpublished keys. `-K` asks for a PIN and accepted an empty one.
- **A server sees an `sk-ecdsa` key,** not the plain ECDSA key the PKCS#11 provider presents: a different `authorized_keys` entry.
- **The call reaches the extension** as a digest: `ecdsaSignatureDigestRFC4754`, 32 B, after one algorithm the prototype refused. So the key must accept digests, as an `auth` key does.
- **Signing works** (`immediate`, rerun at 13:01): `ssh-keygen -Y sign` with each key, `with-cert` and `bare`, and `ssh-keygen -Y verify` reports a good signature for both. An `ssh` login wasn't tried.
- **The same file gives the same digest every time**, for both keys and across runs: nothing in it is fresh, so the record name repeats too. An `ssh` login signs session data, which differs each time.
- **Unapproved calls.** The first two runs were in `handoff` and neither was approved: CTKProto and its extension were replaced during the first, and both requests were denied in the app. `ssh-keygen -Y sign` still wrote a signature file each time ("Write signature to …"), which failed verification. **A refusal doesn't surface as an error to ssh-keygen here**; an ssh server would reject the result. Worth confirming once one is approved.
- **Liveness again:** the first request outlived its extension and was listed until denied 31 s later.
- An unentitled command-line program lists the published keys (`SecItem`, naming the token group).

### Mac, Mail, 2026-11-23 (`immediate`)

- **Mail signed with `with-cert`** (Brian): one `supports` and one `sign` call, `ecdsaSignatureMessageX962SHA256`, 443 B in, 70 B out. No repeats, no digest algorithm asked. The self-signed certificate was offered.
- 443 B is too small to be the mail. It is presumably the S/MIME signed attributes, which hold a digest of the content; the input wasn't kept, so this is inference.
- Not checked then: the received signature, the wait limit and a denial (see below), and decryption.
- **Mail in `handoff`, app-posted notification:** the click opened CTKProto; approved after 57.0 s (`sign done` 57.4 s), and a second call approved after 98.3 s (98.8 s). Both answered. Mail shows the messages as signed, with the expected trust warning for a self-signed certificate (Brian). So **Mail waits at least 98.8 s**.
- **P3: Mail made a second sign call.** It reached the extension 63 ms after the first finished, same key, algorithm and size (443 B) but **different input**, so it isn't an identical retry and the record name (key, algorithm, input) doesn't match. In `immediate` mode there was one call. Brian sent **one** message. Cause unknown: it may have been made while the first was waiting (calls queue), by a draft save, Send pressed again, or Mail itself; the Mac's log kept nothing from Mail. Brian saw several requests and didn't know why.
- Not checked: a denial, and Mail on the iPhone.

### Mac, Mail: why it signs more than once, 2026-11-23 (`handoff`, one message per run)

| Run | Calls | Detail |
| --- | --- | --- |
| Quick, approved in 4.8 s | 1 | |
| Slow, approved after 77.7 s | 2 | second call 32 ms after the first finished, approved after 25.6 s |
| Denied | 3 | Mail: the message failed to send (Brian). Two more calls, 13 s after the denial and then exactly 30.000 s later, which Brian saw were for saving the draft |

- **A denial fails safe:** the message wasn't sent (Brian); nothing was sent unsigned.
- **Mail signs drafts when it autosaves them**, likely on a 30 s timer. That fits the second call in the slow runs (queued behind the first), but it was only seen directly after a denial. Each save signs new input.
- Not checked: whether composing a signed message for longer than 30 s, without sending, also asks; and whether turning signing off for drafts is possible.
- **Open:** Brian reports the sent email's signature as `3046…659e`. A DER signature starting `3046` is 72 bytes, and every Mail call logged here returned 70 or 71. Which message it came from isn't known.

