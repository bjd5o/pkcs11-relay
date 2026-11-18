# Signed setup links for the approver app: design

Status: **approved by Brian on 2026-11-17.** The "Proposed spec changes" section is applied to
`docs/spec.md` and `docs/wire-format.md`, and the decisions are recorded in `docs/decisions.md`.

## Goal

Today the app is set up by copying a `setup.json` from `relayctl app-config` onto the phone.
Instead, `relayctl app-link` asks for what it needs, then prints a URL and a QR code. Scanning
the code with the iPhone camera opens the app, which checks the link and finishes setup.

The link is signed by the manifest signer's own key, it expires, and it carries only public
pins. The person still confirms the signer's fingerprint on the phone. The app also shows the
identity that keys.openpgp.org has verified for that key, or explains why it could not show
one.

The relay checks the link again when the new device first registers. It also keeps checking the
manifest signer's key for revocation and expiry, and it stops serving clients if the key is
revoked or expired.

Two policy settings move from client and app configuration into the signed manifest:

- `require_hardware_attestation`, which replaces `[hardware_attestation] require`;
- a new `max_attestation_window_secs`. Each device chooses its own window at setup, up to that
  maximum.

## Manifest changes (wire-format §9.2, §5.1)

Two new top-level fields, both **required**:

| Field | Type | Rules |
| --- | --- | --- |
| `require_hardware_attestation` | bool | When true, every `attest` key must carry a valid `hardware_attestation` (§9.4). Replaces the `require` setting in the provider, relay and app configs. |
| `max_attestation_window_secs` | integer | 60 to 31 536 000 (one year). The longest attestation window clients accept. |

`relayctl manifest init` writes `true` and 7 days. `relayctl manifest set
--require-hardware-attestation <bool> --max-attestation-window <duration>` changes them.

### Attestation window check

This adds step 4a to `verify_attestation` (§5.1): reject when `not_after − not_before >
max_attestation_window_secs`, with a new error `AttestationWindowTooLong`. It belongs to the
existing Failure handling row "Attestation invalid, expired or not signed by a manifest attest
key", so the provider returns `CKR_DEVICE_ERROR` and the row itself doesn't change.

Where the check runs:

- **Provider:** on every response, as part of `verify_attestation`.
- **App and engine:**
  - It refuses to create an attestation longer than the maximum.
  - It treats an existing one that is too long as due for renewal right away. This happens when
    the manifest lowered the maximum, and the renewal comes at the next approval that has the
    YubiKey present.
- **Relay:** it rejects such registrations, and doesn't count such devices when filtering
  advertisements. The relay checks the signer and this length, but not whether the window has
  passed. The length is fixed when the attestation is signed, so renewing fixes it.

### `[hardware_attestation]` in configs

Only `roots_file` stays, still testing only. `require` is removed from the provider, the relay,
the test approver and the app setup. Configs that still contain it are rejected as unknown
fields, so the change can't go unnoticed.

Trade-off: whoever holds the PGP key can now turn the requirement off. They could already do
everything else, since serial pinning was declined. In exchange, the policy is set in one
signed place instead of on every client.

## The link

```
poh://setup?v=1&relay=https://10.0.0.170:8443&ca=<b64url>&signer=<FPR>&device=iphone&iat=1795000000&exp=1795000900&sig=<b64url>
```

| Param | Meaning | Rules |
| --- | --- | --- |
| `v` | format version | `1` |
| `relay` | relay base URL | `https://`, host and optional port only: no path, query, fragment or userinfo |
| `ca` | SHA-256 of the relay CA's SubjectPublicKeyInfo | base64url, 43 characters; omitted when the relay has a publicly trusted certificate |
| `signer` | the manifest signer's OpenPGP fingerprint | 40 uppercase hex (v4), or 64 (v6) |
| `device` | the device id | `check_id` rules; fixed, shown read-only in the app |
| `iat`, `exp` | issued at, expires | Unix seconds; `iat < exp ≤ iat + 7 days` |
| `sig` | OpenPGP detached signature | base64url of the binary signature packet; must be last |

**Fixed form.** The parameters appear in exactly the order above, each once. Values use only
`A–Z a–z 0–9 - . _ ~ : /`, and no percent-encoding is allowed anywhere. The app rejects any
other form. This means no URL normalisation by iOS or by the camera can change the signed bytes
without the link being rejected.

**Signed bytes.** The exact characters of the link before `&sig=`, as UTF-8, starting with
`poh://setup?v=1&`. Both the prefix and the content work as a context string. A setup
link signature can't be passed off as a manifest signature, because the manifest check parses
JSON. A manifest signature can't be passed off as a link signature either, because the signed
bytes must start with the prefix.

**Signature rules** are the manifest's (§9.1):

- binary-document type `0x00`;
- SHA-256 or stronger;
- made by the primary key or a valid signing subkey;
- no revocation check within the signature check itself. Revocation and expiry of the signer
  key are checked separately, by the app at setup and by the relay ("The relay and the signer
  key").

It uses the same `relay-core` code, extracted so both callers share it.

**Who signs.** `relayctl app-link` signs through `gpg --detach-sign`, so the OpenPGP card works
through gpg-agent as it does for the manifest, or with `--pgp-secret` for tests.

**Size.** With an Ed25519 signing key the signature is about 120 bytes, about 160 characters in
base64url, and the whole link about 350 characters. That's a QR code of version 11 to 12, about
65 modules or 33 terminal lines, and it scans easily. An RSA-4096 key makes the signature about
540 bytes and the link about 1 000 characters: version 20 or so, about 50 lines, which is
harder to scan from a screen. `relayctl` prints a warning and suggests `--svg`.

## App flow

All of this runs in Rust (`relay-ffi::setup_from_link`). Swift shows the results and makes the
person's choices.

1. **Parse** the link strictly (fixed form, above). Anything else fails with "not a valid
   setup link". Nothing is fetched yet.
2. **Time:** reject unless `iat − skew ≤ now ≤ exp + skew`. The messages are "this link expired
   at <time>; make a new one with relayctl app-link", or, if `iat` is in the future, "the phone's
   clock or the link's issue time is wrong".
3. **Relay CA:**
   - Fetch `GET /v1/relay-ca.pem` once, with certificate verification disabled, from a function
     that returns nothing except bytes that passed the next check.
   - Accept the certificate only if it is self-signed with CA set, and the SHA-256 of its SPKI
     equals `ca`.
   - From then on, use it as the only trust anchor, exactly like `relay_ca_pem` today.

   The unverified fetch learns nothing it trusts: the pin from the signed link decides. When
   `ca` is absent, WebPKI is used and nothing is fetched unverified.
4. **Signer key:** fetch `GET /v1/manifest-signer.asc` over the pinned TLS connection. Require
   its fingerprint to equal `signer`. Setup stops if this copy of the key is revoked, or if its
   primary key or every signing-capable subkey has expired. Manifest verification on clients
   still ignores revocation and expiry (§9.1); this check applies to setup only.
5. **Link signature:** verify `sig` over the signed bytes with that key. A failure here means
   the link was altered or not made by this key, and setup stops.
6. **Manifest:** fetch and verify it as today. This also learns `max_attestation_window_secs`
   and `require_hardware_attestation`, and checks that the manifest is signed by the same key.
7. **Identity lookup** (display only, see below), in parallel with steps 3–6.
8. **Confirm screen:**
   - relay;
   - signer fingerprint, grouped;
   - signer identity, or a warning;
   - link issue and expiry times;
   - device id, fixed by the link (see "One link, one device");
   - attestation window: a picker of durations up to the manifest maximum, defaulting to the
     maximum;
   - hardware attestation: required or not, as the manifest says (read-only).

   The person compares the fingerprint with `gpg --fingerprint` and taps "The fingerprint
   matches". Then enrollment starts.

The app stores the same `ApproverConfig` as today. The CA comes from step 3, the signer key from
step 4, the device id from the link and the window from the person's choice. Nothing about the link is kept
except its fingerprint and expiry, for display.

## Signer identity from keys.openpgp.org

- **Request:** `GET https://keys.openpgp.org/vks/v1/by-fingerprint/<FPR>` with WebPKI trust
  (ureq's built-in roots), a 10-second timeout and no redirects.
- **Response:** parsed with rPGP. The returned key's fingerprint must equal `signer`. The user
  IDs shown are those the server returned: keys.openpgp.org publishes only user IDs whose email
  address the owner confirmed.
- **What it means:** the lookup is display-only and never decides anything. Trust still comes
  from the fingerprint the person confirms. A key that matches, with an identity, shows it is
  published under that address, nothing more.

| Outcome | UI |
| --- | --- |
| Found, fingerprint matches, one or more user IDs | Shows each user ID with "verified by keys.openpgp.org" |
| Found, but no user IDs (published without a confirmed address) | Warning: "keys.openpgp.org has this key but no confirmed email address for it, so the identity could not be verified." |
| 404 | Warning: "This key is not on keys.openpgp.org, so the identity could not be verified. Its owner can upload it there and confirm an email address." |
| Network error, timeout, TLS failure or 5xx | Warning: "Could not reach keys.openpgp.org (<reason>), so the identity could not be verified." |
| Key returned with a different fingerprint, or unparseable | Error, in red: "keys.openpgp.org returned a different key. Do not continue unless you are sure of the fingerprint." |
| Key is revoked or expired on the keyserver | **Blocks setup**: "keys.openpgp.org says this key was revoked on <date>" (with the reason, if given), or "This key expired on <date>". Make a new key and manifest, or renew it, before setting up |

Revocation and expiry block setup whichever copy shows them: the keyserver's or the relay's
(step 4). Only the identity display stays advisory.

## One link, one device

The link holds no secret, and replaying it gains nothing on its own. A device set up from a
copied link still needs the YubiKey, its PIN and a touch on the attest key before it can get an
attestation. Without one the relay refuses to register it, so it can't receive requests or have
any response accepted.

To also stop two devices from using one link, the link fixes the device id, and the relay's
existing rule does the rest: a device id stays bound to the first device key that registers it
(wire-format §10), until `relay-server admin devices revoke`.

- `device` is required in the link, and the app shows it read-only.
- A second phone using the same link fails at registration with `DeviceIdTaken`. The app then
  says: "This setup link was already used by another device. Make a new one with `relayctl
  app-link`."
- Reinstalling the app on the same phone creates a new Secure Enclave key, so it needs either a
  new link with a new device id, or the old device revoked first. `relayctl app-link` checks the
  relay's device list and refuses a device id that is already registered, unless given
  `--replace`. That flag revokes the old device through `relay-server admin` after a typed
  confirmation.
- `exp` limits how long an unused link stays usable.

This is enforced by the relay, so it is housekeeping like the relay's other checks: a
compromised relay could ignore it. What protects clients doesn't change. Each device needs its
own attestation from a YubiKey attest key, and clients verify that.

The relay also records every link it accepts, so a link can't be used again even after its
device is revoked ("At a device's first registration"). The link's hash serves as the one-time
token, so the link needs no separate nonce.

## `relayctl app-link`

It prompts for anything not given as a flag, and `--no-input` makes every value come from a
flag.

| Prompt | Flag | Notes |
| --- | --- | --- |
| Relay URL | `--relay-url` | Suggests this machine's LAN addresses |
| Relay CA file | `--relay-ca` | Computes `ca`. It connects to the relay and checks that its live certificate chains to this CA and that `/v1/relay-ca.pem` returns it. Empty means a publicly trusted relay |
| Signer | `--gpg-key` or `--pgp-secret` | Prints the fingerprint. It checks that the relay's `/v1/manifest-signer.asc` and manifest are made by the same key |
| Device id | `--device-id` | `check_id`; refused if already registered at the relay unless `--replace` |
| Link lifetime | `--valid-for` | Default 15 minutes, at most 7 days |

Output: the URL, then the QR code drawn with Unicode half-blocks, then the fingerprint and
expiry. `--svg <file>` also writes an image. Before signing, `relayctl` refuses a signer key that
is revoked or expired, so you find out before the phone does.

The link contains no secret, but it is a working setup invitation until `exp`, so the short
default lifetime is deliberate.

**New dependency:** `qrcode =0.14.1` (MIT OR Apache-2.0), in relayctl only, with
`default-features = false` and the `svg` feature. It is the more widely used of the two
candidates, and it has the Unicode half-block renderer for terminals and an SVG renderer built
in. With default features off it pulls in no image libraries. `qrcodegen` (Nayuki, 1.8.0) is
just as stable, but it only encodes, so we would have to write and test our own terminal
renderer.

## The relay and the signer key

### At a device's first registration

The app sends the setup link it was set up from, in a new `setup_link` field of `POST
/v1/devices`. The relay requires the field when the device id is new. Re-registrations from a
device id it currently holds, with the same device key, don't need it: renewals, push token
changes and key list updates.

**A revoked device id counts as new.** `relay-server admin devices revoke` deletes the device's
row. Its next registration therefore goes through every check below and needs a fresh
`setup_link`, even when it reuses the old device key. A test pins this down so a later change to
revocation, such as keeping a tombstone row, can't quietly skip the check.

**Links are single-use.** The relay keeps the SHA-256 of every setup link it has accepted, in a
`used_setup_links` table. The hash covers only the link's signed bytes, everything before
`&sig=`, never the signature. Some signature schemes let a second valid signature over the same
bytes be made without the private key; hashing the whole link would let such a copy pass as a new
link. The signed content is what is single-use. The audit log and the device record store the
same hash. Revoking a device doesn't remove the entry, and a link seen before is
rejected with `SetupLinkUsed`. Without this, an unexpired link could re-register a device id
right after it was revoked. Entries can be pruned once their `exp` plus the skew has passed,
because by then the time check rejects the link anyway.

The relay then checks, in this order, and rejects with 400 and the error kind shown:

1. **Form:** the link parses in its fixed form (`SetupLinkInvalid`).
2. **Signer:** the link's `signer` fingerprint equals the fingerprint of the relay's own
   `manifest_signer` key, the key it trusts for the manifest (`SetupLinkWrongSigner`).
3. **Signature:** `sig` verifies over the signed bytes with that key, under the §9.1 rules
   (`SetupLinkSignatureInvalid`).
4. **Key status:** the signer key is not revoked or expired, by the relay's current signer
   status, below (`ManifestSignerUnusable`).
5. **Time:** `iat − skew ≤ now ≤ exp + skew` by the relay's clock (`SetupLinkExpired`). Setup,
   enrollment and the YubiKey taps must fit inside the link's lifetime. Fifteen minutes is
   plenty, and an expired link just means making a new one.
6. **Device:** the link's `device` equals the registration's `device_id`
   (`SetupLinkWrongDevice`). With the first-key binding, this makes one link register exactly
   one device.
6a. **Unused:** the link's hash is not in `used_setup_links` (`SetupLinkUsed`). It is recorded
    in the same transaction that stores the device.
7. **Attestation:** then the existing checks: hardware attestation, signer and window length.

The relay stores the same hash of the signed bytes with the device and in the audit log. It doesn't check
the link's `relay` value, because the same relay can be reached under several names, such as a
LAN IP and a tailnet name, and the TLS pin already ties the app to this relay.

"The key presented by the approver" is the key the link names and is signed by. The relay never
takes a key from the app: it checks the link against its own configured copy, which must have
the same fingerprint.

### Signer status

`relay-core` gets `signer_status(copies, now) -> Usable | Revoked { at, reason } | Expired { at }`.
It is built on rPGP's parsed packets and handles two things.

**Revocation:**
- a key-revocation signature on the primary key that verifies under the primary key; or
- every signing-capable subkey revoked, with the primary key not signing-capable.

A revocation only counts if its signature verifies, so neither a keyserver nor a relay can fake
one.

**Expiry:**
- the primary key's expiry from its newest valid self-signature is in the past; or
- the primary key can't sign, and every signing-capable subkey's binding has expired.

The expiry comes from the newest valid self-signature **across all copies seen**. A keyserver
that served an older copy with an earlier expiry, with the newer self-signature stripped, can't
make a renewed key look expired. Revocation from any copy counts.

### When the relay checks

- **Its own file:** it re-reads `manifest_signer` whenever it re-reads the manifest, and at
  least every minute, so expiry takes effect on time without a restart.
- **keys.openpgp.org:** `GET /vks/v1/by-fingerprint/<FPR>` every `interval_secs`, default 15
  minutes, and once at startup. The result is merged with the file as above.
- **New config section:**

  ```toml
  [signer_check]
  keyserver = "https://keys.openpgp.org"  # "" turns off the online check; the file is still checked
  interval_secs = 900
  ```

- **Keyserver unreachable, or the key not published there:** the relay keeps its last known
  status, logs a warning and counts the failure in a metric. It fails open: a keyserver
  outage, or a relay without outside access, must not stop an OpenBao unseal. A revocation is
  still caught at the next successful check.
- **Persistence:**
  - A revocation the relay has seen is written to its database. It stays in force across
    restarts until `manifest_signer` is replaced by a key with a different fingerprint, because
    a revocation is permanent.
  - Expiry is recomputed on every check, so renewing the key (a new self-signature in the file
    or on the keyserver) makes it usable again.

### When the signer key is unusable

The relay stops service to clients and logs the reason at error level, once per change:

| Call | Behaviour |
| --- | --- |
| `GET /v1/keys` | Returns an empty list |
| `POST /v1/requests` | 503 `ManifestSignerUnusable`, with the reason |
| Pending requests | Cancelled. `GET /v1/requests/{id}/result` returns 503 `ManifestSignerUnusable`, and late device responses are refused |
| `POST /v1/clients/pending`, `/approval` | 503 `ManifestSignerUnusable` |
| `POST /v1/devices` | 503 `ManifestSignerUnusable` (new and existing devices) |
| `GET /v1/devices/{id}/pending` | Returns nothing |
| `GET /v1/manifest`, `.asc`, `/v1/manifest-signer.asc`, `/v1/relay-ca.pem` | Still served, so an operator, the app or `relayctl` can see what is wrong |
| `/healthz` | Still `ok` (the process is healthy); `/metrics` exposes `relay_signer_usable 0` |

In the provider, an empty key list gives zero slots, and a 503 on a request gives
`CKR_DEVICE_ERROR`.

**What this adds to the threat model:** clients still don't check revocation themselves,
because headless hosts can't be relied on to reach a keyserver. Now a revocation published to
keys.openpgp.org reaches every client through the relay within one check interval (15 minutes
by default). If your PGP
key is stolen and you revoke it, an honest relay stops serving the thief's manifest. The thief
can't point your clients at another relay without changing their configuration. As with the
relay's other checks, a compromised relay could skip this. It only adds a guarantee; it never
takes one away.

## Relay changes

- `GET /v1/relay-ca.pem`: serves a new config file `tls_ca`, the CA that issued `tls_cert`.
  It is public and unauthenticated, like the manifest.
- `GET /v1/manifest-signer.asc`: serves the existing `manifest_signer` file.
- The attestation-length check in registration and filtering (above).
- The setup-link check at first registration, the signer status, `[signer_check]`, and refusing
  service while the signer key is unusable (above).

## What goes away

- `relayctl app-config` and the app's file import. The simulator test switches to the link: it
  runs `relayctl app-link --no-input --pgp-secret …` and `xcrun simctl openurl`. The test-only
  `attestation_roots_pem` and a keyserver override stay test-only, through the `RELAY_TEST_CARD`
  build's environment injection.
- `attestation_window_secs` and `require_hardware_attestation` in `ApproverConfig` as
  setup-file inputs. The window becomes the person's choice at setup, stored in the app's saved
  state.

## Tests

- **relay-core:**
  - Manifest field parsing; the window check with its exact error and failure row.
  - Link parsing: every fixed-form rule, each one failing alone.
  - Link signature: valid; wrong key; altered parameter; altered `sig`; a manifest signature
    reused as a link signature; and the reverse.
  - Time window boundaries with skew.
  - Golden vectors for one valid link and its failures.
- **relay-ffi:** `setup_from_link` against a local relay:
  - a CA pin mismatch;
  - a CA certificate that is not self-signed;
  - a signer fingerprint mismatch;
  - a manifest from another signer;
  - a window chosen above the maximum.

  It runs against a local stub of keys.openpgp.org for every row of the identity table. The
  stub's URL is a test-only setting.
- **relay-core:** `signer_status`:
  - revoked primary;
  - every signing subkey revoked;
  - expired primary;
  - expiry extended by a newer self-signature;
  - a stripped copy merged with a newer one;
  - a forged revocation that doesn't verify.

  Fixtures come from throwaway rPGP keys and from gpg, as for the manifest vectors.
- **relay-server:**
  - The two new endpoints.
  - Registration: rejected for a window that is too long; a second device key for the same
    device id rejected; each setup-link rejection from the list above, one at a time;
    re-registration without a link accepted.
  - After `admin devices revoke`: re-registration without a link rejected, even with the old
    device key; the old link rejected as `SetupLinkUsed`; a fresh link accepted.
  - The signer check against a local keyserver stub:
    - revoked, then every call in the table refuses;
    - expired, then renewed and usable again;
    - unreachable, keeping the last status;
    - a revocation persisted across a restart, and cleared by a new signer key.
- **Integration:** the m3 gate gets two more checks. After the relay sees its signer revoked,
  `pkcs11-tool -L` lists zero slots and a decrypt returns `CKR_DEVICE_ERROR`. This covers the
  new Failure handling row.
- **Provider and integration:** a device with a too-long attestation, whose responses get
  `CKR_DEVICE_ERROR`.
- **Simulator end-to-end:** setup by link, then the existing pairing and decrypt.

## Proposed spec changes

These are draft text, not yet applied.

- **Trust manifest, fields table:** rows for `require_hardware_attestation` and
  `max_attestation_window_secs`.
- **Enrollment, "Enrolling an approver":** replace "You set the device's attestation window at
  enrollment" with:

  > You choose the device's attestation window at enrollment, up to the manifest's `max_attestation_window_secs`. The app is set up from a signed link that `relayctl app-link` prints as a URL and QR code; it pins the relay's CA and the manifest signer, expires, and is signed by the manifest signer.

- **Provider, response check 2:** append "and the window is no longer than the manifest's
  `max_attestation_window_secs`".
- **Relay API table:** add `GET /v1/relay-ca.pem` and `GET /v1/manifest-signer.asc`. For
  `POST /v1/devices`, add "a setup link signed by the manifest signer, for a new device id".
- **Relay, responsibilities:** add
  > **Watch the manifest signer.** Check the signer key for revocation and expiry, from its own copy and from keys.openpgp.org; while it is revoked or expired, advertise no keys and refuse every client and device call.
- **Relay, configuration:** add `[signer_check]` and `tls_ca`.
- **Trust manifest, "Signer" paragraph:** replace "Clients do not check PGP revocation, because headless hosts cannot be relied on to reach keyservers." with
  > Clients do not check PGP revocation, because headless hosts cannot be relied on to reach keyservers. The relay does: it watches the signer key at keys.openpgp.org and stops serving clients while the key is revoked or expired, and the app refuses setup with such a key.
- **Failure handling:** a new row
  > | Manifest signer revoked or expired (seen by the relay) | The relay advertises no keys and refuses requests | Zero slots; `CKR_DEVICE_ERROR` for a request in flight |
- **Approver application:** setup by link. The identity lookup at keys.openpgp.org is
  display-only.
- **Threat model, "PGP manifest key" row:** "also decides whether attest keys need hardware
  attestation, and the longest attestation window".
- **MVP scope:** the pinned relay CA, by SPKI hash in a signed link, moves from "Out, for
  later" into scope for app setup only. The provider keeps its CA file.

## Work estimate

About 1 900 lines, in roughly this commit order:

1. Manifest fields and the window check (relay-core, all callers, configs, fixtures, vectors).
2. Link format and signature (relay-core) and the shared OpenPGP signature rules.
3. Relay endpoints and the length check.
3a. `relay-core::signer_status`; the relay's signer check, `[signer_check]`, persistence and
    refusing service.
3b. The setup-link check at the relay's first registration.
4. `relayctl app-link` (with the `qrcode` dependency).
5. `relay-ffi::setup_from_link` and the keyserver lookup.
6. App: URL scheme, `onOpenURL`, confirm screen, window picker. Remove the file import.
7. Simulator test by link; docs.

## Decisions taken (2026-11-17)

| Question | Decision |
| --- | --- |
| Privacy note about keys.openpgp.org on the confirm screen | Not shown |
| Revoked or expired signer key | Blocks setup, whether the keyserver's copy or the relay's shows it |
| `max_attestation_window_secs` default | 7 days |
| QR library | `qrcode =0.14.1`, without default features, `svg` feature |
| Link lifetime | Default 15 minutes, at most 7 days |
| URL scheme | `poh://` |
| One link, one device | The link fixes the device id; the relay's first-key binding enforces it |
| Relay checks the setup link | At a device's first registration: signature by its own manifest signer, key not revoked or expired, time, device id |
| Relay watches the signer key | Periodically, from its file and keys.openpgp.org. While the key is revoked or expired, it advertises no keys and refuses client requests |
| Revoked device ids | Treated as new: re-registration needs a fresh setup link |
| Single-use links | The relay records the SHA-256 of each accepted link's signed bytes (never the signature) and rejects reuse; the device record and audit log store the same hash |
| Keyserver unreachable or key not published | Fail open: keep the last known status and log a warning |
| Signer check interval | 15 minutes |
| Pending requests when the signer key becomes unusable | Cancelled |

## Open questions for Brian

None left. Approval of this design applies the spec changes.
