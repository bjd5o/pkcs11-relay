# Client grants, and the Clients and Approvers screens (design draft)

Status: **approved by Brian on 2026-11-18** (see Decisions); **built 2026-11-19**, hardware gate still to run (`docs/progress.md`). Post-MVP. It changes the spec
(pairing, the manifest, response check 1, the wire format and the Failure handling table). Those
spec edits are shown to Brian before they are made, and come before any code.

## Problem

Found in the milestone 5 Part B gate (`docs/progress.md`, "Post-MVP follow-ups"):

1. **A new approver can't answer existing clients.** Each device answers only clients it
   approved itself, because the relay isn't trusted to say which clients exist. The iPad rejected
   `linux-client` as "unpaired client" until the client was revoked and paired again with the
   iPad approving.
2. **A client's keys can't change.** The approved key list is fixed at pairing. Adding `hw-sign`
   meant revoking the client and pairing again. Even if the relay allowed a change, the other
   devices would keep their own older lists.
3. **Nobody can see the whole setup.** The app has no list of paired clients or of the other
   approvers.
4. **Rejections are opaque.** The inbox shows "Deny 1 request(s) that failed their checks"
   without saying which checks failed.

## Idea

When a person approves a pairing, the approver's **`attest` key** (on the YubiKey) signs a
**client grant**: the client's identity key and the manifest keys it may use. Devices trust
grants the way they trust attestations, through the manifest's `attest` keys. The relay stores
and serves grants but can't create or alter them.

- **Pairing:** one card session per client, at pairing. A new device needs no re-pairing and
  no extra card session for existing clients: it fetches and verifies their grants, and the person
  accepts each client on that device with its first approval there.
- **Changing keys:** a new grant with a higher sequence number, signed during one approval.
- **Revoking:** a revocation signed by an `attest` key.

This is option B from the 2026-11-18 discussion, with the attest key signing instead of the
device key, so vouching for a client takes the same as enrolling a device: the YubiKey, its PIN,
and a touch where the attest key's policy requires one.

## Grant

CBOR map, signed per wire-format §1.3, with context string `relay-pkcs11/client-grant/v1` and
signature field `sig`, by an `attest` key:

| Field | Type | Notes |
| --- | --- | --- |
| `v` | uint | 1 |
| `client_id` | text | As paired |
| `client_key` | bytes | The client identity key's SPKI |
| `keys` | array of text | Fingerprints of manifest keys, 1–64, sorted |
| `seq` | uint | Starts at 1 per client key; each change or renewal adds 1 |
| `window_secs` | uint | This client's grant window, chosen at pairing; renewals keep it |
| `issued_at` | uint | Unix seconds |
| `not_after` | uint | Expiry (see "Replay and expiry") |
| `approved_by` | text | Device id of the approver, for display only |
| `attest_key_fingerprint` | text | The signing `attest` key |
| `sig` | bytes | 64 bytes, §1.4 |

`verify_client_grant(grant, manifest, now, skew)` in `relay-core`:

1. Decode canonically, find `attest_key_fingerprint` in the manifest with role `attest`, and
   verify `sig` with that key.
2. Check that `not_after − issued_at = window_secs` and that `window_secs` is at most the
   manifest's new `max_client_grant_window_secs`. Then check that `now` is inside
   `issued_at − skew ..= not_after + skew`. A grant that fails only this time check is **lapsed**
   (see "Replay and expiry"), not invalid.
3. Check that every fingerprint in `keys` is a manifest key with a non-`attest` role.

`verify_client_grant_signer(grant, manifest)` runs steps 1 and 3 without the time, for the
relay. This mirrors `verify_attestation_signer`.

## Revocation

CBOR map with context string `relay-pkcs11/client-revocation/v1`, signed by an `attest` key:
`v`, `client_key`, `seq` (the highest grant sequence it cancels), `issued_at`,
`attest_key_fingerprint`, `sig`. A device that has seen it rejects every grant for that client
key with `seq` at or below it, for good. The relay deletes the client and keeps serving the
revocation until the last grant it cancels has expired.

**Delivery.** The relay sends every live revocation (one whose cancelled grants haven't all
expired) on every `/pending` response and in `GET /v1/clients`. There is no acknowledgement:
revocations are few and small, and the device ignores the ones it already holds. An
acknowledgement scheme was considered and dropped (2026-11-18): it can't stop a compromised
relay from withholding a revocation, which is the case that matters.

**What bounds a compromised relay.** A relay can withhold any revocation it carries. What limits
the damage:
1. **Grant expiry.** A withheld revocation matters only until the revoked client's grant
   expires. Renewing it then needs a person to approve after the lapse notice. Sensitive clients
   can be given short windows, since each client's window is set at pairing.
2. **The person approving.** Every request still needs a biometric, the PIN and the card. A
   revoked client whose revocation was withheld shows up as a request that can be denied, not as
   silent access.
3. **Local effect.** Revoking on a device's Clients screen takes effect on that device at once,
   whatever the relay does.

**Option for emergencies: revocations in the manifest.** The manifest is the one channel the
relay can't silently censor: it is signed with the operator's PGP key, and clients and devices
reject expired or rolled-back copies. An optional `revoked_clients` list of client-key
fingerprints would reach every device. A relay that withholds the new manifest leaves devices on
the old one until it expires, and then they stop working, which fails safe. The cost is
re-signing the manifest. Included in this design (Brian, 2026-11-18); see "Manifest".

`relay-server admin clients revoke` stays, as an emergency stop at the relay only. The app's
Revoke action is the full revocation.

## Replay and expiry

The relay can't forge grants, but it can **withhold** newer ones: serve a device an older,
broader grant, or hide a revocation. Sequence numbers stop a device from going backwards once it
has seen something newer. They can't help a device that never saw the newer record.

Grants therefore **expire**, like attestations, and are **renewed during approvals**: when a
request from a client arrives and its grant is past 75% of its window, the approving device
signs a new grant (same keys, same `window_secs`, `seq + 1`) in the same card session, as
attestation renewal does. A withheld revocation or change then lasts at most one grant window
for a client in use.

**Lapsed clients (Brian, 2026-11-18).** A client unused for a whole window lapses. Its next
request is still shown, if the device's last known grant for it otherwise verifies (signature,
attest key still in the manifest, keys still in the manifest, no known revocation). The approval
screen then carries a notice: "This client's access lapsed on <date>. Approving renews it for
<window>, with keys: …". Approving signs the request and the renewed grant in one card session.
Denying leaves the client lapsed. A request for a key outside the last grant is still rejected.

This puts the person in the loop at exactly the point where the relay could have withheld a
change: the notice shows the keys and the lapse date, and nothing renews without an approval.

## Flows

### Pairing (changed)

Approve pairing → choose keys and the grant window (at most `max_client_grant_window_secs`) →
biometric → PIN → one card session: `SELECT`, `VERIFY`, the attest key signs the grant → session
ends. `POST /v1/clients/{id}/approval` carries the grant instead of
`{"fingerprint", "keys"}`. The relay checks it with `verify_client_grant_signer` and that
`client_key` is the pending client's key, then stores it. The approving device stores it too.

Pairing now needs the YubiKey present, where today it needs only a biometric (accepted by Brian,
2026-11-18).

### A new device

After enrollment, the device calls `GET /v1/clients`, verifies every grant and revocation, and
keeps those that verify. It also verifies the grant that comes with each request. A verified
grant isn't enough on its own, though: the person **accepts** each client on each device
(Brian, 2026-11-18), so no client starts being answered on a device without a person there
saying yes to it.

- **First request on this device.** A request from a client whose grant verifies but that this
  device hasn't accepted is shown with a notice on the approval screen: "First request from
  linux-client on this device. Paired on minimerlin on 18 Nov, keys: `hw-unseal`, `hw-sign`.
  Approving also accepts this client." The notice names the client id, host, approving device,
  date and keys, all from the verified grant (`approved_by` and the host are labelled as
  reported). Approving runs the request and marks the client accepted, with the same biometric
  and PIN; there is no separate prompt. Denying signs a denial and leaves the client unaccepted,
  so its next request carries the notice again.
- **What counts as accepted.** Acceptance is per client key and stays on the device; it is never
  sent to the relay. A client is accepted on a device when the person approves a request with
  the notice there, approves the client's pairing there, or changes or renews its grant from
  that device's Clients screen.
- **Later grants.** Once a client is accepted, grants with a higher `seq` for the same client key
  are followed without a new notice: they were signed by an `attest` key after a person
  approved them with the card. A revocation, in the manifest or signed, clears acceptance along
  with the grant; a client paired again after that needs accepting again.
- **With a lapse.** A lapsed, unaccepted client's request shows both notices in one: approving
  accepts the client and renews its grant in the same card session.
- **Clients screen.** Clients not yet accepted on this device are listed as "not accepted here:
  accepted with its first approval on this device".

### Every request

The device looks the client up among its verified grants, including the one sent with the
request. A missing or revoked grant fails the request's checks, and the device signs a denial
naming the reason (see "Rejection reasons"). A lapsed grant doesn't fail them, and neither does
a client not yet accepted on this device: the request is shown with the renewal notice, the
first-request notice, or both.

### Changing a client's keys

On the Clients screen: Change keys → choose keys and, if wanted, a new window → biometric → PIN → the attest key signs a
grant with `seq + 1`. Every device picks it up on its next sync. This is a new endpoint,
`POST /v1/clients/{id}/grant`.

### Revoking a client

On the Clients screen: Revoke → biometric → PIN → the attest key signs the revocation.

## Relay endpoints for the new screens

| Endpoint | Auth | Body |
| --- | --- | --- |
| `GET /v1/clients` | admin-auth key of an enrolled device (below) | → `{"clients": [{"client_id", "host", "grant", "last_seen"}], "revocations": [revocation]}`, with `grant` and each revocation as base64 CBOR |
| `GET /v1/devices` | admin-auth key of an enrolled device | → `{"devices": [{"device_id", "device_key", "attestation", "keys": [{"public_key", "token"}], "push_kind", "last_seen"}]}` |
| `POST /v1/clients/{id}/grant` | admin-auth key of an enrolled device | a grant (changing keys or renewing) → `204` |
| `POST /v1/clients/{id}/revocation` | admin-auth key of an enrolled device | a revocation → `204` |

**Who may call them:** a device that the relay holds, that hasn't been revoked, and whose
attestation was signed by an `attest` key in the relay's current manifest
(`verify_attestation_signer`). The window isn't checked, so an expired device can still sync and
renew. Everyone else gets 403, clients included.

**Which key signs these calls:** a new **admin-auth key** (Brian, 2026-11-18). The routine
relay-auth key (wire-format §8.4) keeps polling, registration and push tokens, with no biometric,
so background work and the Mac menu bar keep working.

- **The key:** a third Secure Enclave P-256 key, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`,
  access control `.privateKeyUsage` + `.biometryCurrentSet`.
- **Binding:** the device key vouches for it once, at enrollment, like the auth key, over
  `"relay-pkcs11/admin-auth-key/v1" || 0x00 || device_id || 0x00 || fingerprint(admin_key)`.
  The registration carries `admin_key` and `admin_key_sig`. The relay checks the binding in
  `relay_core::relay_auth` and accepts only this key on the four endpoints above. The HTTP
  signature itself is the usual §8 one.
- **Cached context:** the app evaluates one `LAContext` when a Clients or Approvers screen opens,
  and passes it to every admin-key signature (`kSecUseAuthenticationContext`), so Face ID is asked
  once. It invalidates the context after 1 hour or when the app moves to the background,
  whichever comes first. An approval's own biometric context also covers the grant post it
  makes (renewal, lapsed renewal), so approvals need no second prompt.
- **What the window means:** the Secure Enclave checks that a biometric happened in the context,
  not how long ago; the app enforces the hour. It protects against use after the window, not
  against code running inside the app during it.

**Grants for request checks don't need the admin key.** A device answering a request needs the
client's current grant and any revocations, and that happens in the background after a push. So
`GET /v1/devices/{id}/pending` (relay-auth key) carries, with each request, the client's latest
grant, plus every live revocation (see "Revocation"). The device verifies them as
usual. The admin key gates only the full listings and the changes.

**What the access check is for:** it stops anyone without an enrolled approver from listing
clients, hosts and approvers. It isn't a trust boundary for the data: the relay already holds all
of it, and the app verifies every grant, revocation and attestation it shows.

## Screens

### Clients

One row per client:
- client id and host;
- fingerprint, shortened, plus the pairing words (wire-format §10.1);
- the keys it may use, by manifest label;
- who approved it and when;
- the grant window and when the grant expires;
- status: valid, renews soon, lapsed (renews at the next approval), revoked, or "can't verify" (the attest key is no longer
  in the manifest).

Actions: Change keys, Renew, Revoke. Each needs the card.

### Approvers

One row per device:
- device id, with "this device" marked;
- the manifest keys it holds, by label;
- its attestation window and status, verified on this device: valid, renews soon, expired, or
  not vouched for by the current manifest;
- push kind and last seen, labelled as reported by the relay.

No actions in this feature; devices are still revoked with `relay-server admin devices revoke`.

### Inbox

Each request that failed its checks gets a row with the reason before the Deny button.

## Rejection reasons

The engine already produces a reason for each rejection. The app shows it, and the signed denial
carries it in the response's reason code (wire-format §6.1), so the client can log it too. New
reasons: `ClientNotGranted`, `ClientRevoked`, `KeyNotGranted`. A lapsed grant isn't a rejection.

## Failure handling (new rows, to be added to the spec)

| Situation | Behaviour | Returns |
| --- | --- | --- |
| Request from a client with no usable grant on the device (missing, revoked, or the attest key is no longer in the manifest) | The device signs a denial with the reason | `CKR_FUNCTION_REJECTED` |
| Request from a client listed in the manifest's `revoked_clients` | The relay refuses it (403 `ClientRevoked`); a device that receives one anyway signs a denial with reason `ClientRevoked` | `CKR_FUNCTION_REJECTED` |
| Response from a device whose key is listed in the manifest's `revoked_devices` | The relay discards it (403 `DeviceRevoked`); a provider that receives one anyway discards it and logs it loudly | `CKR_DEVICE_ERROR` |
| Grant or revocation fails its signature or manifest check | The device and the relay discard it; the relay answers 400 | none for the client |

## Manifest

A new required field, `max_client_grant_window_secs`, with the same bounds as
`max_attestation_window_secs` (60..=31 536 000). It is the ceiling for every client's
`window_secs`; each client's window is chosen at pairing (Brian, 2026-11-18).

An optional field, `revoked_clients`: an array of client identity-key fingerprints, sorted, at
most 1 024 entries (Brian, 2026-11-18). Absent means none.
- **Devices** reject every grant, and every request, from a listed client key. The Clients
  screen shows it as "revoked in the manifest", with no action to undo it there.
- **The relay** deletes a listed client, refuses its pairing requests and its calls, and stops
  serving its grants.
- **Providers** need no change: a revoked client is the provider itself, and the relay and the
  devices refuse it.
- **Removing** a fingerprint from a later manifest only lifts the block. The client then needs a
  new grant, since its old grants may also be cancelled by an attest-key revocation.
- **`relayctl manifest`** gets `revoke-client <fingerprint>`; the operator re-signs and
  publishes as usual.

An optional field, `revoked_devices`: an array of device-key fingerprints, sorted, at most
1 024 entries (Brian, 2026-11-18). It lists device keys, not device ids, because an id can be
registered again with a new key after a revoke. Absent means none.
- **The relay** refuses everything from a listed device key: registration
  (`POST /v1/devices`, 403 `DeviceRevoked`), polling, responses, pairing approvals, and the
  admin endpoints, whichever key (device, relay-auth or admin-auth) signs the call, since those
  keys are bound to the device key. It deletes the device's registration, stops routing requests
  to it and stops advertising its keys. A response it has already accepted from that device is
  discarded, and the request stays pending for other devices.
- **Providers** check it too, because the relay isn't trusted: `verify_response` rejects a
  response whose attested device key is listed. This extends check 1 of wire-format §6.2
  ("the attestation verifies against a manifest `attest` key, **and its device key is not in
  `revoked_devices`**"), with `CKR_DEVICE_ERROR` like every other check 1 failure. The order of
  the five checks doesn't change, but the spec's check 1 does, so it needs Brian's approval with
  the rest of the spec edits.
- **Devices** show a listed approver as "revoked in the manifest" on the Approvers screen. A
  device that finds its own key listed stops answering and tells the person to set it up again.
- **Renewing doesn't help a revoked device.** A new attestation still names the same device key.
  A device that is set up again gets a new device key, which isn't listed.
- **Attest keys are separate.** If the revoked device's YubiKey holds an `attest` key that is
  also compromised, remove that key from the manifest; this list doesn't cover it.
- **`relayctl manifest`** gets `revoke-device <fingerprint>`; the Approvers screen shows each
  device key's fingerprint so it can be copied.

`verify_manifest` checks both lists' format: valid fingerprints, sorted, no duplicates, within
the size limit. A malformed list makes the manifest invalid, like any other schema error.

## Migration

None (Brian, 2026-11-19). This is a demo, so installs from before grants start clean: drop the
relay database and the app's saved state, then enroll and pair again. Devices keep only their
cache of verified grants and revocations; there are no local pairing records.

## Tests

- `relay-core`: grant and revocation vectors, byte-exact as in wire-format §5.2; every
  verification failure; sequence and revocation ordering.
- The engine: renewal during an approval at 75% of the grant window; a lapsed client's request
  shown with the notice, and renewed by the approval; a new device shows an existing client's
  first request with the first-request notice, accepts the client only when that request is
  approved, and shows the notice again after a denial; a later grant for an accepted client
  needs no notice; a replayed older grant is refused after a newer one was
  seen; a revoked client is denied with its reason.
- The relay: endpoint access (enrolled, revoked, unattested and client callers), and grant and
  revocation storage.
- `revoked_clients`: format checks in `verify_manifest`; a listed client refused by the relay
  and denied by a device; a grant for a listed client rejected.
- `revoked_devices`: the relay refuses a listed device's registration, polling and responses;
  `verify_response` rejects a response from a listed device key; a listed device that renews
  its attestation is still refused.
- One test per new Failure handling row.
- The gate: pair from the phone, add a new device, which answers without re-pairing after
  accepting the client with its first approval; change keys
  on the iPad, and the phone follows; revoke on the Mac, and every device denies.

## Decisions (Brian, 2026-11-18)

| Question | Decision |
| --- | --- |
| Endpoint auth key | A new admin-auth key, biometric-gated, bound by the device key; one cached `LAContext` per screen session, invalidated after 1 hour or on backgrounding; polling stays on the relay-auth key |
| Pairing with the card | Yes: pairing needs the YubiKey, PIN and any touch the attest key requires |
| Grant window | Its own manifest maximum, `max_client_grant_window_secs`, with each client's window chosen at pairing |
| Lapsed clients | An unused client lapses; its next request renews the last known grant during that approval, with a notice on the approval screen |
| Local pairing list | Deleted after migration; superseded on 2026-11-19: no migration, start clean |
| Clients on a new device | Accepted per device: the first request from a client on a device carries a notice, and approving it accepts the client; denying leaves it unaccepted. Replaces the one-time summary |
| Revocation delivery | No acknowledgement: the relay sends every live revocation; a compromised relay is bounded by grant expiry and the person approving |
| Manifest-level revocation | Yes: optional `revoked_clients` list in the manifest |
| Revoked approvers | Yes: optional `revoked_devices` list of device-key fingerprints; the relay refuses the device's calls and responses, and providers reject its responses (extends check 1 of wire-format §6.2, pending spec approval) |
