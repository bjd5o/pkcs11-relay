# Hardware attestation of attest keys: design (proposal)

Status: **draft for review, revision 2.** It records Brian's answers of 2026-11-17. Nothing here
changes `docs/spec.md` or the wire format until Brian approves it. When it is approved, the
"Proposed spec changes" section is applied to `docs/spec.md` and `docs/wire-format.md`, and an
entry goes into `docs/decisions.md`.

## Goal

Today a client trusts an `attest` key because the PGP-signed manifest lists it. Nothing shows
that the key was generated inside a YubiKey, or that the card enforces touch on it. This proposal
adds that evidence. It uses YubiKey PIV attestation: a certificate chain from Yubico's root to the
key, naming the card's serial, firmware and PIN/touch policy. Clients verify it when they load the
manifest.

It fits the planned key setup:

- `sign`, `auth` and `encrypt` keys are generated on an airgapped machine and imported onto both
  YubiKeys, so the cards are interchangeable.
- Each YubiKey generates its own `attest` key on the card. Only keys generated on the card can be
  attested.

## Decisions taken (2026-11-17)

| Question | Decision |
| --- | --- |
| Pin card serials on clients | **No.** Pushing new serials to every client whenever a token is added costs more than it protects. See "Serial pinning" below for the relay-side variant. |
| Hierarchies accepted | **5.7.4+ only:** `Yubico Attestation Root 1`. The old `PIV Root CA Serial 263751` is not accepted. |
| Minimum firmware | **5.7.4**, checked against the leaf's firmware extension. |
| Bad evidence | **Reject the whole manifest.** |
| Verifier | **`rustls-webpki`** for path validation, plus `x509-cert` to read the Yubico extensions. |
| Relay-side serial pinning | **No.** |
| `require` default | **On.** Every attest key must carry a valid chain, unless a deployment explicitly sets `require = false`. |
| Relay checks the manifest it serves | **Yes**, and it filters its key advertisement through the verified manifest (see "Relay filtering"). |

## What it protects against

| Threat | Without this | With this |
| --- | --- | --- |
| Signer lists a software or exported attest key by mistake | Accepted | **Rejected** |
| Attest key without touch `always`, or with PIN policy `never` | Accepted | **Rejected** |
| Attest key on firmware older than 5.7.4, which EUCLEAK affects for ECDSA below 5.7 | Accepted | **Rejected** |
| PGP manifest key stolen; thief lists an attest key on their own YubiKey | Accepted | Accepted: the chain is genuine and names the thief's serial |
| PGP key stolen; thief swaps the `encrypt` public key | Software `C_Encrypt` encrypts to the thief | Same |
| Approver device key not in the Secure Enclave | Not checked | Not checked (App Attest stays post-MVP) |

So this guards against mistakes and weak cards. It does not guard against a stolen PGP key; that
would need serial pinning, which is not adopted.

### Serial pinning: client versus relay

Pinning on the relay would mean the relay refuses a device registration whose attestation was
signed by an attest key on a card not in its serial list. It is cheaper than client pinning, with
one list in one place. But it protects less than it seems:

- The relay is untrusted by design. A check there is defence in depth, not a trust anchor. Anyone
  who controls the relay bypasses it.
- In this deployment the relay also serves the manifest (`GET /v1/manifest`). A PGP-key thief
  already has to replace the relay's manifest file to reach clients, and with that access they can
  edit the relay's serial list as well. Relay pinning therefore adds nothing here.
- It would help only if the manifest were hosted somewhere other than the relay, against a thief
  holding the PGP key and the manifest host but not the relay.

Decision: don't add it. It is easy to add later behind a relay option if the manifest moves off
the relay.

### Relay filtering

The relay verifies the manifest it serves with the same `relay-core` function and policy, and
filters `GET /v1/keys` through it:

- **Valid manifest:** advertise only keys that the manifest lists with a non-`attest` role and
  that a device whose attestation verifies against a manifest attest key has registered.
- **Invalid manifest** (signature, freshness or hardware attestation): advertise **no keys**, and
  log the reason at error level each time the manifest is re-read. The relay keeps serving the
  manifest bytes unchanged, so providers report "manifest invalid" rather than "unreachable" and
  fall back to their cached copy as the Failure handling table says. The relay does not keep a
  cached copy of its own. Whoever controls the relay's manifest file is the one who just replaced
  it.
- **Device registration:** the relay rejects a registration whose attestation doesn't verify
  against the current manifest, with a clear error for the app.

New relay configuration: `manifest_signer` (the PGP public key file, the same one clients use),
plus the `[hardware_attestation]` section, with the same defaults as the provider.

**Providers still verify everything themselves.** The relay is untrusted: a compromised relay can
skip its own checks, or advertise whatever it likes. Relay filtering gives a single place where a
bad manifest becomes visible and stops traffic. It also means the relay never rings an approver
for a key clients would refuse. But it replaces none of the provider's checks. The spec's rule that
"advertisements are untrusted hints: the provider filters them through the manifest" stays as it
is.

## YubiKey PIV attestation (5.7.4+)

Source: developers.yubico.com/PIV/Introduction/PIV_attestation.html. The CA certificates under
/PKI/ were downloaded and inspected on 2026-11-17.

- `GET ATTESTATION` (INS `F9`, P1 = slot) returns an X.509 certificate for a key generated on the
  card, signed by the card's slot-`F9` key. Imported keys return an error.
- The slot-`F9` certificate (data object `5FFF01`) is factory-issued. Overwriting it destroys it
  permanently, so the tooling never writes slot `F9`.
- The chain, leaf first:
  1. the leaf;
  2. the device `F9` certificate (a CA);
  3. `Yubico PIV Attestation {A,B,B2} 1` (pathlen 1);
  4. `Yubico Attestation Intermediate {A,B} 1` (pathlen 2);
  5. the root, `Yubico Attestation Root 1` (RSA-2048, pathlen 3, valid to 9999).

  Items 3 and 4 come from Yubico's published intermediate bundle.
- The same root also issues FIDO, OpenPGP, Secure Domain and YubiHSM attestation CAs. The
  verifier must therefore require that the path passes through a `Yubico PIV Attestation`
  intermediate.
- Leaf extensions:

  | OID | Content |
  | --- | --- |
  | `1.3.6.1.4.1.41482.3.3` | firmware version, 3 bytes |
  | `1.3.6.1.4.1.41482.3.7` | serial, DER INTEGER |
  | `1.3.6.1.4.1.41482.3.8` | PIN policy byte (01 never, 02 once, 03 always), then touch policy byte (01 never, 02 always, 03 cached) |
  | `1.3.6.1.4.1.41482.3.9` | form factor |

## Design

### Manifest field (wire-format §9.2)

A new optional field is allowed on any key. It is expected on `attest` keys.

```json
"hardware_attestation": {
  "format": "yubikey-piv",
  "chain": ["<base64 DER leaf>", "<base64 DER F9 cert>", "<base64 DER PIV Attestation CA>", "<base64 DER Intermediate CA>"]
}
```

| Field | Rules |
| --- | --- |
| `format` | `"yubikey-piv"`; anything else is rejected |
| `chain` | 2–4 base64 DER certificates, leaf first, root excluded; each at most 2 KiB DER |

The serial, firmware and policies are derived from the verified leaf, not stored separately.
**The serial is inside the leaf certificate,** so publishing the chain publishes the card serials
to anyone who can fetch the manifest. That cannot be avoided if the chain is to be checkable. The
repo still never contains real chains or serials; tests use synthetic ones.

`v` stays `1`. Older parsers reject unknown fields, so they fail closed on the new field. Nothing
is deployed outside the test setup.

### Verification (new wire-format §9.4, in `relay-core`)

`verify_piv_attestation(chain, expected_public_key, policy, now) -> PivAttestation { serial, firmware, pin_policy, touch_policy, form_factor }`

1. **Path:** `webpki::EndEntityCert::try_from(chain[0])`, then `verify_for_usage(...)` with:
   - the trust anchor `Yubico Attestation Root 1` (`anchor_from_trusted_cert`);
   - the rest of the chain as intermediates;
   - `UnixTime` from `now`;
   - the algorithms `RSA_PKCS1_2048_8192_SHA256/384/512`, `ECDSA_P256_SHA256` and
     `ECDSA_P384_SHA384`, from webpki's `ring` provider;
   - a custom `ExtendedKeyUsageValidator` that accepts any EKU, since Yubico's chains do not use it;
   - no revocation.

   webpki checks signatures, issuer/subject chaining, CA flags, path length, validity, and rejects
   unknown critical extensions.
2. **PIV branch:** in the `VerifiedPath`, one intermediate's subject CN must start with
   `Yubico PIV Attestation `.
3. **Binding:** the leaf's SubjectPublicKeyInfo, parsed with `x509-cert`, must equal
   `expected_public_key` byte for byte.
4. **Leaf fields:** the serial (`.3.7`) must be present and fit a `u32`. Firmware (`.3.3`) and
   policy (`.3.8`) must be present and well formed.
5. **Firmware:** at least `policy.min_firmware` (5.7.4).

webpki doesn't take a clock skew. The Yubico certificates are valid from 2024 to 9999, so skew
doesn't matter here.

`verify_manifest` gains a `&HardwarePolicy` parameter. After the JSON is parsed, and before the
freshness and rollback checks:

```rust
pub struct HardwarePolicy {
    pub require_for_attest: bool,         // every attest key must carry a valid chain
    pub min_firmware: (u8, u8, u8),       // 5.7.4
    pub roots: Vec<CertificateDer<'static>>, // built-in Root 1; replaced only in tests
}
```

The manifest is **invalid** if any of these holds. The caller then keeps its valid cached copy,
or lists zero slots.

- Any key's `hardware_attestation` fails verification.
- An `attest` key's chain shows touch not `always`, or PIN policy `never`.
- `require_for_attest` is set and an `attest` key has no chain.

Response verification is unchanged: it looks attest keys up in the verified manifest as today.

When the manifest is rejected:

- each provider lists zero slots, or keeps its last good cached manifest;
- the app refuses to enroll against it;
- the relay advertises no keys and logs the failure ("Relay filtering").

### Dependencies

`rustls-webpki` is pinned as `=0.103.17` in `[workspace.dependencies]` with the `ring` feature,
and becomes a direct dependency of `relay-core`. It is already in the lock file, through rustls and
ureq, so the provider and the iOS framework already include it and `ring`. The binaries gain no
new crates. `relay-core` itself gains `ring`, which is C and assembly, but that code already ships
in every binary that uses `relay-core`, except `relayctl` and `relay-softcard`. `rustls-pki-types`
comes with it for `CertificateDer` and `UnixTime`.

### Built-in root

`relay-core` embeds the DER of `Yubico Attestation Root 1`, with its SHA-256 asserted in a test.
`relayctl` embeds Yubico's intermediate bundle to assemble chains. Clients never need it, because
the intermediates travel in the manifest.

### Provider and app configuration

```toml
[hardware_attestation]
require = true               # every attest key must have a valid YubiKey chain
roots_file = "/path/ca.pem"  # testing only: replaces the built-in root; logged as a warning
```

The minimum firmware is fixed at 5.7.4 in code, not configurable. `require` defaults to **true**
in the provider, the relay and the app. Only an explicit `require = false` accepts attest keys
without a chain, and a chain that is present is always verified. `relayctl app-config
--no-hardware-attestation` writes `require = false` into the app's setup file.

This default breaks the current test fixtures and gate manifests, whose attest keys have no
chains. The fixtures get synthetic chains. Existing gate manifests are re-made with `relayctl
manifest add --role attest` on the cards, or set `require = false` until then.

### `relayctl`

- `manifest add --serial S --slot XX --role attest` also runs `GET ATTESTATION` on the slot and
  reads object `5FFF01`. It assembles the chain from the embedded bundle, verifies it with the
  `relay-core` function, prints the serial, firmware and policies, and stores the chain. Both
  operations are read-only on the card. `--no-hardware-attestation` skips this.
- `manifest add --public-key key.pem --attestation-chain chain.pem` attaches a chain gathered
  elsewhere, for example with `ykman piv keys attest`.
- `manifest show` and `manifest verify` print each chain's serial, firmware and policies.

### Approver engine

`discover` compares each found attest key's chain serial with the serial of the card in hand, and
reports any mismatch. This is a sanity check; enforcement is on the clients.

### Softcard and tests

- `relay-softcard` gets a synthetic hierarchy with the same shape: test root, intermediate,
  `Test PIV Attestation` CA, per-card `F9` CA, then the leaf. It supports `GET ATTESTATION` for
  generated keys and returns an error for imported ones. It is built with the `x509-cert` builder
  that is already pinned.
- `relay-core` unit tests:
  - Yubico's real root and intermediates parse with webpki, and the root's hash is asserted.
  - A synthetic chain verifies.
  - Each rule fails when broken:
    - wrong key;
    - broken signature;
    - an intermediate that isn't a PIV attestation CA, such as an OpenPGP one;
    - non-CA intermediate;
    - expired certificate;
    - unknown critical extension;
    - missing serial;
    - touch not `always`;
    - PIN policy `never`;
    - firmware below 5.7.4;
    - chain too long or too large;
    - `require` set with no chain.
- A golden vector: a synthetic manifest key with a chain.
- Integration: the compose test runs with `require = true` and the test root. One extra case uses
  an attest key whose leaf shows touch `never`; the provider must list zero slots. This covers the
  new Failure handling row.
- Real cards: a git-ignored gate step. It runs `relayctl manifest add --role attest` on each card,
  with per-command approval, then loads the manifest with `require = true`.

## Proposed spec changes

These are draft text, not yet applied.

**Trust manifest, fields table:** add a row.

> | `keys[].hardware_attestation` | `{format: "yubikey-piv", chain: […]}` | Optional. The YubiKey's attestation chain (firmware 5.7.4+) for a key generated on the card: proof that it is on a genuine YubiKey, with its serial, firmware and PIN/touch policy. Expected on `attest` keys. The chain names the card's serial |

**Hardware key, configuration table, "PIN and touch policy" row:** append

> Generate the `attest` key on the card, never import it, so the card can attest it. Never write slot `F9`: it holds Yubico's factory attestation key.

**PKCS#11 provider, response checks:** add before item 1

> 0. when the manifest is loaded, every `attest` key's hardware attestation chain (required unless configured otherwise) verifies against Yubico's attestation root, shows touch `always` and firmware 5.7.4 or later; otherwise the manifest is invalid.

**Threat model, `attest` key row, "What still stops them":** append

> hardware attestation in the manifest proves it was generated on a YubiKey with touch `always`.

**Failure handling:** a new row.

> | Manifest's hardware attestation missing (when required), invalid or outside policy | Keeps a valid cached copy if it has one; otherwise lists no slots | Zero slots |

**Relay, responsibilities:** add

> - **Check the manifest.** Verify the manifest it serves, with the same rules as clients. Advertise only keys it lists, and only from devices attested by its `attest` keys. If it is invalid, advertise nothing and log why. Clients still verify everything themselves.

**Relay, configuration:** add the manifest signer's public key and the hardware attestation
policy.

**Failure handling:** a second new row.

> | Relay's manifest invalid | Relay advertises no keys; providers use a valid cached manifest if they have one | Zero slots, or last known slots |

**Enrollment tool, responsibilities:** add

> Read each attest key's attestation chain from the card and store it in the manifest.

**Technology table:** add `rustls-webpki` for X.509 path validation of hardware attestation.

## Work estimate

About 800 lines, test-heavy. The verifier part is smaller now that webpki does path validation.
Commits in order:

1. relay-core: root, `verify_piv_attestation` and unit tests.
2. relay-core: manifest field, `HardwarePolicy`, `verify_manifest` change and callers; golden
   vector.
3. relay-softcard: synthetic hierarchy and `GET ATTESTATION`.
4. relayctl: `manifest add/show/verify` and `app-config` option.
5. Provider and app configuration (`require` on by default), engine serial check; fixtures get
   synthetic chains.
6. Relay: signer and policy configuration, manifest verification, filtered `GET /v1/keys`,
   attestation check on registration.
7. Integration cases for both new failure rows.
8. Docs: spec, wire format, decisions, progress.

The relay filtering adds about 200 lines, so the total is about 1,000.

## Open questions for Brian

None left. Approval of this revision applies the spec changes.
