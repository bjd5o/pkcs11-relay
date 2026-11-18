# Wire format, v1

Status: **reviewed by Brian, 2026-11-15**; §10 (relay API bodies) added in milestone 2. Written from `docs/spec.md` ("Keys and messages") and the defaults table in `docs/milestones-1-4.md`. Where this document goes beyond either, the change is listed under "Departures from the spec" at the end with its `docs/decisions.md` entry; anything still marked **[proposal]** is awaiting review.

`relay-core` is the only implementation. Golden vectors for every message live in `crates/relay-core/tests/vectors/`; if this document and the vectors disagree, that is a bug in one of them, and the fix is recorded in `docs/decisions.md`.

## 1. Conventions

### 1.1 Scalars

| Thing | Encoding |
|---|---|
| Timestamp | Unix seconds, unsigned 64-bit. CBOR: unsigned integer. JSON: integer. |
| Request id (`req_id`) | 16 random bytes from the OS CSPRNG. CBOR: byte string. In URL paths: 32 lowercase hex characters. |
| Client id, device id | UTF-8 text, 1–64 characters from `[a-z0-9-]`, not starting or ending with `-`. |
| Key fingerprint | `"sha256:"` + 64 lowercase hex characters of SHA-256 over the key's DER SubjectPublicKeyInfo (§2). Text string in both CBOR and JSON. |
| Public key | DER SubjectPublicKeyInfo (§2). CBOR: byte string. JSON: base64. |
| Hash | SHA-256, 32 bytes. |
| Binary in JSON and HTTP headers | Base64, RFC 4648 §4 (standard alphabet, with padding). |

### 1.2 Deterministic CBOR

Every signed message is a CBOR map encoded with RFC 8949 core deterministic encoding (§4.2.1):

- integers, lengths and map sizes in their shortest form;
- definite lengths only;
- map keys sorted by the bytewise order of their encoded form. Every key here is a text string under 24 bytes, so the order is **shorter keys first, then bytewise by UTF-8**. The field tables below list fields in that order.

Only these CBOR types appear: unsigned integer (major type 0), byte string (2), text string (3) and map (5). Never negative integers, arrays, tags, floats, `null`, `undefined` or booleans. An optional field that has no value is **left out**, never encoded as `null`.

Decoders are strict. They reject, with no partial result:

- input that is not exactly one CBOR item (trailing bytes included);
- any type outside the four above;
- input that is not canonical. The check: decode, re-encode, and compare byte for byte with the input;
- unknown keys, duplicate keys, missing required keys, or a field of the wrong type;
- `v` other than `1`;
- nesting deeper than 3 maps, or a message over 65 536 bytes;
- text that is not valid UTF-8.

### 1.3 Signed bytes

For a message with signature field `S` and context string `C`:

```
signed_bytes = C || 0x00 || deterministic_CBOR(message map without S)
```

The context strings are ASCII, with no terminator besides the `0x00` shown:

| Message | Context string | Signature field | Signer |
|---|---|---|---|
| Request | `relay-pkcs11/request/v1` | `client_sig` | client identity key |
| Attestation statement | `relay-pkcs11/attestation/v1` | `sig` | manifest `attest` key |
| Response | `relay-pkcs11/response/v1` | `device_sig` | device key |
| Relay HTTP auth | `relay-pkcs11/relay-auth/v1` | `X-Relay-Signature` header | client or device key (§8) |
| Client grant | `relay-pkcs11/client-grant/v1` | `sig` | manifest `attest` key (§12.1) |
| Client revocation | `relay-pkcs11/client-revocation/v1` | `sig` | manifest `attest` key (§12.3) |

The verifier never signs or hashes the bytes it received. It decodes them, which also enforces canonical form, removes the signature field, re-encodes the rest and verifies over that. Because decoding demands canonical input, the result equals the sender's bytes minus the signature entry.

### 1.4 Signature algorithms

The key's type decides the algorithm, and no message carries an algorithm field.

| Key | Algorithm | Signature bytes |
|---|---|---|
| Ed25519 | Ed25519 (RFC 8032) over `signed_bytes`. Verified with `verify_strict`. | 64 |
| P-256 | ECDSA with SHA-256 over `signed_bytes`. | 64: `r ‖ s`, each 32 bytes big-endian, left-padded with zeros |

ECDSA signers may produce high-S values (the Secure Enclave does), and verifiers accept both. No identifier in this protocol is derived from a signature, so malleability does not matter.

Platform note: Security.framework, PIV `GENERAL AUTHENTICATE` and OpenSSL all return DER `ECDSA-Sig-Value`. The signer converts that to `r ‖ s` with `relay_core::padding`, and platform code never does it by hand.

## 2. Keys and fingerprints

`fingerprint(key) = "sha256:" || hex(SHA-256(DER(SubjectPublicKeyInfo)))`

Only one SPKI encoding is accepted per key, so every key has exactly one fingerprint:

| Algorithm name | SPKI | Used for |
|---|---|---|
| `rsa-2048`, `rsa-4096` | `rsaEncryption` (1.2.840.113549.1.1.1) with NULL parameters; modulus exactly 2048 or 4096 bits; public exponent 65537 **[proposal: reject other exponents]** | `sign`, `auth`, `encrypt` |
| `p256` | `id-ecPublicKey` with namedCurve `prime256v1`; **uncompressed** point (65 bytes, leading `0x04`) | `sign`, `auth`, `attest`, device keys, reply keys |
| `p384` | `id-ecPublicKey` with namedCurve `secp384r1`; uncompressed point (97 bytes) | `sign`, `auth`, `encrypt` |
| `x25519` | `id-X25519` (1.3.101.110), no parameters, 32-byte key | `encrypt` |
| `ed25519` | `id-Ed25519` (1.3.101.112), no parameters | `sign`, `auth`, client identity keys |

Any other SPKI form is rejected when parsed: compressed points, explicit curve parameters, RSA-PSS OIDs, or trailing bytes.

Roles each algorithm may take:

| Role | Allowed algorithms |
|---|---|
| `sign` | `rsa-2048`, `rsa-4096`, `p256`, `p384`, `ed25519` |
| `auth` | `rsa-2048`, `rsa-4096`, `p256`, `p384`, `ed25519` |
| `encrypt` | `rsa-2048`, `rsa-4096` (OAEP decrypt); `p256`, `p384`, `x25519` (ECDH) |
| `attest` | `p256` |

Worked example: the P-256 device key from §5's example has this SPKI (91 bytes)

```
3059301306072a8648ce3d020106082a8648ce3d030107034200048b9432b61c9144081b2eff864829ab0440cbe555b62ada198b8131e4e8fcf1f4226fbd788f8a53a858048fc0751d0e773303972e8a645718d4a3055383456528
```

and fingerprint `sha256:d2d3e0fc4b057ee2319854654ec5747eb63a3395343c3d9010afaddb0097f786`.

## 3. Mechanisms, roles and inputs

| Role | Key | Mechanism (`name`) | `op` | `input` | Result (sealed plaintext) |
|---|---|---|---|---|---|
| `sign` | RSA | `CKM_SHA256_RSA_PKCS` | `sign` | full message, 1–32 768 bytes | PKCS#1 v1.5 signature, modulus length, big-endian |
| `sign` | P-256 | `CKM_ECDSA_SHA256` | `sign` | full message, 1–32 768 bytes | `r ‖ s`, 64 bytes |
| `sign` | P-384 | `CKM_ECDSA_SHA384` | `sign` | full message, 1–32 768 bytes | `r ‖ s`, 96 bytes |
| `sign`, `auth` | Ed25519 | `CKM_EDDSA` (pure Ed25519; no prehash, no context) | `sign` | full message, 1–32 768 bytes | 64-byte signature |
| `auth` | RSA | `CKM_RSA_PKCS` | `sign` | caller's data as given to `C_Sign` (normally a DigestInfo), 1 to *k*−11 bytes | PKCS#1 v1.5 signature, modulus length |
| `auth` | P-256, P-384 | `CKM_ECDSA` | `sign` | digest as given to `C_Sign`, 1–64 bytes (truncated or left-padded to the field size) | `r ‖ s`, 64 or 96 bytes |
| `encrypt` | RSA | `CKM_RSA_PKCS_OAEP` | `decrypt` | ciphertext, exactly *k* bytes | plaintext |
| `encrypt` | P-256, P-384, X25519 | `CKM_ECDH1_DERIVE` | `derive` | the peer public key: an uncompressed point (65 or 97 bytes) or the 32-byte X25519 key, checked to be on the curve | the derived key, `out_len` bytes: `CKD_NULL` keeps the leading bytes of the shared secret; `CKD_SHA256_KDF` is ANSI X9.63 with SHA-256 over the secret and `shared_data`. An all-zero shared secret is refused |

The approver runs the card's ECDH (PIV `GENERAL AUTHENTICATE`, tag `85`) and the KDF. The derived key comes back sealed like a decryption result. In the provider it becomes a session-only secret-key object (§ "Derived keys" in the spec).

*k* is the modulus length in bytes. Multi-part signing (`C_SignUpdate`) buffers locally and sends the concatenated message once. A message over 32 768 bytes is refused locally with `CKR_DATA_LEN_RANGE` **[proposal: the limit keeps the request inside the relay's 64 KiB body cap]**.

For the MVP, OAEP takes only `hash = "sha256"` and `mgf = "mgf1-sha256"`. Any other combination, or a label over 256 bytes, is refused locally with `CKR_MECHANISM_PARAM_INVALID`. A mechanism outside the key's row is refused with `CKR_MECHANISM_INVALID`, and an `op` outside the key's role with `CKR_KEY_FUNCTION_NOT_PERMITTED` (Failure handling table). The approver repeats every one of these checks against its own copy of the manifest.

## 4. Request envelope

Built and signed by the provider. CBOR map, context string `relay-pkcs11/request/v1`, signature field `client_sig`.

| Key (canonical order) | Type | Rules |
|---|---|---|
| `v` | uint | `1` |
| `op` | tstr | `"sign"`, `"decrypt"` or `"derive"` |
| `input` | bstr | §3 |
| `req_id` | bstr | 16 bytes |
| `context` | map | §4.1 |
| `client_id` | tstr | §1.1 |
| `mechanism` | map | §4.2 |
| `reply_pub` | bstr | HPKE public key for this request: uncompressed P-256 point, 65 bytes (raw `SerializePublicKey`, **not** SPKI) |
| `client_sig` | bstr | 64 bytes, §1.4 |
| `created_at` | uint | Unix seconds |
| `expires_at` | uint | `created_at < expires_at <= created_at + 120` (the relay's max TTL) |
| `key_fingerprint` | tstr | the hardware key to use |

### 4.1 `context`

The requester's claims. The approval screen shows them under a heading that says they are claims, separate from what the approver checked itself.

| Key | Type | Rules |
|---|---|---|
| `host` | tstr | 1–255 bytes, e.g. `pi5.tailnet` |
| `purpose` | tstr | 0–255 bytes, from the provider config's purpose text |
| `consumer` | tstr | 0–255 bytes, the loading process's executable name if known, e.g. `bao` |

### 4.2 `mechanism`

| Key | Type | Rules |
|---|---|---|
| `mgf` | tstr | OAEP only: `"mgf1-sha256"` |
| `hash` | tstr | OAEP only: `"sha256"` |
| `name` | tstr | a PKCS#11 mechanism name from §3 |
| `label` | bstr | OAEP only: the label (`pSourceData`), 0–256 bytes; present, possibly empty |
| `kdf` | tstr | ECDH only: `"null"` or `"sha256"` |
| `out_len` | uint | ECDH only: derived key length, 1–64 bytes (`null`: at most the field size) |
| `shared_data` | bstr | ECDH only: X9.63 shared info, 0–256 bytes; empty for `null` |

All three of `mgf`, `hash` and `label` are present for `CKM_RSA_PKCS_OAEP` and absent for every other mechanism.

### 4.3 `request_hash`

`request_hash = SHA-256(exact CBOR bytes of the request as sent, including client_sig)`. Because decoders enforce canonical form, every party that accepted the request computes the same hash.

### 4.4 Example (diagnostic notation)

```
{
  "v": 1,
  "op": "decrypt",
  "input": h'5c1e…(512 bytes)',
  "req_id": h'9f2c4e1a7b3d5f60a1b2c3d4e5f60718',
  "context": {"host": "pi5.tailnet", "purpose": "OpenBao unseal on pi5", "consumer": "bao"},
  "client_id": "openbao-pi5",
  "mechanism": {"mgf": "mgf1-sha256", "hash": "sha256", "name": "CKM_RSA_PKCS_OAEP", "label": h''},
  "reply_pub": h'04…(65 bytes)',
  "client_sig": h'…(64 bytes)',
  "created_at": 1794744000,
  "expires_at": 1794744090,
  "key_fingerprint": "sha256:4f1c…"
}
```

The byte-exact version is the golden vector `request/decrypt-oaep.cbor`. Building it needs a real RSA ciphertext, so it is generated by `relay-core` rather than by hand.

## 5. Attestation statement

Signed by a manifest `attest` key (ECDSA P-256). Context string `relay-pkcs11/attestation/v1`, signature field `sig`. Reused across responses until it expires.

| Key (canonical order) | Type | Rules |
|---|---|---|
| `v` | uint | `1` |
| `sig` | bstr | 64 bytes, ECDSA P-256 `r ‖ s` |
| `device_id` | tstr | §1.1 |
| `not_after` | uint | Unix seconds |
| `device_key` | bstr | P-256 SPKI of the device key (§2) |
| `not_before` | uint | `not_before < not_after` |
| `attest_key_fingerprint` | tstr | fingerprint of the signing attest key |
| `device_key_fingerprint` | tstr | must equal `fingerprint(device_key)`; the decoder rejects a mismatch |

On a YubiKey the attest key signs a digest: the approver computes `SHA-256(signed_bytes)`, sends it with `GENERAL AUTHENTICATE`, and converts the card's DER signature to `r ‖ s`.

### 5.1 Verification (`verify_attestation(statement, manifest, now, skew)`)

1. Decode strictly (§1.2), including the `device_key_fingerprint` consistency check.
2. Look up `attest_key_fingerprint` in the manifest. It must exist with role `attest`; otherwise fail with "not signed by a manifest attest key".
3. Verify `sig` over `signed_bytes` with that key's public key, taken from the manifest's `keys[].public_key`.
4. Require `not_before − skew <= now <= not_after + skew`; otherwise fail as expired or not yet valid.
5. Require `not_after − not_before <= manifest.max_attestation_window_secs`; otherwise fail with `AttestationWindowTooLong` (same Failure handling row as steps 2–4).

`verify_attestation_signer(statement, manifest)` runs steps 1–3 and 5, not step 4. The relay uses it: an expired device keeps receiving requests so that it can renew during an approval, while a window that is too long only changes when the device renews.

### 5.2 Worked example (byte-exact)

Keys generated with OpenSSL for this document and signed with `openssl dgst -sha256 -sign`; the signature verifies with `openssl dgst -verify`. This example becomes golden vector `attestation/valid.cbor`.

- attest key fingerprint: `sha256:ea4e871a4792bc891653e2e47e983fee8a0aaca42153951eb89379002574d159`
- device key: the SPKI in §2
- window: `not_before = 1794700800` (2026-11-15T00:00:00Z), `not_after = 1797292800` (2026-12-15T00:00:00Z)

Diagnostic:

```
{
  "v": 1,
  "sig": h'13e38ddd96420e845f36e445709f416c9227410d28b5c08fe48fc4b60196fd61c82c595e14d8c90453a94fb0557f32bf171420a70834b7d5ca0bd3e03b997624',
  "device_id": "brian-iphone",
  "not_after": 1797292800,
  "device_key": h'3059…6528',
  "not_before": 1794700800,
  "attest_key_fingerprint": "sha256:ea4e…d159",
  "device_key_fingerprint": "sha256:d2d3…f786"
}
```

Signed bytes, annotated (the context string, `00`, then a 7-entry map without `sig`):

```
72656c61792d706b637331312f6174746573746174696f6e2f7631   "relay-pkcs11/attestation/v1"
00                                                       separator
a7                                                       map(7)
  61 76  01                                              "v": 1
  69 6465766963655f6964  6c 627269616e2d6970686f6e65     "device_id": "brian-iphone"
  69 6e6f745f6166746572  1a 6b208300                     "not_after": 1797292800
  6a 6465766963655f6b6579  58 5b 3059…6528               "device_key": bstr(91)
  6a 6e6f745f6265666f7265  1a 6af8f600                   "not_before": 1794700800
  76 6174746573745f6b65795f66696e6765727072696e74        "attest_key_fingerprint"
     78 47 7368613235363a6561…                           tstr(71) "sha256:ea4e…"
  76 6465766963655f6b65795f66696e6765727072696e74        "device_key_fingerprint"
     78 47 7368613235363a6432…                           tstr(71) "sha256:d2d3…"
```

The full statement is 424 bytes: `a8 6176 01 63736967 5840 13e3…7624 …` (the same map with `"sig"` in second place).

## 6. Response envelope

Signed by the device key (ECDSA P-256). Context string `relay-pkcs11/response/v1`, signature field `device_sig`. Per the spec, `device_sig` covers every field except `attestation`.

| Key (canonical order) | Type | Rules |
|---|---|---|
| `v` | uint | `1` |
| `reason` | tstr | only with `denied` or `error`; optional; one of the codes in §6.1; covered by `device_sig` |
| `req_id` | bstr | 16 bytes; must equal the request's |
| `status` | tstr | `"approved"`, `"denied"` or `"error"` |
| `device_sig` | bstr | 64 bytes, ECDSA P-256 `r ‖ s` |
| `attestation` | bstr | the attestation statement's exact CBOR bytes (§5), wrapped as a byte string so it is verified over the bytes its signer produced; **not** covered by `device_sig` |
| `request_hash` | bstr | 32 bytes, §4.3 |
| `responded_at` | uint | Unix seconds; informational and logged, not checked |
| `sealed_result` | bstr | present if and only if `status = "approved"`; §7 |
| `device_key_fingerprint` | tstr | fingerprint of the key that made `device_sig` |

### 6.1 Reason codes

`user_denied`, `policy` (the approver's checks refused the request), `client_not_granted` (no usable grant for the client: missing, or its `attest` key left the manifest), `client_revoked` (a revocation, or the manifest's `revoked_clients`), `key_not_granted` (the key is outside the client's grant), `expired`, `card_absent`, `wrong_pin`, `pin_blocked`, `card_error`, `internal`. The provider logs the code and maps every `denied` to `CKR_FUNCTION_REJECTED` and every `error` to `CKR_DEVICE_ERROR`, as the Failure handling table requires. A code is a hint from an attested device, nothing more.

### 6.2 Verification (`verify_response(response, request_bytes, manifest, now, skew)`)

The spec's five checks, in the spec's order, stopping at the first failure. Every failure discards the response and returns `CKR_DEVICE_ERROR`.

1. Decode the response strictly. Run `verify_attestation` (§5.1, steps 1–3) on `attestation`: its signature verifies against a manifest `attest` key. Then check that the statement's `device_key_fingerprint` is not in the manifest's `revoked_devices` (§9.2). A listed key fails with `DeviceRevoked`, which has its own Failure handling row; the provider logs it loudly.
2. §5.1 step 4: `now` is inside the statement's window, allowing `skew`.
3. `response.device_key_fingerprint == statement.device_key_fingerprint`.
4. `device_sig` verifies over `signed_bytes` with `statement.device_key`. Then `req_id == request.req_id` and `request_hash == SHA-256(request_bytes)`. The request hash covers the request's `key_fingerprint` and `mechanism`, so binding the hash binds both (the spec's "echoes this request's id, key and mechanism").
Only after checks 1–4 pass, and only for `approved`: open `sealed_result` (§7) and zero the reply private key.

5. For a signature result: verify the opened signature against the hardware key's public key from the manifest, for the request's mechanism and input. On failure, zero the plaintext and return `CKR_DEVICE_ERROR`. Check 5 needs the opened result, so it runs after the open; nothing is decrypted before the attestation and device signature have been checked. For `denied` or `error`, the checks run the same way; a `denied` that passes them returns `CKR_FUNCTION_REJECTED`, and an `error` that passes them returns `CKR_DEVICE_ERROR`.

### 6.3 Example (diagnostic notation)

```
{
  "v": 1,
  "req_id": h'9f2c4e1a7b3d5f60a1b2c3d4e5f60718',
  "status": "approved",
  "device_sig": h'…(64 bytes)',
  "attestation": h'a8617601…(424 bytes, §5.2)',
  "request_hash": h'…(32 bytes)',
  "responded_at": 1794744031,
  "sealed_result": h'04…(65-byte enc)…(ciphertext + 16-byte tag)',
  "device_key_fingerprint": "sha256:d2d3e0fc4b057ee2319854654ec5747eb63a3395343c3d9010afaddb0097f786"
}
```

A denial is the same without `sealed_result`, with `"status": "denied"` and `"reason": "user_denied"`. The byte-exact versions are golden vectors under `response/`.

## 7. Sealed results (HPKE)

RFC 9180, base mode (`mode_base`, no PSK, no sender authentication):

| Parameter | Value |
|---|---|
| KEM | DHKEM(P-256, HKDF-SHA256), `0x0010` |
| KDF | HKDF-SHA256, `0x0001` |
| AEAD | AES-256-GCM, `0x0002` |
| `info` | ASCII `relay-pkcs11/result/v1` followed directly by the 16-byte `req_id` (38 bytes; no separator needed, since `req_id` has a fixed length) |
| `aad` | the 16-byte `req_id` |
| plaintext | the result bytes in the format the PKCS#11 mechanism returns (§3) |
| `sealed_result` | `enc ‖ ciphertext`: 65-byte encapsulated key (uncompressed point) followed by the AEAD output, which ends with the 16-byte tag. Total = 65 + len(plaintext) + 16. |

Single-shot `Seal` / `Open`, one message per context. The provider generates the reply key pair with `GenerateKeyPair` from the OS CSPRNG for each request, keeps the private key in a `Zeroizing` buffer, and drops it after a successful open, a verification failure or the deadline. Whichever comes first, it never reuses one.

## 8. Relay HTTP authentication

Every authenticated relay call carries:

| Header | Value |
|---|---|
| `X-Relay-Key` | fingerprint of the signing key (a client identity key, or a device's relay-auth key, §8.4) |
| `X-Relay-Time` | Unix seconds, ASCII decimal, no leading zeros |
| `X-Relay-Nonce` | 16 random bytes from the OS CSPRNG, base64 (24 characters) |
| `X-Relay-Signature` | base64 of the 64-byte signature (§1.4) |

Signed bytes (`hash(body)` is SHA-256 of the exact body bytes; an empty body hashes to SHA-256 of the empty string):

```
"relay-pkcs11/relay-auth/v1" || 0x00 || METHOD || 0x00 || path-and-query || 0x00
  || time || 0x00 || nonce(16 raw bytes) || 0x00 || SHA-256(body)
```

- `METHOD`: uppercase ASCII, e.g. `GET`.
- `path-and-query`: the request target in origin form exactly as sent, e.g. `/v1/requests/9f2c…/result?wait=30`; no scheme or host.
- `time`: the header's ASCII digits.

The relay rejects:

- an unknown key;
- `|now − time| > 60 s`;
- a bad signature;
- a nonce already seen for that key within the last 120 s (twice the skew, so a nonce cannot be reused while its timestamp is still acceptable).

Example: an empty-body `GET /v1/requests/9f2c4e1a7b3d5f60a1b2c3d4e5f60718/result?wait=30` at time `1794744000` (2026-11-15T12:00:00Z) with nonce `00112233445566778899aabbccddeeff` (header `ABEiM0RVZneImaq7zN3u/w==`) signs these 152 bytes:

```
72656c61792d706b637331312f72656c61792d617574682f7631 00   "relay-pkcs11/relay-auth/v1" 00
474554 00                                                 "GET" 00
2f76312f72657175657374732f39663263346531613762336435663630613162326333643465356636303731382f726573756c743f776169743d3330 00
                                                          path-and-query 00
31373934373434303030 00                                   "1794744000" 00
00112233445566778899aabbccddeeff 00                       nonce 00
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
                                                          SHA-256("")
```

Envelope bodies (`POST /v1/requests`, `POST /v1/requests/{id}/response`, and the result of `GET …/result`) are `application/cbor`, carrying the envelope's exact bytes. The relay stores and forwards them byte for byte.

### 8.4 Device relay-auth key

A device may authenticate its relay calls with a separate P-256 key instead of its device key. That lets the device key require a biometric for every signature (Secure Enclave `.biometryCurrentSet`) without one for every poll. The device key vouches for the auth key once, at enrollment, by signing these bytes (signature per §1.4):

```
"relay-pkcs11/auth-key/v1" || 0x00 || device_id || 0x00 || fingerprint(auth_key)
```

The registration (`POST /v1/devices`, §10) then carries `auth_key` (base64 SPKI) and `auth_key_sig` (base64, 64 bytes), and is itself signed by the auth key. The relay checks the binding with `relay_core::relay_auth::verify_auth_key_binding` and authenticates that device's later calls with the auth key only. Without `auth_key` the device key authenticates, as before.

The auth key carries no trust for clients: responses are still signed by the attested device key, so a copied auth key can poll the device's queue (which the relay sees anyway) but cannot answer a request. This is relay hygiene, like the rest of §8.

### 8.5 Device admin-auth key

A second P-256 key, generated at enrollment like the relay-auth key, but in the Secure Enclave with access control `.privateKeyUsage` + `.biometryCurrentSet` and accessibility `WhenUnlockedThisDeviceOnly`. The device key vouches for it once, over:

```
"relay-pkcs11/admin-auth-key/v1" || 0x00 || device_id || 0x00 || fingerprint(admin_key)
```

The registration (`POST /v1/devices`, §10) carries `admin_key` (base64 SPKI) and `admin_key_sig` (base64, 64 bytes). The relay checks the binding with `relay_core::relay_auth::verify_admin_key_binding` and stores the key. The calls marked "admin key" in §10 must carry §8 headers signed by this key, and are refused with 403 `AdminKeyRequired` otherwise. Every other device call is refused if signed with it.

The app evaluates one `LAContext` when a Clients or Approvers screen opens and passes it to each admin-key signature (`kSecUseAuthenticationContext`). It invalidates the context after 3 600 s or when the app moves to the background, whichever comes first. During an approval, the approval's own context signs any grant post the approval makes. The time limit is enforced by the app: the Secure Enclave checks only that a biometric happened in that context.

Like the relay-auth key, the admin-auth key carries no trust for clients or other approvers. It gates access to listings and changes at the relay; every grant, revocation and attestation fetched with it is verified on the device.

## 9. Manifest

### 9.1 Files

- `manifest.json`: UTF-8 JSON, at most 1 MiB.
- `manifest.json.asc` (armored) or `manifest.json.sig` (binary): an OpenPGP detached signature over the **exact bytes** of `manifest.json`.

The signature is checked **before** any JSON parsing. Rules for it:

- exactly one signature packet, of signature type `0x00` (binary document). `gpg --detach-sign` produces this. Type `0x01` (canonical text) is rejected, because it signs line-ending-normalised text rather than the exact bytes;
- made by the configured signer's primary key, or by a subkey that has the signing flag and a valid binding signature from that primary;
- hash algorithm SHA-256, SHA-384 or SHA-512 (SHA-1 and MD5 are rejected);
- signature creation time not later than `now + skew`;
- no revocation check, as the spec says. **[proposal]** The signer key's own expiry is also ignored, for the same reason: headless clients cannot learn about a new key anyway, and `valid_until` already bounds staleness.

### 9.2 JSON schema

```json
{
  "v": 1,
  "version": 7,
  "issued_at": 1794700800,
  "valid_until": 1797292800,
  "require_hardware_attestation": true,
  "max_attestation_window_secs": 604800,
  "max_client_grant_window_secs": 2592000,
  "revoked_clients": ["sha256:9b2e…"],
  "revoked_devices": [],
  "keys": [
    {
      "fingerprint": "sha256:4f1c…",
      "role": "encrypt",
      "label": "openbao-unseal",
      "id": "01",
      "token": "yubikey-12345678",
      "algorithm": "rsa-4096",
      "public_key": "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA…"
    }
  ]
}
```

| Field | Type | Rules |
|---|---|---|
| `v` | integer | `1` |
| `version` | integer | ≥ 1; monotonic |
| `require_hardware_attestation` | bool | Required. When true, every `attest` key must carry a valid `hardware_attestation` (§9.4) |
| `max_attestation_window_secs` | integer | Required. 60–31 536 000. The longest `not_after − not_before` accepted for an attestation (§5.1 step 5) |
| `max_client_grant_window_secs` | integer | Required. 60–31 536 000. The longest `window_secs` accepted in a client grant (§12.2) |
| `revoked_clients` | array, optional | 0–1 024 client identity-key fingerprints (§1.1), sorted bytewise, no duplicates. Absent means empty. The relay refuses these clients and approvers deny their requests (`client_revoked`) |
| `revoked_devices` | array, optional | 0–1 024 device-key fingerprints, sorted bytewise, no duplicates. Absent means empty. The relay refuses these devices; providers reject their responses (§6.2 check 1) |
| `issued_at`, `valid_until` | integer | Unix seconds, `issued_at < valid_until`. The spec's table shows dates, which `relayctl manifest show` displays; on the wire they are integers, per the defaults table. |
| `keys` | array | 0–64 entries; no two with the same `fingerprint` |
| `keys[].fingerprint` | string | §1.1 |
| `keys[].role` | string | `sign`, `auth`, `encrypt` or `attest`; anything else is rejected |
| `keys[].label` | string | 1–128 bytes UTF-8; becomes `CKA_LABEL`; unique within its token |
| `keys[].id` | string | 2–128 lowercase hex characters (1–64 bytes); becomes `CKA_ID` as raw bytes (`"01"` → `0x01`); unique within its token |
| `keys[].token` | string | 1–32 bytes UTF-8 (the `CK_TOKEN_INFO.label` limit); groups keys into slots |
| `keys[].algorithm` | string | §2; must match `public_key` and be allowed for `role` |
| `keys[].public_key` | string | base64 DER SPKI (§2); `fingerprint` must equal `fingerprint(public_key)` |
| `keys[].hardware_attestation` | object, optional | `{"format": "yubikey-piv", "chain": [base64 DER, …]}`: 2–4 certificates, leaf first, root excluded, each at most 2 KiB DER; any other `format` is rejected. Verified per §9.4 |

Parsing is strict: unknown fields, duplicate JSON object keys, non-integer numbers, and integers outside 0–2⁶⁴−1 are all rejected.

### 9.3 Freshness (`verify_manifest(bytes, signature, signer, policy, cached, now, skew)`)

1. Verify the OpenPGP signature (§9.1).
2. Parse and validate the JSON (§9.2), including `fingerprint(public_key) == fingerprint` and `algorithm` against `public_key` for every key.
2a. Check hardware attestation against `policy` (§9.4).
3. Reject `now > valid_until + skew` as expired.
4. With a cached copy, reject `version < cached.version` as a rollback, and `version == cached.version` with different bytes as an error. The same version with identical bytes is accepted, which is the normal refetch.

On any failure the caller keeps a valid cached copy if it has one (Failure handling table). The cached copy is re-checked against step 3 every time it is used.

### 9.4 Hardware attestation (`verify_piv_attestation(chain, public_key, roots, now)`)

YubiKey PIV attestation, firmware 5.7.4 and later. The chain, leaf first, is: the attestation certificate for the slot (from `GET ATTESTATION`, INS `F9`); the card's factory `F9` certificate (data object `5FFF01`); `Yubico PIV Attestation {A,B,B2} 1`; `Yubico Attestation Intermediate {A,B} 1`. The root, `Yubico Attestation Root 1`, is built in and never travels in the manifest.

1. Path validation with `rustls-webpki`:
   - trust anchor: the built-in root;
   - intermediates: the chain after the leaf;
   - time: `now`, with no skew; Yubico's certificates are valid until 9999;
   - signature algorithms: RSA PKCS#1 v1.5 (2048–8192 bits) with SHA-256/384/512, and ECDSA P-256/SHA-256 and P-384/SHA-384;
   - extended key usage: not checked; Yubico's chains do not use it, and the PIV branch and the leaf extensions decide;
   - no revocation checking.

   webpki checks signatures, issuer chaining, CA flags, path length, validity and unknown critical extensions.
2. The verified path must include an intermediate whose subject common name starts with `Yubico PIV Attestation `. This excludes the root's FIDO, OpenPGP, Secure Domain and YubiHSM branches.
3. The leaf's SubjectPublicKeyInfo must equal the key's `public_key` byte for byte.
4. The leaf extensions under `1.3.6.1.4.1.41482.3` must be present and well formed:
   - `.3`: firmware, 3 bytes, at least 5.7.4;
   - `.7`: serial, a DER INTEGER that fits a u32;
   - `.8`: PIN policy then touch policy, 1 byte each, values 1–3.

   `.9` (form factor) is read if present.

Policy, applied in step 2a of §9.3:

- any key's chain fails steps 1–4 → the manifest is invalid;
- an `attest` key whose chain shows touch other than `always` (`02`), or PIN policy `never` (`01`) → invalid;
- the manifest's `require_hardware_attestation` is true and an `attest` key has no chain → invalid.

The policy's roots are Yubico's, replaced only by a test-only `roots_file`. A failure in a cached copy's chain also makes that copy unusable.

## 10. Relay API bodies

While the relay's manifest signer is unusable (§11.4), every call below except `GET /v1/keys` (which returns an empty list) and `GET /v1/devices/{id}/pending` (which returns nothing) fails with 503 `ManifestSignerUnusable`, and pending requests are cancelled. `GET /v1/manifest`, `/v1/manifest.asc`, `/v1/manifest-signer.asc` and `/v1/relay-ca.pem` are unauthenticated and always served.

These are not signed messages: the relay is untrusted and every field is a hint. Every call except `/healthz` and `/metrics` carries relay-auth headers (§8). Binary values in JSON are base64 (§1.1). Errors are `{"error": "<Kind>", "detail": "<text>"}` with the HTTP status shown.

| Call | Caller (auth key) | Body → response |
|---|---|---|
| `GET /v1/keys` | paired client | → `{"keys": [{"public_key", "token", "devices", "last_seen"}]}`, only the keys this client was approved for. The provider recomputes each fingerprint, keeps only manifest keys, and ignores `token`. A relay configured with a manifest lists only keys that the manifest gives a non-`attest` role, held by devices whose attestation a manifest `attest` key signed (window not checked), and lists none while its manifest is invalid. Requests are routed by the same rule. |
| `POST /v1/requests` | paired client | request envelope (`application/cbor`) → `202 {"req_id"}`. Rejections: 401 `RequestSignatureInvalid` or relay auth, 403 `UnpairedClient` / `KeyNotApproved`, 409 `DuplicateRequestId`, 410 `RequestExpired`, 422 `NoDevice`, 429 `TooManyPending` / `RateLimited`. |
| `GET /v1/requests/{id}/result?wait=N` | the submitting client | → `200` response envelope (`application/cbor`), delivered once, after which the request is deleted; `204` if nothing yet after `N` ≤ 30 s; `404` once expired. |
| `POST /v1/requests/{id}/response` | a device addressed by the request | response envelope → `204`; 409 `AlreadyAnswered` (the first response wins); 404 if expired. |
| `POST /v1/clients/pending` | the new client's key, which is in the body (proof of possession) | `{"client_id", "public_key", "host"}` → `202 {"status": "pending", "code"}`, or `200 {"status": "approved"}` if already paired. Allowed networks only, at most 4 pending, dropped after 10 min. |
| `GET /v1/clients/self` | a pending or paired client | → `{"status": "pending", "client_id", "code"}` or `{"status": "approved", "client_id", "approved_keys"}`. |
| `POST /v1/clients/{id}/approval` | any registered device (relay-auth key; the grant carries the trust) | `{"grant"}` (base64 CBOR, §12.1) → `204`. The grant's `client_key` must be the pending client key whose code the person compared, `client_id` must equal `{id}`, and `seq` must be 1. The relay runs `verify_client_grant_signer` (§12.2) and answers 400 `GrantInvalid` on failure. |
| `GET /v1/clients` | a registered device (admin key) | → `{"clients": [{"client_id", "host", "grant", "last_seen"}], "revocations": [revocation]}`, with `grant` and each revocation as base64 CBOR, and every live revocation (§12.3). |
| `POST /v1/clients/{id}/grant` | a registered device (admin key, or the relay-auth key for a renewal made during an approval) | `{"grant"}` → `204`. Checked as for the approval; `client_key` must be the stored client's, and `seq` must be greater than the stored grant's (409 `GrantStale` otherwise). Replaces the client's routable keys with the grant's `keys`. |
| `POST /v1/clients/{id}/revocation` | a registered device (admin key) | `{"revocation"}` (base64 CBOR, §12.3) → `204`. The relay verifies it (§12.3), deletes the client, refuses its calls with 403 `ClientRevoked`, and keeps the revocation until `not_after` of the last grant it cancels. 400 `RevocationInvalid` on failure. |
| `GET /v1/devices` | a registered device (admin key) | → `{"devices": [{"device_id", "device_key", "attestation", "keys": [{"public_key", "token"}], "push_kind", "last_seen"}]}`. `push_kind` only, never a push token or topic. |
| `POST /v1/devices` | the auth key in the body, or else the device key | `{"device_id", "device_key", "attestation", "keys": [{"public_key", "token"}], "push": {"kind": "none"} \| {"kind": "ntfy", "topic"} \| {"kind": "apns", "token"}, "auth_key"?, "auth_key_sig"?, "admin_key"?, "admin_key_sig"?, "setup_link"?}` → `204`. `setup_link` is required for a device id the relay does not hold (also after revocation) and checked per §11.3, with 400 `SetupLinkInvalid` / `SetupLinkWrongSigner` / `SetupLinkSignatureInvalid` / `SetupLinkExpired` / `SetupLinkWrongDevice` / `SetupLinkUsed` / `SetupLinkRequired`; 400 `BadAuthKey` when the binding (§8.4) does not verify, and 400 `BadAdminKey` for the admin-key binding (§8.5); 403 `DeviceRevoked` when `device_key`'s fingerprint is in the manifest's `revoked_devices`. A device id stays bound to its first key until `relay-server admin devices revoke`. The relay checks that the attestation decodes and names this device and key. When it has a valid manifest it also checks that one of the manifest's `attest` keys signed it (§5.1 steps 1–3, `verify_attestation_signer`; not the window, so an expired device can re-register after renewing), and rejects a failure with 400 `AttestationInvalid`. Clients check it again either way. |
| (APNs) | the relay | To a device registered with `{"kind": "apns", "token"}`: HTTP/2 POST `/3/device/<token>` with an ES256 provider token (refreshed every 30 minutes), `apns-push-type: alert`, `apns-priority: 10`, `apns-expiration` = now + the relay's max TTL, and the fixed body `{"aps":{"alert":{"title":"Relay Approver","body":"1 pending request"},"sound":"default"}}`. On 410, or 400 `BadDeviceToken` / `DeviceTokenNotForTopic`, the relay forgets that device's token. |
| `GET /v1/devices/{id}/pending?wait=N` | that device | → `{"requests": [envelope], "grants": [grant], "revocations": [revocation], "pairings": [{"client_id", "public_key", "fingerprint", "host", "code", "received_at"}]}`. `grants` holds the latest stored grant for each client with a request in `requests`; `revocations` holds every live revocation (§12.3). Both are base64 CBOR. |
| `GET /v1/devices/{id}/ws` | that device (headers on the upgrade) | WebSocket. The relay sends `{"type": "pending"}` when there may be something to fetch. |

**Manifest revocations at the relay.** With a valid manifest, the relay refuses every call authenticated by a client whose identity-key fingerprint is in `revoked_clients` (403 `ClientRevoked`), and every call from a device whose device-key fingerprint is in `revoked_devices`, whichever of its keys signs it (403 `DeviceRevoked`). When it loads such a manifest it deletes their registrations, stops routing to listed devices, and discards any response from one. `POST /v1/requests` also returns 403 `ClientRevoked` for a client with a stored revocation, and 403 `KeyNotApproved` for a key outside the client's latest grant.

### 10.1 Pairing code

The pairing code is a diceware-style phrase derived from the client's identity key, so a person can read it from a log and compare it on the approval screen.

- Wordlist: the EFF large wordlist (7 776 words, CC BY 3.0), vendored as `crates/relay-core/data/eff_large_wordlist.txt` and checked against its published SHA-256 at build time.
- Derivation: let `n` be the first 8 bytes of `SHA-256(client SPKI)` read as a big-endian u64. For `i` in 0..4: `word[i] = list[n mod 7776]`, then `n = n div 7776`.
- Display: the four words in that order, lowercase, joined by `-`, such as `word-word-word-word`; golden vectors carry real examples.
- Strength: 4 × log₂ 7776 ≈ 51.7 bits, above the 50-bit minimum. 2⁶⁴ is not a multiple of 7776⁴, which biases the first word by less than one part in 5 000, a negligible loss.
- The approver compares the whole phrase. Any change that drops the derived strength below 50 bits needs a new decision.

## 11. Setup link

### 11.1 Form

```
poh://setup?v=1&relay=<url>&ca=<b64url>&signer=<FPR>&device=<id>&iat=<secs>&exp=<secs>&sig=<b64url>
```

| Param | Rules |
|---|---|
| `v` | `1` |
| `relay` | `https://` with host and optional port only: no path, query, fragment or userinfo |
| `ca` | optional: base64url (no padding, 43 characters) of SHA-256 of the relay CA's SubjectPublicKeyInfo; absent for a publicly trusted relay |
| `signer` | OpenPGP fingerprint, uppercase hex: 40 characters (v4) or 64 (v6) |
| `device` | device id (§1.1) |
| `iat`, `exp` | Unix seconds, `iat < exp <= iat + 604800` |
| `sig` | base64url (no padding) of one binary OpenPGP signature packet |

The parameters appear in exactly this order, each once (`ca` may be left out), with no others. Values use only `A–Z a–z 0–9 - . _ ~ : /`; `%` anywhere rejects the link. At most 4 096 bytes.

### 11.2 Signature (`verify_setup_link(link, signer, now, skew)`)

- **Signed bytes:** the link's characters before `&sig=`, as UTF-8. They must start with `poh://setup?v=1&`, which works as the context string: no manifest (JSON) can be mistaken for them, nor they for a manifest.
- **Signature rules:** those of §9.1: exactly one signature packet, type `0x00`, SHA-256 or stronger, by the signer's primary key or a signing subkey with a valid binding, creation time not after `now + skew`.
- **Signer:** `fingerprint(signer) == signer` param.
- **Time:** `iat − skew <= now <= exp + skew`, else `SetupLinkExpired`.
- **Link id:** SHA-256 of the signed bytes, hex. It never covers `sig`: some signature schemes allow a second valid signature over the same bytes without the private key, and that must not make a used link new again.

### 11.3 Relay checks at registration

For a device id it does not hold, in order: §11.1 form (`SetupLinkInvalid`); `signer` equals its `manifest_signer` (`SetupLinkWrongSigner`); §11.2 signature (`SetupLinkSignatureInvalid`); signer status usable (§11.4, else 503 `ManifestSignerUnusable`); time (`SetupLinkExpired`); `device == device_id` (`SetupLinkWrongDevice`); link id not in `used_setup_links` (`SetupLinkUsed`); then the attestation checks. The link id is stored in `used_setup_links`, with the device and in the audit log, in the same transaction as the device. Entries may be pruned after `exp + skew`.

### 11.4 Signer status (`signer_status(copies, now)`)

Over every copy of the signer key seen (the relay's file, keys.openpgp.org):

- **Revoked** if any copy has a key-revocation signature on the primary key that verifies under it, or if the primary key cannot sign and every signing subkey's binding is revoked by a verifying revocation.
- **Expired** if, taking the newest verifying self-signature across all copies, the primary key's expiry is not after `now`, or if the primary key cannot sign and every signing subkey's newest binding has expired.
- Otherwise **usable**.

The relay recomputes it from its file at least every minute, fetches `https://keys.openpgp.org/vks/v1/by-fingerprint/<FPR>` every 900 seconds by default, keeps its last status when the keyserver is unreachable or does not have the key, and persists a revocation until `manifest_signer` changes to another fingerprint. The app applies the same function at setup and refuses a revoked or expired key.

## 12. Client grants and revocations

### 12.1 Client grant

Signed by a manifest `attest` key (ECDSA P-256), on the card like an attestation (§5: the approver sends `SHA-256(signed_bytes)` with `GENERAL AUTHENTICATE`). Context string `relay-pkcs11/client-grant/v1`, signature field `sig`.

| Key (canonical order) | Type | Rules |
|---|---|---|
| `v` | uint | `1` |
| `seq` | uint | ≥ 1; 1 at pairing; each change or renewal adds 1 |
| `sig` | bstr | 64 bytes, ECDSA P-256 `r ‖ s` |
| `keys` | array of tstr | 1–64 key fingerprints, sorted bytewise, no duplicates |
| `client_id` | tstr | §1.1 |
| `issued_at` | uint | Unix seconds |
| `not_after` | uint | must equal `issued_at + window_secs` |
| `client_key` | bstr | SPKI of the client identity key (§2) |
| `approved_by` | tstr | device id of the approving device; display only, not trusted |
| `window_secs` | uint | 60–31 536 000 |
| `attest_key_fingerprint` | tstr | fingerprint of the signing attest key |

### 12.2 Verification (`verify_client_grant(grant, manifest, now, skew)`)

1. Decode strictly. Find `attest_key_fingerprint` among the manifest's keys with role `attest`, and verify `sig` over `signed_bytes` with it; otherwise `GrantInvalid`.
2. Require `not_after = issued_at + window_secs` and `window_secs ≤ manifest.max_client_grant_window_secs`; otherwise `GrantInvalid`.
3. Every fingerprint in `keys` is a manifest key with a role other than `attest`; otherwise `GrantInvalid`.
4. `fingerprint(client_key)` is not in the manifest's `revoked_clients`; otherwise `ClientRevoked`.
5. Time: require `issued_at − skew ≤ now`, otherwise `GrantInvalid` (not yet valid). If `now > not_after + skew`, the grant verifies but is returned as **lapsed**: the approver shows its client's requests only with the renewal notice.

`verify_client_grant_signer(grant, manifest)` runs steps 1–3, without revocation or time; the relay uses it.

An approver keeps, per client key, the verified grant with the highest `seq`. It refuses a grant whose `seq` is lower than or equal to one it holds unless the two are byte-identical, and any grant that a held revocation cancels (§12.3).

### 12.3 Client revocation

Signed by a manifest `attest` key. Context string `relay-pkcs11/client-revocation/v1`, signature field `sig`.

| Key (canonical order) | Type | Rules |
|---|---|---|
| `v` | uint | `1` |
| `seq` | uint | the highest grant `seq` it cancels |
| `sig` | bstr | 64 bytes, ECDSA P-256 `r ‖ s` |
| `issued_at` | uint | Unix seconds |
| `client_key` | bstr | SPKI of the client identity key |
| `attest_key_fingerprint` | tstr | fingerprint of the signing attest key |

`verify_client_revocation(revocation, manifest)`: decode strictly, then verify `sig` with the manifest `attest` key named by `attest_key_fingerprint`; otherwise `RevocationInvalid`. There is no time check. A device keeps a verified revocation for good and refuses every grant for `client_key` with `seq` at or below it.

A revocation is **live** at the relay until `now` passes `not_after` of the last grant it cancels. The relay sends every live revocation with each `/pending` response and in `GET /v1/clients`, with no acknowledgement. A compromised relay can withhold one; the bound is the grant window and the person approving (spec, Enrollment).

## Departures from the spec

Each departure was approved by Brian on 2026-11-15 and is recorded in `docs/decisions.md`. `docs/spec.md` has not been edited.

1. **Manifest keys carry `public_key`** (§9.2). The manifest is now where the attestation's verifier gets the attest public key (§5.1), and where the provider gets every hardware key's public key. The relay's advertisement only says which manifest keys are reachable.
2. **Responses carry an optional `reason`** (§6, §6.1), covered by `device_sig`.
3. **Relay auth carries `X-Relay-Nonce`** (§8), and the relay tracks replays per (key, nonce).
4. **Check 5 runs after opening the result** (§6.2): checks 1–4, then open, then check 5.
5. **The pairing code is a four-word diceware phrase** (§10.1), at least 50 bits, instead of the defaults table's 40-bit base32 code.

Smaller choices made here, which are recorded in `docs/decisions.md`: RSA exponent 65537 only; uncompressed P-256 points only; OAEP SHA-256/MGF1-SHA256 only; `input` capped at 32 KiB, with `CKR_DATA_LEN_RANGE` beyond that; exactly one OpenPGP signature packet of type `0x00`; SHA-256 or stronger in OpenPGP; signer-key expiry ignored; `responded_at` informational only; the attestation embedded as a byte string; manifest timestamps as integers; strict decoding (unknown fields rejected) everywhere.
