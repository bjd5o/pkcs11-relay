//! Regenerates the golden vectors. Not part of the normal test run:
//!
//!     cargo test -p relay-core --test gen_vectors -- --ignored
//!     crates/relay-core/tests/vectors/pgp/make.sh
//!
//! Regenerating replaces every key and vector; commit the result together.

mod common;

use common::*;
use relay_core::attestation::UnsignedAttestation;
use relay_core::request::UnsignedRequest;
use relay_core::response::{Reason, UnsignedResponse};
use relay_core::{Mechanism, Op, Role};
use serde_json::{json, Value};

fn write(kind: &str, name: &str, v: Value) {
    let path = dir().join(kind).join(format!("{name}.json"));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, serde_json::to_string_pretty(&v).unwrap() + "\n").unwrap();
}

fn h(b: &[u8]) -> String {
    hex::encode(b)
}

#[test]
#[ignore]
fn generate() {
    generate_fixture();
    let fx = load();
    attestation_vectors(&fx);
    request_vectors(&fx);
    response_vectors(&fx);
}

/// Only the hardware attestation vectors (wire-format §9.4), leaving every other vector as is:
///
///     cargo test -p relay-core --test gen_vectors generate_hw_attestation -- --ignored
#[test]
#[ignore]
fn generate_hw_attestation() {
    use relay_core::hw_attestation::testing::{HierarchyOptions, LeafOptions, TestHierarchy};
    let key = |seed: u8| {
        let k = p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
        p256::pkcs8::EncodePublicKey::to_public_key_der(k.verifying_key())
            .unwrap()
            .into_vec()
    };
    let attest = key(0x41);
    let hier = TestHierarchy::new();
    let d = hier.device(12_345_678, (5, 7, 4));
    let good = LeafOptions::for_device(&d, 2, 2);
    let v = |name: &str, desc: &str, root: &[u8], chain: &[Vec<u8>], pk: &[u8], expect: Value| {
        write(
            "hw-attestation",
            name,
            json!({
                "description": desc,
                "root": h(root),
                "chain": chain.iter().map(|c| h(c)).collect::<Vec<_>>(),
                "public_key": h(pk),
                "now": NOW,
                "expect": expect,
            }),
        );
    };
    let root = hier.root_der();
    v(
        "valid",
        "leaf, F9, PIV attestation CA, intermediate; PIN once, touch always",
        &root,
        &d.chain(0x85, &attest, &good),
        &attest,
        json!({"serial": 12_345_678, "firmware": "5.7.4", "pin_policy": "once", "touch_policy": "always", "form_factor": 3}),
    );
    v(
        "wrong-key",
        "a valid chain for another key",
        &root,
        &d.chain(0x85, &key(0x42), &good),
        &attest,
        json!("HardwareAttestationInvalid"),
    );
    v(
        "other-root",
        "a valid chain checked against another root",
        &TestHierarchy::new().root_der(),
        &d.chain(0x85, &attest, &good),
        &attest,
        json!("HardwareAttestationInvalid"),
    );
    let old = hier.device(12_345_678, (5, 7, 3));
    v(
        "firmware-5.7.3",
        "firmware older than 5.7.4",
        &root,
        &old.chain(0x85, &attest, &LeafOptions::for_device(&old, 2, 2)),
        &attest,
        json!("HardwareAttestationInvalid"),
    );
    let opgp = TestHierarchy::with_options(HierarchyOptions {
        branch_cn: "Yubico OPGP Attestation Test 1".into(),
        ..Default::default()
    });
    let od = opgp.device(12_345_678, (5, 7, 4));
    v(
        "not-piv-branch",
        "issued through an OpenPGP attestation CA",
        &opgp.root_der(),
        &od.chain(0x85, &attest, &LeafOptions::for_device(&od, 2, 2)),
        &attest,
        json!("HardwareAttestationInvalid"),
    );
}

/// Only the setup-link vectors (wire-format §11):
///
///     cargo test -p relay-core --test gen_vectors generate_setup_link -- --ignored
#[test]
#[ignore]
fn generate_setup_link() {
    use relay_core::setup_link::SetupLinkDraft;
    // rPGP signs at the real time, so these vectors are anchored at generation time.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let k = relay_core::PgpSecretKey::generate("setup link vectors <links@test.invalid>").unwrap();
    let signer = k.public_armored().unwrap();
    let fpr = relay_core::ManifestSigner::from_bytes(signer.as_bytes())
        .unwrap()
        .fingerprint();
    let d = SetupLinkDraft {
        relay: "https://10.0.0.170:8443".into(),
        ca: Some(relay_core::setup_link::spki_pin(b"example CA SPKI")),
        signer: fpr,
        device: "brian-iphone".into(),
        iat: now - 60,
        exp: now + 840,
    };
    let bytes = d.signed_bytes().unwrap();
    let good = d
        .with_signature(&k.sign_detached_binary(bytes.as_bytes()).unwrap())
        .unwrap();
    let id = relay_core::setup_link::parse(&good).unwrap().id();
    let v = |name: &str, desc: &str, link: &str, now: u64, expect: &str| {
        write(
            "setup-link",
            name,
            json!({"description": desc, "link": link, "signer": signer, "now": now, "skew": SKEW, "expect": expect, "id": id}),
        );
    };
    v(
        "valid",
        "a link inside its window, signed by the signer",
        &good,
        now,
        "ok",
    );
    v(
        "expired",
        "the same link after exp + skew",
        &good,
        d.exp + SKEW + 1,
        "SetupLinkExpired",
    );
    v(
        "altered",
        "device changed after signing",
        &good.replacen("brian-iphone", "brian-ipad", 1),
        now,
        "SetupLinkSignatureInvalid",
    );
    v(
        "percent-encoded",
        "a URL rewritten with percent-encoding",
        &good.replacen("10.0.0.170", "10%2E0.0.170", 1),
        now,
        "SetupLinkInvalid",
    );
}

fn attestation_vectors(fx: &Fx) {
    let a = |name: &str, desc: &str, bytes: &[u8], now: u64, expect: &str| {
        write(
            "attestation",
            name,
            json!({"description": desc, "attestation": h(bytes), "now": now, "skew": SKEW, "expect": expect}),
        );
    };
    let good = fx.attestation();
    a(
        "valid",
        "statement from the manifest attest key, inside its window",
        good.bytes(),
        NOW,
        "ok",
    );
    a(
        "skew-boundary-after",
        "now = not_after + skew: still accepted",
        good.bytes(),
        VALID_UNTIL + SKEW,
        "ok",
    );
    a(
        "skew-boundary-before",
        "now = not_before - skew: still accepted",
        good.bytes(),
        ISSUED_AT - SKEW,
        "ok",
    );
    a(
        "expired",
        "now = not_after + skew + 1",
        good.bytes(),
        VALID_UNTIL + SKEW + 1,
        "AttestationExpired",
    );
    a(
        "not-yet-valid",
        "now = not_before - skew - 1",
        good.bytes(),
        ISSUED_AT - SKEW - 1,
        "AttestationExpired",
    );
    let rogue = fx.attestation_with(&fx.rogue_attest, &fx.device, ISSUED_AT, VALID_UNTIL);
    a(
        "unknown-signer",
        "signed by a P-256 key the manifest does not list",
        rogue.bytes(),
        NOW,
        "AttestationUnknownSigner",
    );
    let by_sign_key = fx.attestation_with(&fx.sign, &fx.device, ISSUED_AT, VALID_UNTIL);
    a(
        "signer-not-attest-role",
        "signed by a manifest key whose role is sign, not attest",
        by_sign_key.bytes(),
        NOW,
        "AttestationUnknownSigner",
    );
    let mut sig = good.sig;
    sig[10] ^= 1;
    let bad = good.fields.clone().with_signature(sig);
    a(
        "bad-signature",
        "names the attest key but the signature does not verify",
        bad.bytes(),
        NOW,
        "AttestationInvalid",
    );
    // "v": 1 re-encoded as 0x18 0x01: same value, not canonical.
    let mut nc = good.bytes().to_vec();
    assert_eq!(&nc[1..4], &[0x61, 0x76, 0x01]);
    nc.splice(3..4, [0x18, 0x01]);
    a(
        "non-canonical",
        "valid statement with a non-shortest integer encoding",
        &nc,
        NOW,
        "AttestationInvalid",
    );
    let st = UnsignedAttestation::new(
        "test-device",
        fx.device.public_key(),
        ISSUED_AT,
        VALID_UNTIL,
        fx.attest.public_key().fingerprint().clone(),
    )
    .unwrap();
    let mut tbs_mismatch = st.clone();
    tbs_mismatch.device_id = "other-device".into();
    let swapped = tbs_mismatch.with_signature(fx.attest.sign(&st.to_be_signed()));
    a(
        "field-changed-after-signing",
        "device_id changed after the attest key signed",
        swapped.bytes(),
        NOW,
        "AttestationInvalid",
    );
}

fn request_vectors(fx: &Fx) {
    let r = |name: &str, desc: &str, bytes: &[u8], now: u64, expect: &str| {
        write(
            "request",
            name,
            json!({"description": desc, "request": h(bytes), "now": now, "skew": SKEW, "expect": expect}),
        );
    };
    let (dec, _) = fx.decrypt_request(b"unseal key");
    r(
        "valid-decrypt",
        "OAEP decrypt on the encrypt key",
        dec.bytes(),
        NOW,
        "ok",
    );
    let (sign, _, _) = fx.sign_request(b"a commit to sign");
    r(
        "valid-sign",
        "ECDSA-SHA256 on the sign key",
        sign.bytes(),
        NOW,
        "ok",
    );
    r(
        "expired",
        "now past expires_at + skew",
        sign.bytes(),
        NOW + 90 + SKEW + 1,
        "RequestExpired",
    );
    r(
        "from-the-future",
        "created_at more than skew ahead of now",
        sign.bytes(),
        NOW - SKEW - 1,
        "RequestExpired",
    );
    let forged = sign
        .fields
        .clone()
        .with_signature(fx.device.sign(&sign.fields.to_be_signed()));
    r(
        "bad-signature",
        "signed by a key other than the paired client's",
        forged.bytes(),
        NOW,
        "RequestSignatureInvalid",
    );
    // Built without UnsignedRequest::new, which would refuse them locally.
    let mut role = sign.fields.clone();
    role.key_fingerprint = fx.key(Role::Sign).fingerprint.clone();
    role.op = Op::Decrypt;
    role.mechanism = Mechanism::RsaPkcsOaep { label: vec![] };
    let role = role
        .clone()
        .with_signature(fx.client.sign(&role.to_be_signed()));
    r(
        "role-violation",
        "decrypt addressed to a sign key",
        role.bytes(),
        NOW,
        "KeyFunctionNotPermitted",
    );
    let mut mech = sign.fields.clone();
    mech.mechanism = Mechanism::Ecdsa;
    let mech = mech
        .clone()
        .with_signature(fx.client.sign(&mech.to_be_signed()));
    r(
        "mechanism-invalid",
        "raw CKM_ECDSA on a sign key (hash-and-sign only)",
        mech.bytes(),
        NOW,
        "MechanismInvalid",
    );
    let mut attest = sign.fields.clone();
    attest.key_fingerprint = fx.key(Role::Attest).fingerprint.clone();
    let attest = attest
        .clone()
        .with_signature(fx.client.sign(&attest.to_be_signed()));
    r(
        "attest-key",
        "a sign operation addressed to the attest key",
        attest.bytes(),
        NOW,
        "KeyFunctionNotPermitted",
    );
    let mut unknown = sign.fields.clone();
    unknown.key_fingerprint = fx.rogue_attest.public_key().fingerprint().clone();
    let unknown = unknown
        .clone()
        .with_signature(fx.client.sign(&unknown.to_be_signed()));
    r(
        "unknown-key",
        "a key the manifest does not list",
        unknown.bytes(),
        NOW,
        "UnknownKey",
    );
    // ECDH (op = derive) on the P-256 encrypt key.
    let (d, _, _) = fx.derive_request(relay_core::mechanism::ckm::CKD_NULL, b"", 32);
    r(
        "valid-derive-null",
        "ECDH with CKD_NULL on the P-256 encrypt key",
        d.bytes(),
        NOW,
        "ok",
    );
    let (d2, _, _) = fx.derive_request(
        relay_core::mechanism::ckm::CKD_SHA256_KDF,
        b"shared info",
        16,
    );
    r(
        "valid-derive-sha256",
        "ECDH with the X9.63 SHA-256 KDF and shared info",
        d2.bytes(),
        NOW,
        "ok",
    );
    let mut off = d.fields.clone();
    off.input[20] ^= 1;
    let off = off
        .clone()
        .with_signature(fx.client.sign(&off.to_be_signed()));
    r(
        "derive-peer-off-curve",
        "ECDH peer key not on the curve",
        off.bytes(),
        NOW,
        "MechanismParamInvalid",
    );
    let mut on_sign = d.fields.clone();
    on_sign.key_fingerprint = fx.key(Role::Sign).fingerprint.clone();
    let on_sign = on_sign
        .clone()
        .with_signature(fx.client.sign(&on_sign.to_be_signed()));
    r(
        "derive-on-sign-key",
        "ECDH addressed to a sign key",
        on_sign.bytes(),
        NOW,
        "KeyFunctionNotPermitted",
    );
    let _ = UnsignedRequest::new; // documented above
}

fn response_vectors(fx: &Fx) {
    #[allow(clippy::too_many_arguments)]
    fn v(
        name: &str,
        desc: &str,
        req: &[u8],
        resp: &[u8],
        reply: &[u8],
        now: u64,
        expect: &str,
        extra: Value,
    ) {
        let mut j = json!({"description": desc, "request": h(req), "response": h(resp), "reply_key": h(reply), "now": now, "skew": SKEW, "expect": expect});
        if let (Value::Object(m), Value::Object(e)) = (&mut j, extra) {
            m.extend(e);
        }
        write("response", name, j);
    }
    let att = fx.attestation();

    let (dec, k) = fx.decrypt_request(b"unseal key");
    let resp = fx.approve(&dec, b"unseal key", &att, &fx.device);
    v(
        "approved-decrypt",
        "approved OAEP decrypt",
        dec.bytes(),
        &resp,
        &k.private_bytes(),
        NOW,
        "approved",
        json!({"result": h(b"unseal key")}),
    );

    let (sign, k, sig) = fx.sign_request(b"a commit to sign");
    let resp = fx.approve(&sign, &sig, &att, &fx.device);
    let ks = k.private_bytes();
    v(
        "approved-sign",
        "approved ECDSA-SHA256 signature, passes check 5",
        sign.bytes(),
        &resp,
        &ks,
        NOW,
        "approved",
        json!({"result": h(&sig)}),
    );
    v(
        "attestation-expired",
        "valid response, attestation past its window",
        sign.bytes(),
        &resp,
        &ks,
        VALID_UNTIL + SKEW + 1,
        "AttestationExpired",
        json!({}),
    );

    let deny = fx.deny(&sign, Some(Reason::UserDenied));
    v(
        "denied",
        "signed denial from an attested device",
        sign.bytes(),
        &deny,
        &ks,
        NOW,
        "denied",
        json!({"reason": "user_denied"}),
    );
    let err = fx.error(&sign, Some(Reason::WrongPin));
    v(
        "error",
        "signed error from an attested device",
        sign.bytes(),
        &err,
        &ks,
        NOW,
        "error",
        json!({"reason": "wrong_pin"}),
    );

    let rogue_att = fx.attestation_with(&fx.rogue_attest, &fx.rogue_device, ISSUED_AT, VALID_UNTIL);
    let resp = fx.approve(&sign, &sig, &rogue_att, &fx.rogue_device);
    v(
        "rogue-attestation",
        "device attested by a key the manifest does not list",
        sign.bytes(),
        &resp,
        &ks,
        NOW,
        "AttestationUnknownSigner",
        json!({}),
    );

    let mut u = UnsignedResponse::approved(&sign, &sig, &att, NOW + 30).unwrap();
    u.device_key_fingerprint = fx.rogue_device.public_key().fingerprint().clone();
    let resp = u
        .clone()
        .with_signature(fx.rogue_device.sign(&u.to_be_signed()));
    v(
        "signer-mismatch",
        "signed by a key other than the attested device key",
        sign.bytes(),
        resp.bytes(),
        &ks,
        NOW,
        "ResponseSignerMismatch",
        json!({}),
    );

    let u = UnsignedResponse::approved(&sign, &sig, &att, NOW + 30).unwrap();
    let resp = u
        .clone()
        .with_signature(fx.rogue_device.sign(&u.to_be_signed()));
    v(
        "bad-device-signature",
        "names the attested device key but another key signed",
        sign.bytes(),
        resp.bytes(),
        &ks,
        NOW,
        "ResponseSignatureInvalid",
        json!({}),
    );

    let (other, _, _) = fx.sign_request(b"a different request");
    let resp = fx.approve(&other, &sig, &att, &fx.device);
    v(
        "wrong-request",
        "a valid response to a different request",
        sign.bytes(),
        &resp,
        &ks,
        NOW,
        "ResponseNotBound",
        json!({}),
    );

    let (der, dk, dres) = fx.derive_request(relay_core::mechanism::ckm::CKD_SHA256_KDF, b"ctx", 32);
    let resp = fx.approve(&der, &dres, &att, &fx.device);
    v(
        "approved-derive",
        "approved ECDH (X9.63 KDF): the derived key, sealed",
        der.bytes(),
        &resp,
        &dk.private_bytes(),
        NOW,
        "approved",
        json!({"result": h(&dres)}),
    );

    let mut wrong = sig.clone();
    wrong[0] ^= 1;
    let resp = fx.approve(&sign, &wrong, &att, &fx.device);
    v(
        "bad-result-signature",
        "attested and bound, but the signature result fails check 5",
        sign.bytes(),
        &resp,
        &ks,
        NOW,
        "ResultSignatureInvalid",
        json!({}),
    );
}

/// Only the client grant and revocation vectors (wire-format §12), leaving every other vector
/// as is:
///
///     cargo test -p relay-core --test gen_vectors generate_client_grants -- --ignored
#[test]
#[ignore]
fn generate_client_grants() {
    use relay_core::cbor::{decode_map, encode, Value};
    use relay_core::grant::{UnsignedGrant, UnsignedRevocation};
    use relay_core::signing::SoftwareKey;

    let fx = load();
    let granted = vec![
        fx.key(Role::Sign).fingerprint.clone(),
        fx.key(Role::Encrypt).fingerprint.clone(),
    ];
    let grant_by = |signer: &SoftwareKey, keys: Vec<relay_core::Fingerprint>, window: u64| {
        let g = UnsignedGrant::new(
            CLIENT_ID,
            fx.client.public_key(),
            keys,
            1,
            window,
            ISSUED_AT,
            "test-device",
            signer.public_key().fingerprint().clone(),
        )
        .unwrap();
        let sig = signer.sign(&g.to_be_signed());
        g.with_signature(sig)
    };
    const WINDOW: u64 = 7 * 86_400;
    let w = |name: &str, desc: &str, bytes: &[u8], now: u64, expect: &str| {
        write(
            "client-grant",
            name,
            json!({"description": desc, "grant": h(bytes), "now": now, "skew": SKEW, "expect": expect}),
        );
    };
    let good = grant_by(&fx.attest, granted.clone(), WINDOW);
    let end = ISSUED_AT + WINDOW;
    w(
        "valid",
        "grant from the manifest attest key, inside its window",
        good.bytes(),
        NOW,
        "ok",
    );
    w(
        "skew-boundary-after",
        "now = not_after + skew: not yet lapsed",
        good.bytes(),
        end + SKEW,
        "ok",
    );
    w(
        "lapsed",
        "now = not_after + skew + 1: verifies, lapsed",
        good.bytes(),
        end + SKEW + 1,
        "lapsed",
    );
    w(
        "skew-boundary-before",
        "now = issued_at - skew",
        good.bytes(),
        ISSUED_AT - SKEW,
        "ok",
    );
    w(
        "not-yet-valid",
        "now = issued_at - skew - 1",
        good.bytes(),
        ISSUED_AT - SKEW - 1,
        "GrantInvalid",
    );
    let rogue = grant_by(&fx.rogue_attest, granted.clone(), WINDOW);
    w(
        "unknown-signer",
        "signed by a P-256 key the manifest does not list",
        rogue.bytes(),
        NOW,
        "GrantInvalid",
    );
    let by_sign = grant_by(&fx.sign, granted.clone(), WINDOW);
    w(
        "signer-not-attest-role",
        "signed by a manifest key whose role is sign",
        by_sign.bytes(),
        NOW,
        "GrantInvalid",
    );
    let mut sig = good.sig;
    sig[10] ^= 1;
    let bad = good.fields.clone().with_signature(sig);
    w(
        "bad-signature",
        "one bit of the signature flipped",
        bad.bytes(),
        NOW,
        "GrantInvalid",
    );
    let mut changed = good.fields.clone();
    changed.seq = 2;
    let changed = changed.with_signature(good.sig);
    w(
        "field-changed-after-signing",
        "seq changed after signing",
        changed.bytes(),
        NOW,
        "GrantInvalid",
    );
    let long = grant_by(&fx.attest, granted.clone(), 30 * 86_400 + 1);
    w(
        "window-too-long",
        "window one second over the manifest's max_client_grant_window_secs",
        long.bytes(),
        NOW,
        "GrantInvalid",
    );
    let unknown_key = grant_by(
        &fx.attest,
        vec![fx.rogue_attest.public_key().fingerprint().clone()],
        WINDOW,
    );
    w(
        "key-not-in-manifest",
        "grants a key the manifest does not list",
        unknown_key.bytes(),
        NOW,
        "GrantInvalid",
    );
    let attest_key = grant_by(
        &fx.attest,
        vec![fx.key(Role::Attest).fingerprint.clone()],
        WINDOW,
    );
    w(
        "key-is-attest",
        "grants the manifest's attest key",
        attest_key.bytes(),
        NOW,
        "GrantInvalid",
    );
    // Decode-level failures: edit the CBOR directly (the signature no longer matters).
    let edited = |f: &dyn Fn(&mut std::collections::BTreeMap<String, Value>)| {
        let mut m = decode_map(good.bytes()).unwrap();
        f(&mut m);
        encode(&Value::Map(m))
    };
    let mut unsorted: Vec<String> = granted.iter().map(|k| k.as_str().to_string()).collect();
    unsorted.sort();
    unsorted.reverse();
    w(
        "keys-unsorted",
        "keys out of order",
        &edited(&|m| {
            m.insert("keys".into(), Value::TextArray(unsorted.clone()));
        }),
        NOW,
        "GrantInvalid",
    );
    w(
        "not-after-mismatch",
        "not_after is not issued_at + window_secs",
        &edited(&|m| {
            m.insert("not_after".into(), Value::Uint(end + 1));
        }),
        NOW,
        "GrantInvalid",
    );
    w(
        "keys-empty",
        "an empty key list",
        &edited(&|m| {
            m.insert("keys".into(), Value::TextArray(vec![]));
        }),
        NOW,
        "GrantInvalid",
    );
    let mut noncanon = good.bytes().to_vec();
    // `v` = 1 written as 0x18 0x01; the first map entry is "v" (0x61 0x76) then 0x01.
    let i = noncanon
        .windows(3)
        .position(|w| w == [0x61, 0x76, 0x01])
        .unwrap();
    noncanon.splice(i + 2..i + 3, [0x18, 0x01]);
    w(
        "non-canonical",
        "v encoded in two bytes",
        &noncanon,
        NOW,
        "GrantInvalid",
    );

    let r = |name: &str, desc: &str, bytes: &[u8], expect: &str| {
        write(
            "client-revocation",
            name,
            json!({"description": desc, "revocation": h(bytes), "expect": expect}),
        );
    };
    let rev_by = |signer: &SoftwareKey, seq: u64| {
        let u = UnsignedRevocation::new(
            fx.client.public_key(),
            seq,
            ISSUED_AT + 3_600,
            signer.public_key().fingerprint().clone(),
        )
        .unwrap();
        let sig = signer.sign(&u.to_be_signed());
        u.with_signature(sig)
    };
    let rev = rev_by(&fx.attest, 1);
    r(
        "valid",
        "revocation of seq 1 from the manifest attest key",
        rev.bytes(),
        "ok",
    );
    r(
        "unknown-signer",
        "signed by a key the manifest does not list",
        rev_by(&fx.rogue_attest, 1).bytes(),
        "RevocationInvalid",
    );
    r(
        "signer-not-attest-role",
        "signed by the manifest's sign key",
        rev_by(&fx.sign, 1).bytes(),
        "RevocationInvalid",
    );
    let mut sig = rev.sig;
    sig[0] ^= 1;
    r(
        "bad-signature",
        "one bit of the signature flipped",
        rev.fields.clone().with_signature(sig).bytes(),
        "RevocationInvalid",
    );
    let mut m = decode_map(rev.bytes()).unwrap();
    m.insert("seq".into(), Value::Uint(0));
    r(
        "seq-zero",
        "cancels seq 0",
        &encode(&Value::Map(m)),
        "RevocationInvalid",
    );
}
