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
