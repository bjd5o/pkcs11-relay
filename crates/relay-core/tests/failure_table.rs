//! Milestone 1 gate: one named test per row of the spec's Failure handling table that the core
//! can detect, each asserting the exact error and PKCS#11 return code.
//!
//! Manifest rows (signature invalid, rolled back, expired → zero slots) are in
//! `manifest_pgp.rs`, against signatures made by real gpg.
//! The hardware attestation row (missing when required, invalid or outside policy → zero
//! slots) is in `manifest_hw.rs`; the relay's own manifest row is in relay-server's tests.
//!
//! Rows that only the provider can produce, covered in milestone 3:
//! manifest unreachable with no cache; relay unreachable during discovery; relay unreachable
//! for a request (`CKR_DEVICE_ERROR`); no answer before `expires_at` (`CKR_FUNCTION_CANCELED`);
//! output buffer too small (`CKR_BUFFER_TOO_SMALL`); second call of the length-query pattern.

mod common;

use common::*;
use relay_core::error::ckr;
use relay_core::request::{RequestContext, UnsignedRequest};
use relay_core::response::{Reason, UnsignedResponse};
use relay_core::seal::ReplyKey;
use relay_core::{verify_response, Error, FailureRow, Mechanism, Op, Outcome, Role};

fn ctx() -> RequestContext {
    RequestContext {
        host: "pi5.tailnet".into(),
        purpose: "test".into(),
        consumer: "pkcs11-tool".into(),
    }
}

fn local_request(
    fx: &Fx,
    role: Role,
    op: Op,
    mech: Mechanism,
    len: usize,
) -> relay_core::Result<UnsignedRequest> {
    UnsignedRequest::new(
        CLIENT_ID,
        fx.key(role),
        op,
        mech,
        vec![0u8; len],
        ctx(),
        ReplyKey::generate().public_bytes(),
        NOW,
        NOW + 90,
    )
}

// --- Operation outside the key's role: rejected locally, CKR_KEY_FUNCTION_NOT_PERMITTED ---

#[test]
fn row_operation_outside_role_is_rejected_locally() {
    let fx = load();
    let cases = [
        (
            Role::Sign,
            Op::Decrypt,
            Mechanism::RsaPkcsOaep { label: vec![] },
            256,
        ),
        (
            Role::Auth,
            Op::Decrypt,
            Mechanism::RsaPkcsOaep { label: vec![] },
            256,
        ),
        (Role::Encrypt, Op::Sign, Mechanism::RsaPkcs, 32),
        (Role::Attest, Op::Sign, Mechanism::Ecdsa, 32),
    ];
    for (role, op, mech, len) in cases {
        let e = local_request(&fx, role, op, mech, len).unwrap_err();
        assert_eq!(e, Error::KeyFunctionNotPermitted, "{role:?} {op:?}");
        assert_eq!(e.ckr(), Some(ckr::KEY_FUNCTION_NOT_PERMITTED));
        assert_eq!(e.failure_row(), FailureRow::RoleViolation);
    }
}

// --- Mechanism not allowed for the key: rejected locally, CKR_MECHANISM_INVALID ---

#[test]
fn row_mechanism_not_allowed_is_rejected_locally() {
    let fx = load();
    let cases = [
        (Role::Sign, Mechanism::Ecdsa), // auth-only mechanism on a sign key
        (Role::Auth, Mechanism::EcdsaSha256), // hash-and-sign on an auth key
        (Role::Sign, Mechanism::Sha256RsaPkcs), // RSA mechanism on a P-256 key
    ];
    for (role, mech) in cases {
        let e = local_request(&fx, role, Op::Sign, mech.clone(), 32).unwrap_err();
        assert_eq!(e, Error::MechanismInvalid, "{role:?} {mech:?}");
        assert_eq!(e.ckr(), Some(ckr::MECHANISM_INVALID));
        assert_eq!(e.failure_row(), FailureRow::MechanismNotAllowed);
    }
}

#[test]
fn row_mechanism_parameters_not_supported() {
    use relay_core::mechanism::{ckm, OaepParams};
    let e = Mechanism::from_pkcs11(
        ckm::RSA_PKCS_OAEP,
        Some(OaepParams {
            hash_alg: 0x220,
            mgf: 1,
            label: vec![],
        }),
    )
    .unwrap_err();
    assert_eq!(e.ckr(), Some(ckr::MECHANISM_PARAM_INVALID));
    let e = Mechanism::from_pkcs11(0x8000_0001, None).unwrap_err();
    assert_eq!(e.ckr(), Some(ckr::MECHANISM_INVALID));
}

// --- Signed denial from an attested device: CKR_FUNCTION_REJECTED ---

#[test]
fn row_signed_denial_returns_function_rejected() {
    let fx = load();
    let (req, reply, _) = fx.sign_request(b"msg");
    let resp = fx.deny(&req, Some(Reason::UserDenied));
    let out = verify_response(&resp, req.bytes(), &fx.manifest, NOW, SKEW, reply).unwrap();
    assert_eq!(out, Outcome::Denied(Some(Reason::UserDenied)));
    assert_eq!(out.ckr(), ckr::FUNCTION_REJECTED);
}

// --- Signed error from an attested device: logged, CKR_DEVICE_ERROR ---

#[test]
fn row_signed_error_returns_device_error() {
    let fx = load();
    for reason in [
        Reason::CardAbsent,
        Reason::WrongPin,
        Reason::PinBlocked,
        Reason::CardError,
    ] {
        let (req, reply, _) = fx.sign_request(b"msg");
        let resp = fx.error(&req, Some(reason));
        let out = verify_response(&resp, req.bytes(), &fx.manifest, NOW, SKEW, reply).unwrap();
        assert_eq!(out, Outcome::Error(Some(reason)));
        assert_eq!(out.ckr(), ckr::DEVICE_ERROR);
    }
}

// --- Attestation invalid, expired or not signed by a manifest attest key: CKR_DEVICE_ERROR ---

fn assert_attestation_row(r: relay_core::Result<Outcome>, want: Error) {
    let e = r.unwrap_err();
    assert_eq!(e.kind(), want.kind());
    assert_eq!(e.failure_row(), FailureRow::AttestationRejected);
    assert_eq!(e.ckr(), Some(ckr::DEVICE_ERROR));
}

#[test]
fn row_attestation_expired() {
    let fx = load();
    let (req, reply, sig) = fx.sign_request(b"msg");
    let resp = fx.approve(&req, &sig, &fx.attestation(), &fx.device);
    assert_attestation_row(
        verify_response(
            &resp,
            req.bytes(),
            &fx.manifest,
            VALID_UNTIL + SKEW + 1,
            SKEW,
            reply,
        ),
        Error::AttestationExpired,
    );
}

/// The window is longer than the manifest's `max_attestation_window_secs` (fixture: 30 days).
#[test]
fn row_attestation_window_too_long() {
    let fx = load();
    let (req, reply, sig) = fx.sign_request(b"msg");
    let resp = fx.approve(&req, &sig, &fx.attestation(), &fx.device);
    let mut manifest = fx.manifest.clone();
    manifest.max_attestation_window_secs = 29 * 86_400;
    let e = verify_response(&resp, req.bytes(), &manifest, NOW, SKEW, reply).unwrap_err();
    assert_eq!(
        e,
        Error::AttestationWindowTooLong {
            window: VALID_UNTIL - ISSUED_AT,
            max: 29 * 86_400
        }
    );
    assert_eq!(e.failure_row(), FailureRow::AttestationRejected);
    assert_eq!(e.ckr(), Some(relay_core::error::ckr::DEVICE_ERROR));
    // The relay's check: the signer, and the length, not the time.
    assert!(relay_core::attestation::verify_attestation_signer(
        fx.attestation().bytes(),
        &manifest
    )
    .is_err());
    relay_core::attestation::verify_attestation_signer(fx.attestation().bytes(), &fx.manifest)
        .unwrap();
}

#[test]
fn row_attestation_not_yet_valid() {
    let fx = load();
    let att = fx.attestation_with(&fx.attest, &fx.device, NOW + 3600, VALID_UNTIL);
    let (req, reply, sig) = fx.sign_request(b"msg");
    let resp = fx.approve(&req, &sig, &att, &fx.device);
    assert_attestation_row(
        verify_response(&resp, req.bytes(), &fx.manifest, NOW, SKEW, reply),
        Error::AttestationExpired,
    );
}

#[test]
fn row_attestation_not_signed_by_manifest_attest_key() {
    let fx = load();
    // A key the manifest does not list at all, and a manifest key whose role is not attest.
    for signer in [&fx.rogue_attest, &fx.sign] {
        let att = fx.attestation_with(signer, &fx.device, ISSUED_AT, VALID_UNTIL);
        let (req, reply, sig) = fx.sign_request(b"msg");
        let resp = fx.approve(&req, &sig, &att, &fx.device);
        assert_attestation_row(
            verify_response(&resp, req.bytes(), &fx.manifest, NOW, SKEW, reply),
            Error::AttestationUnknownSigner,
        );
    }
}

#[test]
fn row_attestation_invalid_signature() {
    let fx = load();
    let good = fx.attestation();
    let mut sig = good.sig;
    sig[0] ^= 0x40;
    let bad = good.fields.clone().with_signature(sig);
    let (req, reply, s) = fx.sign_request(b"msg");
    let resp = fx.approve(&req, &s, &bad, &fx.device);
    assert_attestation_row(
        verify_response(&resp, req.bytes(), &fx.manifest, NOW, SKEW, reply),
        Error::AttestationInvalid(String::new()),
    );
}

#[test]
fn row_attest_key_removed_from_manifest_voids_attestation() {
    let fx = load();
    let without = relay_core::Manifest::from_json_unverified(
        &std::fs::read(dir().join("fixture/manifest-v2.json")).unwrap(),
    )
    .unwrap();
    let (req, reply, sig) = fx.sign_request(b"msg");
    let resp = fx.approve(&req, &sig, &fx.attestation(), &fx.device);
    assert_attestation_row(
        verify_response(&resp, req.bytes(), &without, NOW, SKEW, reply),
        Error::AttestationUnknownSigner,
    );
}

#[test]
fn attestation_skew_boundaries() {
    let fx = load();
    for (now, ok) in [
        (VALID_UNTIL + SKEW, true),
        (VALID_UNTIL + SKEW + 1, false),
        (ISSUED_AT - SKEW, true),
        (ISSUED_AT - SKEW - 1, false),
    ] {
        let r = relay_core::verify_attestation(fx.attestation().bytes(), &fx.manifest, now, SKEW);
        assert_eq!(r.is_ok(), ok, "now = {now}");
    }
}

// --- Response signed by another key, or not bound to this request: CKR_DEVICE_ERROR, tampering ---

fn assert_tampering(r: relay_core::Result<Outcome>, kind: &str) {
    let e = r.unwrap_err();
    assert_eq!(e.kind(), kind);
    assert!(e.is_tampering());
    assert_eq!(e.ckr(), Some(ckr::DEVICE_ERROR));
}

#[test]
fn row_response_signed_by_key_other_than_attested_device() {
    let fx = load();
    let att = fx.attestation();
    let (req, reply, sig) = fx.sign_request(b"msg");
    // Names the rogue key as its signer: mismatch with the attestation.
    let mut u = UnsignedResponse::approved(&req, &sig, &att, NOW).unwrap();
    u.device_key_fingerprint = fx.rogue_device.public_key().fingerprint().clone();
    let resp = u
        .clone()
        .with_signature(fx.rogue_device.sign(&u.to_be_signed()));
    assert_tampering(
        verify_response(resp.bytes(), req.bytes(), &fx.manifest, NOW, SKEW, reply),
        "ResponseSignerMismatch",
    );
    // Names the attested key but was signed by another.
    let (req, reply, sig) = fx.sign_request(b"msg");
    let u = UnsignedResponse::approved(&req, &sig, &att, NOW).unwrap();
    let resp = u
        .clone()
        .with_signature(fx.rogue_device.sign(&u.to_be_signed()));
    assert_tampering(
        verify_response(resp.bytes(), req.bytes(), &fx.manifest, NOW, SKEW, reply),
        "ResponseSignatureInvalid",
    );
}

#[test]
fn row_response_not_bound_to_this_request() {
    let fx = load();
    let att = fx.attestation();
    let (req, reply, sig) = fx.sign_request(b"msg");
    let (other, _, _) = fx.sign_request(b"msg");
    let resp = fx.approve(&other, &sig, &att, &fx.device);
    assert_tampering(
        verify_response(&resp, req.bytes(), &fx.manifest, NOW, SKEW, reply),
        "ResponseNotBound",
    );
    // Same req_id but a different request (request_hash differs).
    let (req, reply, sig) = fx.sign_request(b"msg");
    let mut u = UnsignedResponse::approved(&req, &sig, &att, NOW).unwrap();
    u.request_hash[0] ^= 1;
    let resp = u.clone().with_signature(fx.device.sign(&u.to_be_signed()));
    assert_tampering(
        verify_response(resp.bytes(), req.bytes(), &fx.manifest, NOW, SKEW, reply),
        "ResponseNotBound",
    );
}

#[test]
fn row_signature_result_fails_check_5() {
    let fx = load();
    let (req, reply, _) = fx.sign_request(b"msg");
    // Validly attested and bound, but the "signature" is from a different key.
    let forged = fx.auth.sign(b"msg");
    let resp = fx.approve(&req, &forged, &fx.attestation(), &fx.device);
    assert_tampering(
        verify_response(&resp, req.bytes(), &fx.manifest, NOW, SKEW, reply),
        "ResultSignatureInvalid",
    );
}

#[test]
fn checks_run_in_spec_order() {
    // A response failing several checks reports the first in the spec's order: here the
    // attestation is expired AND the response is for another request.
    let fx = load();
    let (req, reply, sig) = fx.sign_request(b"msg");
    let (other, _, _) = fx.sign_request(b"msg");
    let resp = fx.approve(&other, &sig, &fx.attestation(), &fx.device);
    let e = verify_response(
        &resp,
        req.bytes(),
        &fx.manifest,
        VALID_UNTIL + SKEW + 1,
        SKEW,
        reply,
    )
    .unwrap_err();
    assert_eq!(e, Error::AttestationExpired);
}

#[test]
fn approved_decrypt_opens_result() {
    let fx = load();
    let (req, reply) = fx.decrypt_request(b"root key");
    let resp = fx.approve(&req, b"root key", &fx.attestation(), &fx.device);
    let out = verify_response(&resp, req.bytes(), &fx.manifest, NOW, SKEW, reply).unwrap();
    assert_eq!(
        out,
        Outcome::Approved(zeroize::Zeroizing::new(b"root key".to_vec()))
    );
    assert_eq!(out.ckr(), 0);
}

// --- Approver-side: expired requests map to CKR_FUNCTION_CANCELED ---

#[test]
fn expired_request_maps_to_function_canceled() {
    assert_eq!(Error::RequestExpired.ckr(), Some(ckr::FUNCTION_CANCELED));
    assert_eq!(Error::RequestExpired.failure_row(), FailureRow::Expired);
}

mod cbor_properties {
    use proptest::prelude::*;
    use relay_core::cbor::{decode_map, encode, Value};
    use std::collections::BTreeMap;

    fn value() -> impl Strategy<Value = Value> {
        let leaf = prop_oneof![
            any::<u64>().prop_map(Value::Uint),
            proptest::collection::vec(any::<u8>(), 0..64).prop_map(Value::Bytes),
            "[a-z0-9 _-]{0,40}".prop_map(Value::Text),
        ];
        leaf.prop_recursive(2, 32, 8, |inner| {
            proptest::collection::btree_map("[a-z_]{1,22}", inner, 0..8).prop_map(Value::Map)
        })
    }

    proptest! {
        #[test]
        fn round_trip(m in proptest::collection::btree_map("[a-z_]{1,22}", value(), 0..12)) {
            let bytes = encode(&Value::Map(m.clone()));
            prop_assert_eq!(decode_map(&bytes).unwrap(), m);
        }

        #[test]
        fn decoder_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = decode_map(&bytes);
        }

        #[test]
        fn decoded_input_is_canonical(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            if let Ok(m) = decode_map(&bytes) {
                prop_assert_eq!(encode(&Value::Map(m)), bytes);
            }
        }
    }

    #[test]
    fn empty_map() {
        assert_eq!(decode_map(&[0xa0]).unwrap(), BTreeMap::new());
    }
}
