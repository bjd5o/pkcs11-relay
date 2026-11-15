//! The core's PIV layer driving the softcard, checked by the core's own verifiers.

use relay_core::attestation::UnsignedAttestation;
use relay_core::manifest::{DraftKey, ManifestDraft};
use relay_core::piv::{self, PivError, Slot};
use relay_core::response::verify_signature_result;
use relay_core::signing::SoftwareKey;
use relay_core::{verify_attestation, Algorithm, Manifest, Mechanism, Role};
use relay_softcard::SoftCard;

const PIN: &[u8] = b"123456";

struct Fixture {
    card: SoftCard,
    manifest: Manifest,
}

fn slot(s: u8) -> Slot {
    Slot::new(s).unwrap()
}

fn fixture() -> Fixture {
    let mut card = SoftCard::new(PIN);
    let specs = [
        (0x9d, Algorithm::Rsa2048, Role::Encrypt, "enc"),
        (0x9c, Algorithm::P256, Role::Sign, "sign-ec"),
        (0x82, Algorithm::Rsa2048, Role::Sign, "sign-rsa"),
        (0x9a, Algorithm::P256, Role::Auth, "auth-ec"),
        (0x83, Algorithm::Rsa2048, Role::Auth, "auth-rsa"),
        (0x95, Algorithm::P256, Role::Attest, "attest"),
    ];
    let keys = specs
        .iter()
        .enumerate()
        .map(|(i, (s, alg, role, label))| DraftKey {
            role: *role,
            label: label.to_string(),
            id: vec![i as u8 + 1],
            token: "softcard".into(),
            public_key: card.generate(slot(*s), *alg),
        })
        .collect();
    let draft = ManifestDraft {
        version: 1,
        issued_at: 1_000,
        valid_until: 2_000_000_000,
        keys,
    };
    let manifest = Manifest::from_json_unverified(&draft.to_json().unwrap()).unwrap();
    piv::select(&mut card).unwrap();
    Fixture { card, manifest }
}

fn key<'a>(m: &'a Manifest, label: &str) -> &'a relay_core::ManifestKey {
    m.keys.iter().find(|k| k.label == label).unwrap()
}

#[test]
fn oaep_decrypt_through_card() {
    let mut f = fixture();
    piv::verify_pin(&mut f.card, PIN).unwrap();
    let k = key(&f.manifest, "enc");
    // Encrypt with the rsa crate (standing in for OpenSSL) to the manifest's public key.
    let pk =
        <rsa::PublicKey as rsa::pkcs8::DecodePublicKey>::from_public_key_der(k.public_key.spki())
            .unwrap();
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    let ct = pk
        .encrypt(
            &mut rng,
            rsa::Oaep::<sha2::Sha256>::new_with_label(b"L".to_vec().into_boxed_slice()),
            b"unseal key",
        )
        .unwrap();
    let mech = Mechanism::RsaPkcsOaep {
        label: b"L".to_vec(),
    };
    let pt = piv::perform(&mut f.card, slot(0x9d), Algorithm::Rsa2048, &mech, &ct).unwrap();
    assert_eq!(&*pt, b"unseal key");
    // A wrong label is a generic card error, reported as card_error.
    let mech = Mechanism::RsaPkcsOaep {
        label: b"X".to_vec(),
    };
    let e = piv::perform(&mut f.card, slot(0x9d), Algorithm::Rsa2048, &mech, &ct).unwrap_err();
    assert_eq!(e.reason(), relay_core::response::Reason::CardError);
}

#[test]
fn signatures_through_card_pass_check_5() {
    let mut f = fixture();
    piv::verify_pin(&mut f.card, PIN).unwrap();
    let digest_info = {
        use sha2::Digest;
        let mut v = relay_core::padding::SHA256_DIGEST_INFO_PREFIX.to_vec();
        v.extend_from_slice(&sha2::Sha256::digest(b"challenge"));
        v
    };
    let cases: Vec<(&str, u8, Algorithm, Mechanism, Vec<u8>)> = vec![
        (
            "sign-ec",
            0x9c,
            Algorithm::P256,
            Mechanism::EcdsaSha256,
            b"a commit".to_vec(),
        ),
        (
            "sign-rsa",
            0x82,
            Algorithm::Rsa2048,
            Mechanism::Sha256RsaPkcs,
            b"a commit".to_vec(),
        ),
        (
            "auth-ec",
            0x9a,
            Algorithm::P256,
            Mechanism::Ecdsa,
            vec![7u8; 32],
        ),
        (
            "auth-rsa",
            0x83,
            Algorithm::Rsa2048,
            Mechanism::RsaPkcs,
            digest_info,
        ),
    ];
    for (label, s, alg, mech, input) in cases {
        let sig = piv::perform(&mut f.card, slot(s), alg, &mech, &input).unwrap();
        let k = key(&f.manifest, label);
        verify_signature_result(k, &mech, &input, &sig).unwrap_or_else(|e| panic!("{label}: {e}"));
        let mut bad = sig.to_vec();
        bad[5] ^= 1;
        assert!(
            verify_signature_result(k, &mech, &input, &bad).is_err(),
            "{label}"
        );
        // A signature from the right card but the wrong key fails check 5.
        let other = key(
            &f.manifest,
            if alg == Algorithm::P256 {
                "attest"
            } else {
                "enc"
            },
        );
        assert!(
            verify_signature_result(other, &mech, &input, &sig).is_err(),
            "{label}"
        );
    }
}

#[test]
fn attestation_signed_on_card_verifies() {
    let mut f = fixture();
    piv::verify_pin(&mut f.card, PIN).unwrap();
    let attest = key(&f.manifest, "attest").fingerprint.clone();
    let device = SoftwareKey::generate_p256();
    let st = UnsignedAttestation::new("test-device", device.public_key(), 10_000, 20_000, attest)
        .unwrap();
    let st = piv::sign_attestation(&mut f.card, slot(0x95), st).unwrap();
    let v = verify_attestation(st.bytes(), &f.manifest, 15_000, 60).unwrap();
    assert_eq!(v.device_key, device.public_key());
}

#[test]
fn pin_retry_counter_and_block() {
    let mut f = fixture();
    assert_eq!(piv::pin_retries(&mut f.card).unwrap(), Some(3));
    // Operations need the PIN.
    let e = piv::perform(
        &mut f.card,
        slot(0x9a),
        Algorithm::P256,
        &Mechanism::Ecdsa,
        &[1u8; 32],
    )
    .unwrap_err();
    assert_eq!(e, PivError::SecurityStatusNotSatisfied);
    assert_eq!(
        piv::verify_pin(&mut f.card, b"000000"),
        Err(PivError::WrongPin { retries: 2 })
    );
    assert_eq!(
        piv::verify_pin(&mut f.card, b"000000"),
        Err(PivError::WrongPin { retries: 1 })
    );
    assert_eq!(
        piv::verify_pin(&mut f.card, b"000000"),
        Err(PivError::PinBlocked)
    );
    assert_eq!(piv::verify_pin(&mut f.card, PIN), Err(PivError::PinBlocked));
    // The card's log never holds PIN bytes.
    assert!(f
        .card
        .log
        .iter()
        .filter(|a| a[1] == 0x20)
        .all(|a| a.len() <= 5));
}

#[test]
fn certificate_read_and_parse() {
    use x509_cert::der::{Decode, Encode};
    let mut f = fixture();
    let der = piv::read_certificate(&mut f.card, slot(0x9d)).unwrap();
    assert!(der.len() > 256, "RSA certificate needs response chaining");
    let cert = x509_cert::Certificate::from_der(&der).unwrap();
    let spki = cert
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .unwrap();
    assert_eq!(spki, key(&f.manifest, "enc").public_key.spki());
    assert_eq!(
        piv::read_certificate(&mut f.card, slot(0x84)),
        Err(PivError::NotFound)
    );
}
