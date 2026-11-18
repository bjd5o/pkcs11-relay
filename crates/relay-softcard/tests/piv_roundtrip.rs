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
            hardware_attestation: None,
        })
        .collect();
    let draft = ManifestDraft {
        version: 1,
        issued_at: 1_000,
        valid_until: 2_000_000_000,
        keys,
        ..Default::default()
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

/// ECDH on each curve through the core's PIV layer, checked against the same agreement
/// computed in software from the peer's side; and both KDFs.
#[test]
fn ecdh_through_card_matches_software() {
    use relay_core::mechanism::{ckm, Kdf};
    let mut card = SoftCard::new(PIN);
    let p256_pk = card.generate(slot(0x86), Algorithm::P256);
    let p384_pk = card.generate(slot(0x87), Algorithm::P384);
    let x_pk = card.generate(slot(0x88), Algorithm::X25519);
    piv::select(&mut card).unwrap();
    piv::verify_pin(&mut card, PIN).unwrap();
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);

    // P-256: the peer's ephemeral key and its view of the shared secret.
    let eph =
        <p256::ecdsa::SigningKey as p256::elliptic_curve::Generate>::generate_from_rng(&mut rng);
    let card_pub = p256::PublicKey::from_sec1_bytes(&p256_pk.ec_point().unwrap()).unwrap();
    let expect = p256::ecdh::diffie_hellman(eph.as_nonzero_scalar(), card_pub.as_affine());
    let peer = eph.verifying_key().to_sec1_point(false).as_bytes().to_vec();
    let m = Mechanism::ecdh_from_pkcs11(ckm::CKD_NULL, vec![], 32).unwrap();
    let got = piv::perform(&mut card, slot(0x86), Algorithm::P256, &m, &peer).unwrap();
    assert_eq!(&got[..], &expect.raw_secret_bytes()[..]);
    // X9.63 KDF with shared info, 16 bytes.
    let m = Mechanism::ecdh_from_pkcs11(ckm::CKD_SHA256_KDF, b"info".to_vec(), 16).unwrap();
    let got = piv::perform(&mut card, slot(0x86), Algorithm::P256, &m, &peer).unwrap();
    let mut want = [0u8; 16];
    ansi_x963_kdf::derive_key_into::<sha2::Sha256>(expect.raw_secret_bytes(), b"info", &mut want)
        .unwrap();
    assert_eq!(&got[..], &want);
    let _ = Kdf::Null;

    // P-384.
    let eph =
        <p384::ecdsa::SigningKey as p384::elliptic_curve::Generate>::generate_from_rng(&mut rng);
    let card_pub = p384::PublicKey::from_sec1_bytes(&p384_pk.ec_point().unwrap()).unwrap();
    let expect = p384::ecdh::diffie_hellman(eph.as_nonzero_scalar(), card_pub.as_affine());
    let peer = eph.verifying_key().to_sec1_point(false).as_bytes().to_vec();
    let m = Mechanism::ecdh_from_pkcs11(ckm::CKD_NULL, vec![], 48).unwrap();
    let got = piv::perform(&mut card, slot(0x87), Algorithm::P384, &m, &peer).unwrap();
    assert_eq!(&got[..], &expect.raw_secret_bytes()[..]);

    // X25519.
    let mut b = [0u8; 32];
    relay_core::signing::random_bytes(&mut b);
    let eph = x25519_dalek::StaticSecret::from(b);
    let card_pub: [u8; 32] = x_pk.ec_point().unwrap().try_into().unwrap();
    let expect = eph.diffie_hellman(&x25519_dalek::PublicKey::from(card_pub));
    let peer = x25519_dalek::PublicKey::from(&eph).as_bytes().to_vec();
    let m = Mechanism::ecdh_from_pkcs11(ckm::CKD_NULL, vec![], 32).unwrap();
    let got = piv::perform(&mut card, slot(0x88), Algorithm::X25519, &m, &peer).unwrap();
    assert_eq!(&got[..], expect.as_bytes());
    // A low-order peer key gives an all-zero secret: refused.
    assert!(piv::perform(&mut card, slot(0x88), Algorithm::X25519, &m, &[0u8; 32]).is_err());
}

#[test]
fn p384_signatures_pass_check_5() {
    use relay_core::manifest::{DraftKey, ManifestDraft};
    let mut card = SoftCard::new(PIN);
    let sign = card.generate(slot(0x89), Algorithm::P384);
    let auth = card.generate(slot(0x8a), Algorithm::P384);
    let keys = vec![
        DraftKey {
            role: Role::Sign,
            label: "sign-p384".into(),
            id: vec![1],
            token: "t".into(),
            public_key: sign,
            hardware_attestation: None,
        },
        DraftKey {
            role: Role::Auth,
            label: "auth-p384".into(),
            id: vec![2],
            token: "t".into(),
            public_key: auth,
            hardware_attestation: None,
        },
    ];
    let m = Manifest::from_json_unverified(
        &ManifestDraft {
            version: 1,
            issued_at: 1,
            valid_until: 2_000_000_000,
            keys,
            ..Default::default()
        }
        .to_json()
        .unwrap(),
    )
    .unwrap();
    piv::select(&mut card).unwrap();
    piv::verify_pin(&mut card, PIN).unwrap();
    let sig = piv::perform(
        &mut card,
        slot(0x89),
        Algorithm::P384,
        &Mechanism::EcdsaSha384,
        b"tag",
    )
    .unwrap();
    assert_eq!(sig.len(), 96);
    verify_signature_result(key(&m, "sign-p384"), &Mechanism::EcdsaSha384, b"tag", &sig).unwrap();
    use sha2::Digest;
    let d = sha2::Sha384::digest(b"challenge");
    let sig = piv::perform(
        &mut card,
        slot(0x8a),
        Algorithm::P384,
        &Mechanism::Ecdsa,
        &d,
    )
    .unwrap();
    verify_signature_result(key(&m, "auth-p384"), &Mechanism::Ecdsa, &d, &sig).unwrap();
    assert!(verify_signature_result(key(&m, "sign-p384"), &Mechanism::Ecdsa, &d, &sig).is_err());
}

#[test]
fn ed25519_signatures_pass_check_5() {
    use relay_core::manifest::{DraftKey, ManifestDraft};
    let mut card = SoftCard::new(PIN);
    let sign = card.generate(slot(0x8b), Algorithm::Ed25519);
    let auth = card.generate(slot(0x8c), Algorithm::Ed25519);
    let keys = vec![
        DraftKey {
            role: Role::Sign,
            label: "sign-ed".into(),
            id: vec![1],
            token: "t".into(),
            public_key: sign,
            hardware_attestation: None,
        },
        DraftKey {
            role: Role::Auth,
            label: "auth-ed".into(),
            id: vec![2],
            token: "t".into(),
            public_key: auth,
            hardware_attestation: None,
        },
    ];
    let m = Manifest::from_json_unverified(
        &ManifestDraft {
            version: 1,
            issued_at: 1,
            valid_until: 2_000_000_000,
            keys,
            ..Default::default()
        }
        .to_json()
        .unwrap(),
    )
    .unwrap();
    piv::select(&mut card).unwrap();
    piv::verify_pin(&mut card, PIN).unwrap();
    // A message longer than one APDU exercises command chaining.
    let msg = vec![0x5a; 600];
    for (s, label) in [(0x8b, "sign-ed"), (0x8c, "auth-ed")] {
        let sig = piv::perform(
            &mut card,
            slot(s),
            Algorithm::Ed25519,
            &Mechanism::Eddsa,
            &msg,
        )
        .unwrap();
        assert_eq!(sig.len(), 64);
        verify_signature_result(key(&m, label), &Mechanism::Eddsa, &msg, &sig).unwrap();
        assert!(
            verify_signature_result(key(&m, label), &Mechanism::Eddsa, b"other", &sig).is_err()
        );
    }
    // The certificate (issued by a throwaway key) still yields the slot's public key.
    let pk = piv::read_public_key(&mut card, slot(0x8b)).unwrap();
    assert_eq!(&pk, &key(&m, "sign-ed").public_key);
}

/// A card session leaves no PIN verified: the next session must verify again, and the card
/// counts each session.
#[test]
fn session_clears_pin_state() {
    let mut card = SoftCard::new(PIN);
    card.generate(slot(0x9c), Algorithm::P256);
    let m = Mechanism::Ecdsa;
    let digest = [7u8; 32];
    let sig = piv::in_session(&mut card, |c| {
        piv::select(c)?;
        piv::verify_pin(c, PIN)?;
        piv::perform(c, slot(0x9c), Algorithm::P256, &m, &digest)
    })
    .unwrap();
    assert_eq!(sig.len(), 64);
    let e = piv::in_session(&mut card, |c| {
        piv::select(c)?;
        piv::perform(c, slot(0x9c), Algorithm::P256, &m, &digest)
    })
    .unwrap_err();
    assert_eq!(e, PivError::SecurityStatusNotSatisfied);
    assert_eq!(card.sessions, 2);
}
