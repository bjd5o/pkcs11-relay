//! wire-format §11: setup links (form, signature, time, identity) and the signer key's status.

use relay_core::setup_link::{parse, verify_setup_link, SetupLinkDraft, PREFIX};
use relay_core::signer::{parse_key, signer_status, SignerStatus};
use relay_core::{verify_manifest, Error, HardwarePolicy, ManifestSigner, PgpSecretKey};

/// The time the test runs: rPGP signs at the real current time, so a fixed time would turn
/// every signature into one "created in the future" once the clock passed it.
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn signer() -> (PgpSecretKey, ManifestSigner) {
    let k = PgpSecretKey::generate("link <link@test.invalid>").unwrap();
    let s = ManifestSigner::from_bytes(k.public_armored().unwrap().as_bytes()).unwrap();
    (k, s)
}

fn draft(signer: &ManifestSigner) -> SetupLinkDraft {
    SetupLinkDraft {
        relay: "https://10.0.0.170:8443".into(),
        ca: Some([7u8; 32]),
        signer: signer.fingerprint(),
        device: "iphone".into(),
        iat: now() - 60,
        exp: now() + 900,
    }
}

fn link(k: &PgpSecretKey, d: &SetupLinkDraft) -> String {
    let bytes = d.signed_bytes().unwrap();
    d.with_signature(&k.sign_detached_binary(bytes.as_bytes()).unwrap())
        .unwrap()
}

fn kind<T: std::fmt::Debug>(r: relay_core::Result<T>) -> &'static str {
    r.unwrap_err().kind()
}

#[test]
fn a_signed_link_verifies_and_round_trips() {
    let (k, s) = signer();
    let d = draft(&s);
    let l = link(&k, &d);
    assert!(l.starts_with(PREFIX));
    assert!(l.len() < 400, "Ed25519 links stay small: {}", l.len());
    let v = verify_setup_link(&l, &s, now(), 60).unwrap();
    assert_eq!(v.relay, d.relay);
    assert_eq!(v.ca, d.ca);
    assert_eq!(v.device, "iphone");
    assert_eq!((v.iat, v.exp), (d.iat, d.exp));
    assert_eq!(v.signed_bytes(), d.signed_bytes().unwrap());
    // Without a CA pin.
    let d2 = SetupLinkDraft { ca: None, ..d };
    let v2 = verify_setup_link(&link(&k, &d2), &s, now(), 60).unwrap();
    assert_eq!(v2.ca, None);
}

#[test]
fn the_id_covers_the_signed_bytes_only() {
    let (k, s) = signer();
    let d = draft(&s);
    let a = link(&k, &d);
    // A second, different signature over the same bytes (another key's will do: parsing does
    // not check signatures) is still the same link.
    let (other, _) = signer();
    let b = d
        .with_signature(
            &other
                .sign_detached_binary(d.signed_bytes().unwrap().as_bytes())
                .unwrap(),
        )
        .unwrap();
    let (pa, pb) = (parse(&a).unwrap(), parse(&b).unwrap());
    assert_ne!(pa.sig, pb.sig);
    assert_eq!(pa.id(), pb.id());
    assert_eq!(pa.id().len(), 64);
    let other_link = link(
        &k,
        &SetupLinkDraft {
            exp: d.exp + 1,
            ..d
        },
    );
    assert_ne!(parse(&other_link).unwrap().id(), pa.id());
}

#[test]
fn the_fixed_form_is_enforced() {
    let (k, s) = signer();
    let l = link(&k, &draft(&s));
    let sig_at = l.rfind("&sig=").unwrap();
    let edits: Vec<(&str, String)> = vec![
        ("other scheme", l.replacen("poh://", "pah://", 1)),
        (
            "percent-encoding",
            l.replacen("10.0.0.170", "10%2E0.0.170", 1),
        ),
        (
            "reordered",
            l.replacen("&device=iphone&iat=", "&iat=", 1).replacen(
                "&exp=",
                "&device=iphone&exp=",
                1,
            ),
        ),
        (
            "duplicate",
            l.replacen("&device=iphone", "&device=iphone&device=iphone", 1),
        ),
        (
            "unknown param",
            format!("{}&x=1{}", &l[..sig_at], &l[sig_at..]),
        ),
        ("trailing param", format!("{l}&x=1")),
        ("path in relay", l.replacen(":8443", ":8443/x", 1)),
        ("http relay", l.replacen("https://", "http://", 1)),
        (
            "lowercase signer",
            l.replacen(&s.fingerprint(), &s.fingerprint().to_lowercase(), 1),
        ),
        (
            "bad device",
            l.replacen("device=iphone", "device=iPhone", 1),
        ),
        ("leading zero", l.replacen("&iat=", "&iat=0", 1)),
        ("space", l.replacen("iphone", "i phone", 1)),
        ("short ca", l.replacen("&ca=", "&ca=AA", 1)),
        ("no sig", l[..sig_at].to_string()),
        ("too long", format!("{l}{}", "A".repeat(5000))),
    ];
    for (name, bad) in edits {
        let e = parse(&bad).unwrap_err();
        assert_eq!(e.kind(), "SetupLinkInvalid", "{name}: {e}");
    }
    // exp after iat, at most seven days later.
    for (iat, exp) in [(now(), now()), (now(), now() + 7 * 86_400 + 1)] {
        let d = SetupLinkDraft {
            iat,
            exp,
            ..draft(&s)
        };
        assert_eq!(d.signed_bytes().unwrap_err().kind(), "SetupLinkInvalid");
    }
}

#[test]
fn signature_and_signer_are_checked() {
    let (k, s) = signer();
    let d = draft(&s);
    let l = link(&k, &d);
    // Any change to the signed bytes breaks the signature.
    let altered = l.replacen("device=iphone", "device=ipad", 1);
    assert_eq!(
        kind(verify_setup_link(&altered, &s, now(), 60)),
        "SetupLinkSignatureInvalid"
    );
    // Another key's signature over the right bytes, naming the right signer.
    let (other, _) = signer();
    let forged = d
        .with_signature(
            &other
                .sign_detached_binary(d.signed_bytes().unwrap().as_bytes())
                .unwrap(),
        )
        .unwrap();
    assert_eq!(
        kind(verify_setup_link(&forged, &s, now(), 60)),
        "SetupLinkSignatureInvalid"
    );
    // A link naming another signer.
    let (_, s2) = signer();
    assert_eq!(
        kind(verify_setup_link(&l, &s2, now(), 60)),
        "SetupLinkWrongSigner"
    );
}

#[test]
fn manifest_and_link_signatures_cannot_stand_in_for_each_other() {
    let (k, s) = signer();
    let d = draft(&s);
    // A manifest signature presented as a link signature.
    let manifest = br#"{"v":1}"#;
    let msig = k.sign_detached_binary(manifest).unwrap();
    let swapped = d.with_signature(&msig).unwrap();
    assert_eq!(
        kind(verify_setup_link(&swapped, &s, now(), 60)),
        "SetupLinkSignatureInvalid"
    );
    // A link's signed bytes and signature presented as a manifest.
    let l = parse(&link(&k, &d)).unwrap();
    let e = verify_manifest(
        l.signed_bytes().as_bytes(),
        &l.sig,
        &s,
        &HardwarePolicy::yubico(),
        None,
        now(),
        60,
    )
    .unwrap_err();
    assert!(matches!(e, Error::ManifestMalformed(_)), "{e}");
}

#[test]
fn time_window_with_skew() {
    let (k, s) = signer();
    let mut d = draft(&s);
    // Issued a little after it is signed, so checking at `iat - skew` is still after the
    // signature's creation time.
    d.iat += 180;
    d.exp += 180;
    let l = link(&k, &d);
    verify_setup_link(&l, &s, d.iat - 60, 60).unwrap();
    verify_setup_link(&l, &s, d.exp + 60, 60).unwrap();
    assert_eq!(
        kind(verify_setup_link(&l, &s, d.exp + 61, 60)),
        "SetupLinkExpired"
    );
    // Not yet valid: the signature itself is from the future too, so that check fires first.
    assert!(verify_setup_link(&l, &s, d.iat - 3_600, 60).is_err());
}

// ---------- signer status ----------

const T0: u64 = 1_794_700_800; // keys created
const DAY: u64 = 86_400;

fn key(name: &str) -> pgp::composed::SignedPublicKey {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/signer")
        .join(name);
    parse_key(&std::fs::read(p).unwrap()).unwrap()
}

#[test]
fn usable_and_expiring_keys() {
    assert_eq!(
        signer_status(&[key("usable.asc")], T0 + 400 * DAY).unwrap(),
        SignerStatus::Usable { expires: None }
    );
    let exp = signer_status(&[key("expiring.asc")], T0 + 3_600).unwrap();
    assert_eq!(
        exp,
        SignerStatus::Usable {
            expires: Some(T0 + DAY)
        }
    );
    assert_eq!(
        signer_status(&[key("expiring.asc")], T0 + 2 * DAY).unwrap(),
        SignerStatus::Expired { at: T0 + DAY }
    );
}

#[test]
fn a_newer_self_signature_renews_even_beside_a_stripped_copy() {
    let renewed = signer_status(&[key("renewed.asc")], T0 + 2 * DAY).unwrap();
    assert!(renewed.is_usable(), "{renewed:?}");
    // The keyserver (or anyone) serving the older copy can't make it look expired.
    for copies in [
        vec![key("expiring.asc"), key("renewed.asc")],
        vec![key("renewed.asc"), key("expiring.asc")],
    ] {
        assert!(signer_status(&copies, T0 + 2 * DAY).unwrap().is_usable());
    }
}

#[test]
fn revocation_counts_from_any_copy_and_only_if_it_verifies() {
    let r = signer_status(&[key("revoked.asc")], T0 + DAY).unwrap();
    assert!(matches!(r, SignerStatus::Revoked { .. }), "{r:?}");
    assert!(!r.is_usable());
    // A revocation made for another key, attached to this one, does not count.
    let mut forged = key("usable.asc");
    forged
        .details
        .revocation_signatures
        .extend(key("revoked.asc").details.revocation_signatures);
    assert!(signer_status(&[forged], T0 + DAY).unwrap().is_usable());
}

#[test]
fn signing_subkeys() {
    let s = signer_status(&[key("subkey-expiring.asc")], T0 + 3_600).unwrap();
    assert_eq!(
        s,
        SignerStatus::Usable {
            expires: Some(T0 + DAY)
        }
    );
    assert_eq!(
        signer_status(&[key("subkey-expiring.asc")], T0 + 2 * DAY).unwrap(),
        SignerStatus::Expired { at: T0 + DAY }
    );
    let r = signer_status(&[key("subkey-revoked.asc")], T0 + DAY).unwrap();
    assert!(matches!(r, SignerStatus::Revoked { .. }), "{r:?}");
    assert_eq!(
        signer_status(&[key("cert-only.asc")], T0 + DAY).unwrap(),
        SignerStatus::CannotSign
    );
}

#[test]
fn copies_of_different_keys_are_refused() {
    let e = signer_status(&[key("usable.asc"), key("revoked.asc")], T0).unwrap_err();
    assert!(e.to_string().contains("copies of different keys"), "{e}");
    assert!(signer_status(&[], T0).is_err());
}

#[test]
fn the_relay_ca_must_be_the_pinned_self_signed_ca() {
    use relay_core::hw_attestation::testing::{to_pem, TestHierarchy};
    use relay_core::setup_link::{check_relay_ca, spki_pin};
    use x509_cert::der::{Decode, Encode};
    let h = TestHierarchy::new();
    let root = h.root_der();
    let spki = |der: &[u8]| {
        x509_cert::Certificate::from_der(der)
            .unwrap()
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .unwrap()
    };
    let pin = spki_pin(&spki(&root));
    check_relay_ca(to_pem(std::slice::from_ref(&root)).as_bytes(), &pin).unwrap();
    let e = check_relay_ca(to_pem(&[root]).as_bytes(), &[0u8; 32]).unwrap_err();
    assert!(e.to_string().contains("pin"), "{e}");
    // An intermediate (a CA, but not self-signed) with a matching pin is still refused.
    let inter = h.intermediates()[1].clone();
    let e = check_relay_ca(
        to_pem(std::slice::from_ref(&inter)).as_bytes(),
        &spki_pin(&spki(&inter)),
    )
    .unwrap_err();
    assert!(e.to_string().contains("self-signed"), "{e}");
    assert!(check_relay_ca(b"junk", &pin).is_err());
}
