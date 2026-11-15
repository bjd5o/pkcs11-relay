//! Manifest verification against OpenPGP signatures made by real gpg (tests/vectors/pgp).
//! Failure handling rows: "Manifest signature invalid, rolled back or expired" (zero slots).

mod common;

use common::*;
use relay_core::{verify_manifest, Error, FailureRow, Manifest, ManifestSigner};

fn pgp(name: &str) -> Vec<u8> {
    std::fs::read(dir().join("pgp").join(name)).unwrap()
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(dir().join("fixture").join(name)).unwrap()
}

fn signer() -> ManifestSigner {
    ManifestSigner::from_bytes(&pgp("signer-ed25519.asc")).unwrap()
}

fn verify(sig: &str, cached: Option<&Manifest>, now: u64) -> relay_core::Result<Manifest> {
    verify_manifest(
        &fixture("manifest.json"),
        &pgp(sig),
        &signer(),
        cached,
        now,
        SKEW,
    )
}

/// Every manifest rejection lists zero slots: no PKCS#11 return code, ManifestRejected row.
fn assert_zero_slots(e: &Error) {
    assert_eq!(e.failure_row(), FailureRow::ManifestRejected, "{e}");
    assert_eq!(e.ckr(), None);
}

#[test]
fn gpg_armored_and_binary_signatures_verify() {
    let m = verify("manifest.json.asc", None, NOW).unwrap();
    assert_eq!(m.version, 1);
    assert_eq!(m.keys.len(), 4);
    verify("manifest.json.sig", None, NOW).unwrap();
}

#[test]
fn gpg_signing_subkey_verifies() {
    let s = ManifestSigner::from_bytes(&pgp("signer-rsa-subkey.asc")).unwrap();
    verify_manifest(
        &fixture("manifest.json"),
        &pgp("manifest.json.subkey.asc"),
        &s,
        None,
        NOW,
        SKEW,
    )
    .unwrap();
}

#[test]
fn manifest_signature_invalid_wrong_key() {
    let e = verify("manifest.json.wrongkey.asc", None, NOW).unwrap_err();
    assert!(matches!(e, Error::ManifestSignatureInvalid(_)), "{e}");
    assert_zero_slots(&e);
    // A valid signature from another configured signer does not count either.
    let s = ManifestSigner::from_bytes(&pgp("signer-rsa-subkey.asc")).unwrap();
    let e = verify_manifest(
        &fixture("manifest.json"),
        &pgp("manifest.json.asc"),
        &s,
        None,
        NOW,
        SKEW,
    )
    .unwrap_err();
    assert!(matches!(e, Error::ManifestSignatureInvalid(_)), "{e}");
}

#[test]
fn manifest_signature_invalid_tampered_bytes() {
    let mut bytes = fixture("manifest.json");
    let pos = bytes.iter().position(|b| *b == b'7').unwrap_or(10);
    bytes[pos] ^= 1;
    let e = verify_manifest(
        &bytes,
        &pgp("manifest.json.asc"),
        &signer(),
        None,
        NOW,
        SKEW,
    )
    .unwrap_err();
    assert!(matches!(e, Error::ManifestSignatureInvalid(_)), "{e}");
    // Even one trailing newline is a different file.
    let mut bytes = fixture("manifest.json");
    bytes.push(b'\n');
    assert!(verify_manifest(
        &bytes,
        &pgp("manifest.json.asc"),
        &signer(),
        None,
        NOW,
        SKEW
    )
    .is_err());
}

#[test]
fn manifest_signature_invalid_text_mode() {
    let e = verify("manifest.json.text.asc", None, NOW).unwrap_err();
    assert!(
        matches!(e, Error::ManifestSignatureInvalid(ref m) if m.contains("binary")),
        "{e}"
    );
}

#[test]
fn manifest_signature_invalid_sha1() {
    let s = ManifestSigner::from_bytes(&pgp("signer-rsa-subkey.asc")).unwrap();
    let e = verify_manifest(
        &fixture("manifest.json"),
        &pgp("manifest.json.sha1.asc"),
        &s,
        None,
        NOW,
        SKEW,
    )
    .unwrap_err();
    assert!(
        matches!(e, Error::ManifestSignatureInvalid(ref m) if m.contains("SHA-256")),
        "{e}"
    );
}

#[test]
fn manifest_signature_invalid_two_signatures() {
    let e = verify("manifest.json.double.asc", None, NOW).unwrap_err();
    assert!(
        matches!(e, Error::ManifestSignatureInvalid(ref m) if m.contains("exactly one")),
        "{e}"
    );
}

#[test]
fn manifest_signature_invalid_created_in_future() {
    // Signed at ISSUED_AT; a clock more than `skew` earlier sees a future signature.
    let e = verify("manifest.json.asc", None, ISSUED_AT - SKEW - 1).unwrap_err();
    assert!(
        matches!(e, Error::ManifestSignatureInvalid(ref m) if m.contains("future")),
        "{e}"
    );
}

#[test]
fn manifest_signature_garbage() {
    let e = verify_manifest(
        &fixture("manifest.json"),
        b"not a signature",
        &signer(),
        None,
        NOW,
        SKEW,
    )
    .unwrap_err();
    assert_zero_slots(&e);
}

#[test]
fn manifest_expired() {
    verify("manifest.json.asc", None, VALID_UNTIL + SKEW).unwrap();
    let e = verify("manifest.json.asc", None, VALID_UNTIL + SKEW + 1).unwrap_err();
    assert!(matches!(e, Error::ManifestExpired { .. }), "{e}");
    assert_zero_slots(&e);
    // A cached copy is re-checked on every use.
    let m = verify("manifest.json.asc", None, NOW).unwrap();
    assert!(m.check_fresh(VALID_UNTIL + SKEW + 1, SKEW).is_err());
}

#[test]
fn manifest_rolled_back() {
    let v2 = verify_manifest(
        &fixture("manifest-v2.json"),
        &pgp("manifest-v2.json.asc"),
        &signer(),
        None,
        NOW,
        SKEW,
    )
    .unwrap();
    let e = verify("manifest.json.asc", Some(&v2), NOW).unwrap_err();
    assert_eq!(
        e,
        Error::ManifestRolledBack {
            version: 1,
            cached: 2
        }
    );
    assert_zero_slots(&e);
}

#[test]
fn manifest_same_version_different_bytes() {
    let v1 = verify("manifest.json.asc", None, NOW).unwrap();
    let e = verify_manifest(
        &fixture("manifest-v1-alt.json"),
        &pgp("manifest-v1-alt.json.asc"),
        &signer(),
        Some(&v1),
        NOW,
        SKEW,
    )
    .unwrap_err();
    assert_eq!(e, Error::ManifestVersionConflict { version: 1 });
}

#[test]
fn manifest_refetch_and_upgrade() {
    let v1 = verify("manifest.json.asc", None, NOW).unwrap();
    assert_eq!(verify("manifest.json.asc", Some(&v1), NOW).unwrap(), v1);
    let v2 = verify_manifest(
        &fixture("manifest-v2.json"),
        &pgp("manifest-v2.json.asc"),
        &signer(),
        Some(&v1),
        NOW,
        SKEW,
    )
    .unwrap();
    assert_eq!(v2.version, 2);
}

#[test]
fn signer_key_must_parse() {
    assert!(ManifestSigner::from_bytes(
        b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----\n"
    )
    .is_err());
}

/// JSON validation, run after the signature check. These use the unverified constructor
/// because each needs its own malformed manifest.
mod json {
    use super::*;

    fn base() -> serde_json::Value {
        serde_json::from_slice(&fixture("manifest.json")).unwrap()
    }

    fn reject(v: serde_json::Value, why: &str) {
        let bytes = serde_json::to_vec(&v).unwrap();
        let e = Manifest::from_json_unverified(&bytes).unwrap_err();
        assert!(matches!(e, Error::ManifestMalformed(_)), "{why}: {e}");
    }

    #[test]
    fn rejects_unknown_fields_and_roles() {
        let mut v = base();
        v["extra"] = 1.into();
        reject(v, "unknown top-level field");
        let mut v = base();
        v["keys"][0]["note"] = "x".into();
        reject(v, "unknown key field");
        let mut v = base();
        v["keys"][0]["role"] = "admin".into();
        reject(v, "unknown role");
    }

    #[test]
    fn rejects_inconsistent_keys() {
        let mut v = base();
        let fp1 = v["keys"][1]["fingerprint"].clone();
        v["keys"][0]["fingerprint"] = fp1;
        reject(v, "fingerprint does not match public_key");
        let mut v = base();
        v["keys"][0]["algorithm"] = "rsa-4096".into();
        reject(v, "algorithm does not match public_key");
        let mut v = base();
        v["keys"][1]["role"] = "encrypt".into();
        reject(v, "P-256 key with role encrypt");
        let mut v = base();
        let k0 = v["keys"][0].clone();
        v["keys"].as_array_mut().unwrap().push(k0);
        reject(v, "duplicate fingerprint");
    }

    #[test]
    fn rejects_bad_dates_and_versions() {
        let mut v = base();
        v["valid_until"] = v["issued_at"].clone();
        reject(v, "valid_until == issued_at");
        let mut v = base();
        v["version"] = 7.5.into();
        reject(v, "fractional version");
        let mut v = base();
        v["v"] = 2.into();
        reject(v, "v = 2");
    }

    #[test]
    fn rejects_duplicate_json_keys() {
        let s = String::from_utf8(fixture("manifest.json")).unwrap();
        let dup = s.replacen("\"v\": 1,", "\"v\": 1,\n  \"v\": 1,", 1);
        assert_ne!(dup, s);
        assert!(Manifest::from_json_unverified(dup.as_bytes()).is_err());
    }
}
