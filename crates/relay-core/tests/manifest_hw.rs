//! wire-format §9.4 policy, applied by `verify_manifest`. Failure handling row: "Manifest's
//! hardware attestation missing (when required), invalid or outside policy" (zero slots).

use relay_core::hw_attestation::testing::{LeafOptions, TestHierarchy};
use relay_core::{
    verify_manifest, DraftKey, Error, FailureRow, HardwarePolicy, ManifestDraft, ManifestSigner,
    PgpSecretKey, PublicKey, Role,
};

/// The time the test runs: rPGP signs manifests at the real current time, so a fixed time
/// would turn every signature into one "created in the future" once the clock passed it.
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
const SERIAL: u32 = 7_654_321;

fn p256() -> PublicKey {
    let k = <p256::ecdsa::SigningKey as p256::elliptic_curve::Generate>::generate_from_rng(
        &mut rand_core::UnwrapErr(getrandom::SysRng),
    );
    let der = p256::pkcs8::EncodePublicKey::to_public_key_der(k.verifying_key()).unwrap();
    PublicKey::from_spki(der.as_bytes()).unwrap()
}

struct Fx {
    h: TestHierarchy,
    pgp: PgpSecretKey,
    signer: ManifestSigner,
}

impl Fx {
    fn new() -> Self {
        let pgp = PgpSecretKey::generate("test <t@example.invalid>").unwrap();
        let signer = ManifestSigner::from_bytes(pgp.public_armored().unwrap().as_bytes()).unwrap();
        Fx {
            h: TestHierarchy::new(),
            pgp,
            signer,
        }
    }

    fn policy(&self) -> HardwarePolicy {
        HardwarePolicy::with_roots(vec![self.h.root_der()]).unwrap()
    }

    /// A manifest with one sign key and one attest key; `chain` builds the attest key's chain.
    fn manifest(&self, chain: Option<(u8, u8)>, require: bool) -> (Vec<u8>, Vec<u8>) {
        let d = self.h.device(SERIAL, (5, 7, 4));
        let attest = p256();
        let hw = chain.map(
            |(pin, touch)| relay_core::hw_attestation::HardwareAttestation {
                chain: d.chain(
                    0x85,
                    attest.spki(),
                    &LeafOptions::for_device(&d, pin, touch),
                ),
            },
        );
        let draft = ManifestDraft {
            version: 1,
            issued_at: now() - 100,
            valid_until: now() + 86_400,
            keys: vec![
                DraftKey {
                    role: Role::Sign,
                    label: "sign".into(),
                    id: vec![1],
                    token: "ops".into(),
                    public_key: p256(),
                    hardware_attestation: None,
                },
                DraftKey {
                    role: Role::Attest,
                    label: "attest".into(),
                    id: vec![0x85],
                    token: "card-a".into(),
                    public_key: attest,
                    hardware_attestation: hw,
                },
            ],
            require_hardware_attestation: require,
            ..Default::default()
        };
        let json = draft.to_json().unwrap();
        let sig = self.pgp.sign_detached(&json).unwrap().into_bytes();
        (json, sig)
    }

    fn verify(&self, m: &(Vec<u8>, Vec<u8>)) -> relay_core::Result<relay_core::Manifest> {
        verify_manifest(&m.0, &m.1, &self.signer, &self.policy(), None, now(), 60)
    }
}

fn assert_rejected(r: relay_core::Result<relay_core::Manifest>, needle: &str) {
    match r {
        Err(e @ Error::HardwareAttestationInvalid(_)) => {
            assert!(
                e.to_string().contains(needle),
                "expected '{needle}' in '{e}'"
            );
            assert_eq!(e.failure_row(), FailureRow::ManifestRejected);
            assert_eq!(e.ckr(), None);
        }
        other => panic!("expected HardwareAttestationInvalid, got {other:?}"),
    }
}

#[test]
fn attested_manifest_verifies_and_records_the_card() {
    let fx = Fx::new();
    let m = fx.verify(&fx.manifest(Some((2, 2)), true)).unwrap();
    let a = m.keys.iter().find(|k| k.role == Role::Attest).unwrap();
    let att = a.attested.unwrap();
    assert_eq!(att.serial, SERIAL);
    assert!(m
        .keys
        .iter()
        .find(|k| k.role == Role::Sign)
        .unwrap()
        .attested
        .is_none());
    // The chain round-trips through the draft.
    let d = ManifestDraft::from_json(m.bytes()).unwrap();
    assert_eq!(d.to_json().unwrap(), m.bytes());
}

#[test]
fn missing_chain_is_rejected_by_default_and_accepted_when_not_required() {
    let fx = Fx::new();
    assert_rejected(
        fx.verify(&fx.manifest(None, true)),
        "has no hardware attestation",
    );
    assert!(relay_core::ManifestDraft::default().require_hardware_attestation);
    fx.verify(&fx.manifest(None, false)).unwrap();
}

#[test]
fn attest_key_needs_touch_always_and_a_pin() {
    let fx = Fx::new();
    assert_rejected(
        fx.verify(&fx.manifest(Some((2, 3)), true)),
        "touch policy cached",
    );
    assert_rejected(
        fx.verify(&fx.manifest(Some((2, 1)), true)),
        "touch policy never",
    );
    assert_rejected(
        fx.verify(&fx.manifest(Some((1, 2)), true)),
        "PIN policy never",
    );
    fx.verify(&fx.manifest(Some((3, 2)), true)).unwrap();
    // Even when chains are optional, a chain that is present must pass.
    assert_rejected(
        fx.verify(&fx.manifest(Some((2, 3)), false)),
        "touch policy cached",
    );
}

#[test]
fn chain_from_another_hierarchy_is_rejected() {
    let fx = Fx::new();
    let m = fx.manifest(Some((2, 2)), true);
    let other = HardwarePolicy::with_roots(vec![TestHierarchy::new().root_der()]).unwrap();
    let e = verify_manifest(&m.0, &m.1, &fx.signer, &other, None, now(), 60);
    assert_rejected(e, "key attest");
    // The built-in Yubico root does not accept the synthetic chain either.
    let e = verify_manifest(
        &m.0,
        &m.1,
        &fx.signer,
        &HardwarePolicy::default(),
        None,
        now(),
        60,
    );
    assert_rejected(e, "does not verify");
}

#[test]
fn malformed_hardware_attestation_json_is_rejected() {
    let fx = Fx::new();
    let (json, _) = fx.manifest(Some((2, 2)), true);
    let mut v: serde_json::Value = serde_json::from_slice(&json).unwrap();
    let edits: [(&str, serde_json::Value); 4] = [
        ("format", serde_json::json!("tpm")),
        ("chain", serde_json::json!(["AAAA"])),
        ("chain", serde_json::json!(["not base64!", "AAAA"])),
        ("extra", serde_json::json!(1)),
    ];
    for (field, value) in edits {
        let mut m = v.clone();
        m["keys"][1]["hardware_attestation"][field] = value;
        let bytes = serde_json::to_vec(&m).unwrap();
        let sig = fx.pgp.sign_detached(&bytes).unwrap().into_bytes();
        let e =
            verify_manifest(&bytes, &sig, &fx.signer, &fx.policy(), None, now(), 60).unwrap_err();
        assert!(matches!(e, Error::ManifestMalformed(_)), "{field}: {e}");
    }
    // `null` is the same as no chain, which a manifest that doesn't require one accepts.
    v["keys"][1]["hardware_attestation"] = serde_json::json!(null);
    v["require_hardware_attestation"] = serde_json::json!(false);
    let bytes = serde_json::to_vec(&v).unwrap();
    let sig = fx.pgp.sign_detached(&bytes).unwrap().into_bytes();
    verify_manifest(&bytes, &sig, &fx.signer, &fx.policy(), None, now(), 60).unwrap();
}

#[test]
fn device_policy_fields_are_required_and_bounded() {
    let fx = Fx::new();
    let (json, _) = fx.manifest(Some((2, 2)), true);
    let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
    assert_eq!(v["max_attestation_window_secs"], 7 * 86_400);
    assert_eq!(v["max_client_grant_window_secs"], 30 * 86_400);
    let cases: [(&str, Option<serde_json::Value>); 8] = [
        ("max_client_grant_window_secs", None),
        ("max_client_grant_window_secs", Some(serde_json::json!(59))),
        (
            "max_client_grant_window_secs",
            Some(serde_json::json!(365 * 86_400 + 1)),
        ),
        ("require_hardware_attestation", None),
        ("max_attestation_window_secs", None),
        ("max_attestation_window_secs", Some(serde_json::json!(59))),
        (
            "max_attestation_window_secs",
            Some(serde_json::json!(365 * 86_400 + 1)),
        ),
        (
            "require_hardware_attestation",
            Some(serde_json::json!("yes")),
        ),
    ];
    for (field, value) in cases {
        let mut m = v.clone();
        match value {
            None => {
                m.as_object_mut().unwrap().remove(field);
            }
            Some(x) => m[field] = x,
        }
        let bytes = serde_json::to_vec(&m).unwrap();
        let sig = fx.pgp.sign_detached(&bytes).unwrap().into_bytes();
        let e =
            verify_manifest(&bytes, &sig, &fx.signer, &fx.policy(), None, now(), 60).unwrap_err();
        assert!(matches!(e, Error::ManifestMalformed(_)), "{field}: {e}");
    }
}

fn fp(n: u8) -> String {
    format!("sha256:{}", hex::encode([n; 32]))
}

#[test]
fn revocation_lists_are_sorted_bounded_fingerprints() {
    let fx = Fx::new();
    let (json, _) = fx.manifest(Some((2, 2)), true);
    let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
    let signed = |m: &serde_json::Value| {
        let bytes = serde_json::to_vec(m).unwrap();
        let sig = fx.pgp.sign_detached(&bytes).unwrap().into_bytes();
        verify_manifest(&bytes, &sig, &fx.signer, &fx.policy(), None, now(), 60)
    };
    // Absent means empty.
    let m = signed(&v).unwrap();
    assert!(m.revoked_clients.is_empty() && m.revoked_devices.is_empty());
    for field in ["revoked_clients", "revoked_devices"] {
        let mut ok = v.clone();
        ok[field] = serde_json::json!([fp(1), fp(2)]);
        let m = signed(&ok).unwrap();
        let first = relay_core::Fingerprint::parse(&fp(1)).unwrap();
        let other = relay_core::Fingerprint::parse(&fp(3)).unwrap();
        if field == "revoked_clients" {
            assert!(m.client_revoked(&first) && !m.client_revoked(&other));
            assert!(!m.device_revoked(&first));
        } else {
            assert!(m.device_revoked(&first) && !m.device_revoked(&other));
            assert!(!m.client_revoked(&first));
        }
        let too_many: Vec<String> = (0..=1_024u32)
            .map(|i| format!("sha256:{:064x}", i))
            .collect();
        let bad = [
            serde_json::json!([fp(2), fp(1)]),
            serde_json::json!([fp(1), fp(1)]),
            serde_json::json!(["sha256:abc"]),
            serde_json::json!([fp(1).to_uppercase()]),
            serde_json::json!(too_many),
            serde_json::json!("sha256:x"),
        ];
        for b in bad {
            let mut m = v.clone();
            m[field] = b;
            let e = signed(&m).unwrap_err();
            assert!(matches!(e, Error::ManifestMalformed(_)), "{field}: {e}");
        }
    }
}

#[test]
fn drafts_write_revocation_lists_sorted_and_only_when_present() {
    let fx = Fx::new();
    let (json, _) = fx.manifest(Some((2, 2)), true);
    let mut d = ManifestDraft::from_json(&json).unwrap();
    assert!(!String::from_utf8_lossy(&d.to_json().unwrap()).contains("revoked_"));
    let f = |n| relay_core::Fingerprint::parse(&fp(n)).unwrap();
    d.revoked_clients = vec![f(9), f(3), f(9)];
    d.revoked_devices = vec![f(4)];
    let out = d.to_json().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["revoked_clients"], serde_json::json!([fp(3), fp(9)]));
    assert_eq!(v["revoked_devices"], serde_json::json!([fp(4)]));
    let back = ManifestDraft::from_json(&out).unwrap();
    assert_eq!(back.revoked_clients, vec![f(3), f(9)]);
}
