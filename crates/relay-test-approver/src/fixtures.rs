//! `gen-fixtures`: a throwaway PGP signer, softcard keys for every role across three simulated
//! devices, a signed manifest, and the configs compose and the in-process tests use.
//!
//! Device A approves (and pairs the test client); device B denies after a delay; device C
//! answers with an expired attestation. All three hold the same attest key.

use std::path::Path;

use base64::Engine as _;
use relay_core::manifest::{DraftKey, ManifestDraft};
use relay_core::piv::Slot;
use relay_core::signing::SoftwareKey;
use relay_core::{Algorithm, PgpSecretKey, PublicKey, Role};
use relay_softcard::{SlotKey, SoftCard};

pub const CLIENT_ID: &str = "openbao-pi5";
pub const PIN: &str = "123456";

struct Spec {
    card: &'static str,
    slot: u8,
    alg: Algorithm,
    role: Role,
    label: &'static str,
}

const SPECS: &[Spec] = &[
    Spec {
        card: "a",
        slot: 0x9d,
        alg: Algorithm::Rsa2048,
        role: Role::Encrypt,
        label: "openbao-unseal",
    },
    Spec {
        card: "a",
        slot: 0x9c,
        alg: Algorithm::P256,
        role: Role::Sign,
        label: "sign-ec",
    },
    Spec {
        card: "a",
        slot: 0x82,
        alg: Algorithm::Rsa2048,
        role: Role::Sign,
        label: "sign-rsa",
    },
    Spec {
        card: "a",
        slot: 0x9a,
        alg: Algorithm::P256,
        role: Role::Auth,
        label: "auth-ec",
    },
    Spec {
        card: "a",
        slot: 0x83,
        alg: Algorithm::Rsa2048,
        role: Role::Auth,
        label: "auth-rsa",
    },
    Spec {
        card: "a",
        slot: 0x84,
        alg: Algorithm::P256,
        role: Role::Auth,
        label: "unapproved",
    },
    Spec {
        card: "b",
        slot: 0x85,
        alg: Algorithm::P256,
        role: Role::Auth,
        label: "denied",
    },
    Spec {
        card: "c",
        slot: 0x86,
        alg: Algorithm::P256,
        role: Role::Auth,
        label: "stale",
    },
];

fn w(path: &Path, data: impl AsRef<[u8]>) -> Result<(), String> {
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    std::fs::write(path, data).map_err(|e| format!("{}: {e}", path.display()))
}

/// Generate into `out`. Paths inside configs start with `root` (where `out` is mounted).
pub fn generate(
    out: &Path,
    root: &str,
    relay_url: &str,
    pairing_cidrs: &[String],
    now: u64,
) -> Result<(), String> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let attest = SlotKey::generate(Algorithm::P256);
    let attest_pk = attest.public_key();
    let attest_cert = attest.self_signed_certificate("relay fixture attest");
    let attest_slot = Slot::new(0x95).expect("slot");
    let mut keys = Vec::new();
    for (i, s) in SPECS.iter().enumerate() {
        let k = SlotKey::generate(s.alg);
        let cert = k.self_signed_certificate(&format!("relay fixture {}", s.label));
        SoftCard::write_slot(
            &out.join(format!("softcard-{}", s.card)),
            Slot::new(s.slot).expect("slot"),
            &k,
            &cert,
        )
        .map_err(|e| e.to_string())?;
        keys.push(DraftKey {
            role: s.role,
            label: s.label.into(),
            id: vec![i as u8 + 1],
            token: format!("softcard-{}", s.card),
            public_key: k.public_key(),
        });
    }
    for card in ["a", "b", "c"] {
        SoftCard::write_slot(
            &out.join(format!("softcard-{card}")),
            attest_slot,
            &attest,
            &attest_cert,
        )
        .map_err(|e| e.to_string())?;
    }
    keys.push(DraftKey {
        role: Role::Attest,
        label: "attest".into(),
        id: vec![0x99],
        token: "softcard-a".into(),
        public_key: attest_pk,
    });

    let draft = ManifestDraft {
        version: 1,
        issued_at: now - 60,
        valid_until: now + 7 * 86_400,
        keys: keys.clone(),
    };
    let manifest = draft.to_json().map_err(|e| e.to_string())?;
    let pgp = PgpSecretKey::generate("pkcs11-relay test fixtures <fixtures@test.invalid>")
        .map_err(|e| e.to_string())?;
    w(&out.join("manifest.json"), &manifest)?;
    w(
        &out.join("manifest.json.asc"),
        pgp.sign_detached(&manifest).map_err(|e| e.to_string())?,
    )?;
    w(
        &out.join("signer.asc"),
        pgp.public_armored().map_err(|e| e.to_string())?,
    )?;
    w(
        &out.join("signer-secret.asc"),
        pgp.to_armored().map_err(|e| e.to_string())?.as_bytes(),
    )?;
    w(&out.join("pin"), PIN)?;

    let client = SoftwareKey::generate_ed25519();
    w(
        &out.join("client.pem"),
        client.to_pkcs8_pem().map_err(|e| e.to_string())?.as_bytes(),
    )?;
    let client_pub = b64.encode(client.public_key().spki());
    let fp = |label: &str| -> String {
        keys.iter()
            .find(|k| k.label == label)
            .map(|k| PublicKey::fingerprint(&k.public_key).to_string())
            .expect("label")
    };
    let approved: Vec<String> = [
        "openbao-unseal",
        "sign-ec",
        "sign-rsa",
        "auth-ec",
        "auth-rsa",
        "denied",
        "stale",
    ]
    .iter()
    .map(|l| fp(l))
    .collect();

    let cidrs = pairing_cidrs
        .iter()
        .map(|c| format!("{c:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    w(&out.join("relay.toml"), format!("listen = \"0.0.0.0:8080\"\ndata_dir = \"/data\"\npairing_allowed_cidrs = [{cidrs}]\n\n[notify]\nkind = \"log\"\n"))?;
    for (card, approve) in [("a", true), ("b", false), ("c", false)] {
        let cfg = format!(
            "relay_url = {relay_url:?}\ndevice_id = \"approver-{card}\"\ndata_dir = \"{root}/state/approver-{card}\"\n\
             manifest_url = \"file://{root}/manifest.json\"\nmanifest_signer = \"{root}/signer.asc\"\n\
             softcard_dir = \"{root}/softcard-{card}\"\npin_file = \"{root}/pin\"\nattest_slot = \"95\"\n\n\
             [[trusted_clients]]\nclient_id = \"{CLIENT_ID}\"\npublic_key = \"{client_pub}\"\nkeys = {approved:?}\napprove_pairing = {approve}\n"
        );
        w(&out.join(format!("approver-{card}.toml")), cfg)?;
    }
    w(
        &out.join("gate.toml"),
        format!(
            "relay_url = {relay_url:?}\nmanifest_url = \"file://{root}/manifest.json\"\nmanifest_signer = \"{root}/signer.asc\"\n\
             client_key = \"{root}/client.pem\"\nclient_id = \"{CLIENT_ID}\"\n"
        ),
    )?;
    Ok(())
}
