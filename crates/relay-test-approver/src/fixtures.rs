//! `gen-fixtures`: a throwaway PGP signer, softcard keys for every role across three simulated
//! devices, a signed manifest, and the configs compose and the in-process tests use.
//!
//! Device A approves (and pairs the test client); device B denies after a delay; device C
//! answers with an expired attestation. All three hold the same attest key, whose YubiKey
//! attestation chain comes from a synthetic hierarchy: `attestation-root.pem` is its root, for
//! the configs' `[hardware_attestation] roots_file`, and `attestation-anchors.pem` is the root
//! followed by its intermediates, for `relayctl --attestation-roots`.

use std::path::Path;

use base64::Engine as _;
use relay_core::hw_attestation::testing::{LeafOptions, TestHierarchy};
use relay_core::hw_attestation::HardwareAttestation;
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
    // ECC encryption, P-384 and Ed25519 signing (appended so earlier CKA_IDs stay stable).
    Spec {
        card: "a",
        slot: 0x87,
        alg: Algorithm::P256,
        role: Role::Encrypt,
        label: "enc-p256",
    },
    Spec {
        card: "a",
        slot: 0x88,
        alg: Algorithm::P384,
        role: Role::Encrypt,
        label: "enc-p384",
    },
    Spec {
        card: "a",
        slot: 0x89,
        alg: Algorithm::X25519,
        role: Role::Encrypt,
        label: "enc-x25519",
    },
    Spec {
        card: "a",
        slot: 0x8a,
        alg: Algorithm::P384,
        role: Role::Sign,
        label: "sign-p384",
    },
    Spec {
        card: "a",
        slot: 0x8b,
        alg: Algorithm::P384,
        role: Role::Auth,
        label: "auth-p384",
    },
    Spec {
        card: "a",
        slot: 0x8c,
        alg: Algorithm::Ed25519,
        role: Role::Sign,
        label: "sign-ed25519",
    },
    Spec {
        card: "a",
        slot: 0x8d,
        alg: Algorithm::Ed25519,
        role: Role::Auth,
        label: "auth-ed25519",
    },
];

/// Serial of the synthetic card that "generated" the fixture attest key.
pub const ATTEST_SERIAL: u32 = 20_261_117;

fn pem_certs(ders: &[Vec<u8>]) -> Result<String, String> {
    Ok(relay_core::hw_attestation::testing::to_pem(ders))
}

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
            hardware_attestation: None,
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
    let hierarchy = TestHierarchy::new();
    let device = hierarchy.device(ATTEST_SERIAL, (5, 7, 4));
    let chain = device.chain(
        attest_slot.id(),
        attest_pk.spki(),
        &LeafOptions::for_device(&device, 0x02, 0x02),
    );
    w(
        &out.join("attestation-root.pem"),
        pem_certs(&[hierarchy.root_der()])?,
    )?;
    let mut anchors = vec![hierarchy.root_der()];
    anchors.extend(hierarchy.intermediates());
    w(&out.join("attestation-anchors.pem"), pem_certs(&anchors)?)?;
    keys.push(DraftKey {
        role: Role::Attest,
        label: "attest".into(),
        id: vec![0x99],
        token: "softcard-a".into(),
        public_key: attest_pk,
        hardware_attestation: Some(HardwareAttestation { chain }),
    });

    let draft = ManifestDraft {
        version: 1,
        issued_at: now - 60,
        valid_until: now + 7 * 86_400,
        keys: keys.clone(),
        ..Default::default()
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
    // The same manifest, except that the attest key's attestation shows touch `never`: the
    // provider must refuse it (Failure handling: hardware attestation outside policy).
    let mut weak = draft.clone();
    for k in weak.keys.iter_mut().filter(|k| k.role == Role::Attest) {
        k.hardware_attestation = Some(HardwareAttestation {
            chain: device.chain(
                attest_slot.id(),
                k.public_key.spki(),
                &LeafOptions::for_device(&device, 0x02, 0x01),
            ),
        });
    }
    let weak = weak.to_json().map_err(|e| e.to_string())?;
    w(&out.join("manifest-touch-never.json"), &weak)?;
    w(
        &out.join("manifest-touch-never.json.asc"),
        pgp.sign_detached(&weak).map_err(|e| e.to_string())?,
    )?;
    w(
        &out.join("signer-secret.asc"),
        pgp.to_armored().map_err(|e| e.to_string())?.as_bytes(),
    )?;
    w(&out.join("pin"), PIN)?;
    tls_material(out)?;

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
        "enc-p256",
        "enc-p384",
        "enc-x25519",
        "sign-p384",
        "auth-p384",
        "sign-ed25519",
        "auth-ed25519",
    ]
    .iter()
    .map(|l| fp(l))
    .collect();

    let hw = format!("\n[hardware_attestation]\nroots_file = \"{root}/attestation-root.pem\"\n");
    let cidrs = pairing_cidrs
        .iter()
        .map(|c| format!("{c:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    w(&out.join("relay.toml"), format!("listen = \"0.0.0.0:8443\"\ntls_cert = \"{root}/relay-cert.pem\"\ntls_key = \"{root}/relay-key.pem\"\ndata_dir = \"/data\"\n# Two gates in one minute: above the default of 30 requests per minute.\nclient_requests_per_minute = 120\npairing_allowed_cidrs = [{cidrs}]\nmanifest_file = \"{root}/manifest.json\"\nmanifest_signer = \"{root}/signer.asc\"\n\n[notify]\nkind = \"log\"\n{hw}"))?;
    for (card, approve) in [("a", true), ("b", false), ("c", false)] {
        let cfg = format!(
            "relay_url = {relay_url:?}\nrelay_ca_file = \"{root}/relay-ca.pem\"\ndevice_id = \"approver-{card}\"\ndata_dir = \"{root}/state/approver-{card}\"\n\
             manifest_url = \"file://{root}/manifest.json\"\nmanifest_signer = \"{root}/signer.asc\"\n\
             softcard_dir = \"{root}/softcard-{card}\"\npin_file = \"{root}/pin\"\nattest_slot = \"95\"\n\n\
             [[trusted_clients]]\nclient_id = \"{CLIENT_ID}\"\npublic_key = \"{client_pub}\"\nkeys = {approved:?}\napprove_pairing = {approve}\n{hw}"
        );
        w(&out.join(format!("approver-{card}.toml")), cfg)?;
    }
    w(
        &out.join("gate.toml"),
        format!(
            "relay_url = {relay_url:?}\nrelay_ca_file = \"{root}/relay-ca.pem\"\nmanifest_url = \"file://{root}/manifest.json\"\nmanifest_signer = \"{root}/signer.asc\"\n\
             client_key = \"{root}/client.pem\"\nclient_id = \"{CLIENT_ID}\"\n{hw}"
        ),
    )?;
    // authorized_keys for the test sshd: the auth-ec key in OpenSSH wire format.
    let auth_ec = keys.iter().find(|k| k.label == "auth-ec").expect("auth-ec");
    w(
        &out.join("ssh_authorized_keys"),
        format!("{}\n", ssh_ecdsa_public(&auth_ec.public_key)),
    )?;
    // The PKCS#11 provider's config (RELAY_PKCS11_CONFIG) for the client container.
    w(
        &out.join("provider.toml"),
        format!(
            "relay_url = {relay_url:?}\nrelay_ca_file = \"{root}/relay-ca.pem\"\nmanifest_url = \"{relay_url}/v1/manifest\"\n\
             manifest_signer = \"{root}/signer.asc\"\nmanifest_cache = \"{root}/state/client/manifest.json\"\n\
             client_id = \"{CLIENT_ID}\"\nclient_key = \"{root}/client.pem\"\npurpose = \"milestone 3 gate\"\ntimeout_secs = 30\nlog_level = \"info\"\n{hw}"
        ),
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            out.join("client.pem"),
            std::fs::Permissions::from_mode(0o600),
        );
    }
    Ok(())
}

/// TLS for the test relay: a private CA and a relay certificate it issued for `relay`,
/// `localhost` and `127.0.0.1`. Writes `relay-ca.pem`, `relay-cert.pem`, `relay-key.pem`.
pub fn tls_material(out: &Path) -> Result<(), String> {
    use std::str::FromStr;
    use std::time::Duration;
    use x509_cert::builder::profile::BuilderProfile;
    use x509_cert::builder::{Builder, CertificateBuilder};
    use x509_cert::der::asn1::Ia5String;
    use x509_cert::der::{Decode, EncodePem};
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::ext::pkix::{
        BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectAltName,
    };
    use x509_cert::ext::{Extension, ToExtension};
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::{SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};
    use x509_cert::time::Validity;
    use x509_cert::TbsCertificate;

    struct Ca(Name);
    impl BuilderProfile for Ca {
        fn get_issuer(&self, s: &Name) -> Name {
            s.clone()
        }
        fn get_subject(&self) -> Name {
            self.0.clone()
        }
        fn build_extensions(
            &self,
            _: SubjectPublicKeyInfoRef<'_>,
            _: SubjectPublicKeyInfoRef<'_>,
            tbs: &TbsCertificate,
        ) -> x509_cert::builder::Result<Vec<Extension>> {
            let s = tbs.subject();
            Ok(vec![
                (&BasicConstraints {
                    ca: true,
                    path_len_constraint: Some(0),
                })
                    .to_extension(s, &[])?,
                (&KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign)).to_extension(s, &[])?,
            ])
        }
    }
    struct Leaf {
        issuer: Name,
        subject: Name,
    }
    impl BuilderProfile for Leaf {
        fn get_issuer(&self, _: &Name) -> Name {
            self.issuer.clone()
        }
        fn get_subject(&self) -> Name {
            self.subject.clone()
        }
        fn build_extensions(
            &self,
            _: SubjectPublicKeyInfoRef<'_>,
            _: SubjectPublicKeyInfoRef<'_>,
            tbs: &TbsCertificate,
        ) -> x509_cert::builder::Result<Vec<Extension>> {
            let s = tbs.subject();
            let san = SubjectAltName(vec![
                GeneralName::DnsName(Ia5String::new("relay")?),
                GeneralName::DnsName(Ia5String::new("localhost")?),
                GeneralName::from(std::net::IpAddr::from([127, 0, 0, 1])),
            ]);
            Ok(vec![
                (&BasicConstraints {
                    ca: false,
                    path_len_constraint: None,
                })
                    .to_extension(s, &[])?,
                (&KeyUsage(KeyUsages::DigitalSignature.into())).to_extension(s, &[])?,
                (&ExtendedKeyUsage(vec![x509_cert::der::oid::db::rfc5280::ID_KP_SERVER_AUTH]))
                    .to_extension(s, &[])?,
                (&san).to_extension(s, &[])?,
            ])
        }
    }

    let e = |e: &dyn std::fmt::Display| e.to_string();
    let gen = || {
        <p256::ecdsa::SigningKey as p256::elliptic_curve::Generate>::generate_from_rng(
            &mut rand_core::UnwrapErr(getrandom::SysRng),
        )
    };
    let spki = |k: &p256::ecdsa::SigningKey| {
        SubjectPublicKeyInfoOwned::from_der(PublicKey::spki(
            &SoftwareKey::P256(k.clone()).public_key(),
        ))
        .map_err(|x| x.to_string())
    };
    let validity = Validity::from_now(Duration::from_secs(30 * 86_400)).map_err(|x| e(&x))?;
    let ca_key = gen();
    let ca_name = Name::from_str("CN=pkcs11-relay test CA").map_err(|x| e(&x))?;
    let ca = CertificateBuilder::new(
        Ca(ca_name.clone()),
        SerialNumber::from(1u32),
        validity,
        spki(&ca_key)?,
    )
    .map_err(|x| e(&x))?
    .build::<_, p256::ecdsa::DerSignature>(&ca_key)
    .map_err(|x| e(&x))?;
    let leaf_key = gen();
    let leaf = CertificateBuilder::new(
        Leaf {
            issuer: ca_name,
            subject: Name::from_str("CN=relay").map_err(|x| e(&x))?,
        },
        SerialNumber::from(2u32),
        validity,
        spki(&leaf_key)?,
    )
    .map_err(|x| e(&x))?
    .build::<_, p256::ecdsa::DerSignature>(&ca_key)
    .map_err(|x| e(&x))?;
    let le = x509_cert::der::pem::LineEnding::LF;
    w(&out.join("relay-ca.pem"), ca.to_pem(le).map_err(|x| e(&x))?)?;
    w(
        &out.join("relay-cert.pem"),
        leaf.to_pem(le).map_err(|x| e(&x))?,
    )?;
    let key_pem =
        p256::pkcs8::EncodePrivateKey::to_pkcs8_pem(&leaf_key, p256::pkcs8::LineEnding::LF)
            .map_err(|x| e(&x))?;
    w(&out.join("relay-key.pem"), key_pem.as_bytes())?;
    Ok(())
}

/// `ecdsa-sha2-nistp256 <base64>` for a P-256 key (RFC 5656 §3.1).
pub fn ssh_ecdsa_public(pk: &PublicKey) -> String {
    fn string(out: &mut Vec<u8>, b: &[u8]) {
        out.extend_from_slice(&(b.len() as u32).to_be_bytes());
        out.extend_from_slice(b);
    }
    let mut blob = Vec::new();
    string(&mut blob, b"ecdsa-sha2-nistp256");
    string(&mut blob, b"nistp256");
    string(&mut blob, &pk.ec_point().expect("P-256 key"));
    format!(
        "ecdsa-sha2-nistp256 {}",
        base64::engine::general_purpose::STANDARD.encode(blob)
    )
}
