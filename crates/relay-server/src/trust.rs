//! The relay's check of the manifest it serves (spec: Relay, "Check the manifest").
//!
//! This is hygiene, not trust: clients verify everything themselves. It makes a bad manifest
//! visible in one place and stops the relay from advertising keys or devices that clients
//! would refuse. All verification is relay-core's.

use std::sync::Mutex;

use relay_core::attestation::verify_attestation_signer;
use relay_core::{HardwarePolicy, Manifest, ManifestSigner};

use crate::config::Config;
use crate::db::DeviceRecord;

/// What the relay currently knows about its manifest.
#[derive(Debug, Clone)]
pub enum View {
    /// No `manifest_file`: advertisements are not filtered (clients still filter them).
    Unconfigured,
    Valid(Box<Manifest>),
    /// Advertise nothing.
    Invalid(String),
}

struct Cached {
    bytes: Vec<u8>,
    sig: Vec<u8>,
    signer: String,
    result: Result<Manifest, String>,
}

/// Verifies the manifest with the key the relay's signer watch currently holds.
pub struct ManifestCheck {
    policy: HardwarePolicy,
    cached: Mutex<Option<Cached>>,
    /// The last problem logged, so a persistent one is logged once, not per request.
    last_logged: Mutex<Option<String>>,
}

impl std::fmt::Debug for ManifestCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManifestCheck").finish_non_exhaustive()
    }
}

impl ManifestCheck {
    pub fn new(cfg: &Config) -> Result<Self, String> {
        let policy = cfg
            .hardware_attestation
            .policy()
            .map_err(|e| format!("hardware_attestation: {e}"))?;
        if let Some(w) = cfg.hardware_attestation.warning() {
            tracing::warn!("{w}");
        }
        Ok(ManifestCheck {
            policy,
            cached: Mutex::new(None),
            last_logged: Mutex::new(None),
        })
    }

    /// Re-read the manifest files and verify them if they changed; then check freshness.
    pub fn view(&self, cfg: &Config, now: u64, signer: Option<&ManifestSigner>) -> View {
        let (Some(path), Some(signer)) = (&cfg.manifest_file, signer) else {
            return View::Unconfigured;
        };
        let read =
            |p: &std::path::Path| std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()));
        let files = read(path).and_then(|b| read(&cfg.manifest_signature_path()).map(|s| (b, s)));
        let view = match files {
            Err(e) => View::Invalid(format!("manifest unreadable: {e}")),
            Ok((bytes, sig)) => {
                let mut cached = self.cached.lock().unwrap_or_else(|e| e.into_inner());
                let fpr = signer.fingerprint();
                let fresh = !matches!(&*cached, Some(c) if c.bytes == bytes && c.sig == sig && c.signer == fpr);
                if fresh {
                    let result = relay_core::verify_manifest(
                        &bytes,
                        &sig,
                        signer,
                        &self.policy,
                        None,
                        now,
                        cfg.skew_secs,
                    )
                    .map_err(|e| format!("{e} ({})", e.kind()));
                    if let Ok(m) = &result {
                        tracing::info!(
                            version = m.version,
                            keys = m.keys.len(),
                            "manifest verified"
                        );
                    }
                    *cached = Some(Cached {
                        bytes,
                        sig,
                        signer: fpr,
                        result,
                    });
                }
                match &cached.as_ref().expect("cached").result {
                    Err(e) => View::Invalid(e.clone()),
                    Ok(m) => match m.check_fresh(now, cfg.skew_secs) {
                        Ok(()) => View::Valid(Box::new(m.clone())),
                        Err(e) => View::Invalid(format!("{e} ({})", e.kind())),
                    },
                }
            }
        };
        let mut last = self.last_logged.lock().unwrap_or_else(|e| e.into_inner());
        match &view {
            View::Invalid(e) if last.as_deref() != Some(e) => {
                tracing::error!(error = %e, "manifest invalid: advertising no keys");
                *last = Some(e.clone());
            }
            View::Valid(_) => *last = None,
            _ => {}
        }
        view
    }
}

impl View {
    /// Whether a device's advertisement of `fp` counts: always without a manifest; with one,
    /// only for keys it lists outside the `attest` role, from devices whose attestation
    /// verifies against it.
    pub fn counts(&self, d: &DeviceRecord, fp: &str) -> bool {
        if !d.advertises(fp) {
            return false;
        }
        match self {
            View::Unconfigured => true,
            View::Invalid(_) => false,
            View::Valid(m) => {
                let listed = relay_core::Fingerprint::parse(fp)
                    .ok()
                    .and_then(|f| m.key(&f))
                    .is_some_and(|k| k.role != relay_core::Role::Attest);
                listed && device_attested(d, m)
            }
        }
    }
}

/// The device's stored attestation is signed by a manifest attest key and names this device
/// and key. Its window is not checked: an expired device keeps receiving requests so it can
/// renew during an approval, and clients reject its responses until then.
pub fn device_attested(d: &DeviceRecord, m: &Manifest) -> bool {
    verify_attestation_signer(&d.attestation, m).is_ok_and(|a| {
        a.device_key.spki() == d.device_key.as_slice()
            && a.device_id == d.device_id
            && !m.device_revoked(a.device_key.fingerprint())
    })
}

#[cfg(test)]
mod tests {
    //! Failure handling row "Relay's own manifest copy invalid": the relay advertises no keys.

    use std::path::{Path, PathBuf};

    use relay_core::attestation::UnsignedAttestation;
    use relay_core::hw_attestation::testing::{to_pem, LeafOptions, TestHierarchy};
    use relay_core::hw_attestation::{HardwareAttestation, PolicyConfig};
    use relay_core::manifest::{DraftKey, ManifestDraft};
    use relay_core::signing::SoftwareKey;
    use relay_core::{PgpSecretKey, PublicKey, Role};

    use super::*;
    use crate::db::{AdvertisedKey, PushTarget};

    fn now() -> u64 {
        crate::state::now()
    }

    struct Fx {
        dir: PathBuf,
        pgp: PgpSecretKey,
        h: TestHierarchy,
        attest: SoftwareKey,
        sign: PublicKey,
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("relay-trust-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    impl Fx {
        fn new(name: &str) -> Self {
            let dir = tmp(name);
            let pgp = PgpSecretKey::generate("t <t@test.invalid>").unwrap();
            std::fs::write(dir.join("signer.asc"), pgp.public_armored().unwrap()).unwrap();
            let h = TestHierarchy::new();
            std::fs::write(dir.join("root.pem"), to_pem(&[h.root_der()])).unwrap();
            Fx {
                dir,
                pgp,
                h,
                attest: SoftwareKey::generate_p256(),
                sign: SoftwareKey::generate_p256().public_key(),
            }
        }

        fn signer(&self) -> ManifestSigner {
            ManifestSigner::from_bytes(self.pgp.public_armored().unwrap().as_bytes()).unwrap()
        }

        fn cfg(&self) -> Config {
            Config {
                manifest_file: Some(self.dir.join("manifest.json")),
                manifest_signer: Some(self.dir.join("signer.asc")),
                hardware_attestation: PolicyConfig {
                    roots_file: Some(self.dir.join("root.pem")),
                },
                ..Default::default()
            }
        }

        /// Write and sign a manifest; `chain` gives the attest key its YubiKey attestation.
        fn publish(&self, chain: bool, valid_until: u64) {
            let d = self.h.device(4242, (5, 7, 4));
            let attest = self.attest.public_key();
            let hw = chain.then(|| HardwareAttestation {
                chain: d.chain(0x85, attest.spki(), &LeafOptions::for_device(&d, 2, 2)),
            });
            let key = |role, label: &str, id, pk, hw| DraftKey {
                role,
                label: label.into(),
                id: vec![id],
                token: "t".into(),
                public_key: pk,
                hardware_attestation: hw,
            };
            let json = ManifestDraft {
                version: 1,
                issued_at: now() - 100,
                valid_until,
                keys: vec![
                    key(Role::Attest, "attest", 1, attest, hw),
                    key(Role::Sign, "sign", 2, self.sign.clone(), None),
                ],
                ..Default::default()
            }
            .to_json()
            .unwrap();
            write(&self.dir.join("manifest.json"), &json);
            write(
                &self.dir.join("manifest.json.asc"),
                self.pgp.sign_detached(&json).unwrap().as_bytes(),
            );
        }

        fn device(
            &self,
            signer: &SoftwareKey,
            window: (u64, u64),
            keys: &[&PublicKey],
        ) -> DeviceRecord {
            let dk = SoftwareKey::generate_p256().public_key();
            let st = UnsignedAttestation::new(
                "phone",
                dk.clone(),
                window.0,
                window.1,
                signer.public_key().fingerprint().clone(),
            )
            .unwrap();
            let sig = signer.sign(&st.to_be_signed());
            DeviceRecord {
                device_id: "phone".into(),
                device_key: dk.spki().to_vec(),
                fingerprint: dk.fingerprint().to_string(),
                auth_key: dk.spki().to_vec(),
                auth_fingerprint: dk.fingerprint().to_string(),
                admin_key: None,
                admin_fingerprint: None,
                attestation: st.with_signature(sig).bytes().to_vec(),
                keys: keys
                    .iter()
                    .map(|k| AdvertisedKey {
                        fingerprint: k.fingerprint().to_string(),
                        public_key: String::new(),
                        token: "t".into(),
                    })
                    .collect(),
                push: PushTarget::None,
                last_seen: 0,
                created_at: 0,
                setup_link_id: None,
            }
        }
    }

    fn write(p: &Path, b: &[u8]) {
        // A new file each time, so the relay's change check sees new bytes.
        std::fs::write(p, b).unwrap();
    }

    #[test]
    fn manifest_file_needs_a_signer() {
        let cfg = Config {
            manifest_file: Some("/nonexistent/manifest.json".into()),
            ..Default::default()
        };
        assert!(crate::signer_watch::SignerWatch::new(&cfg)
            .err()
            .is_some_and(|e| e.contains("manifest_signer")));
        let unconfigured = ManifestCheck::new(&Config::default()).unwrap();
        assert!(matches!(
            unconfigured.view(&Config::default(), now(), None),
            View::Unconfigured
        ));
    }

    #[test]
    fn valid_manifest_filters_advertisements() {
        let fx = Fx::new("valid");
        fx.publish(true, now() + 86_400);
        let cfg = fx.cfg();
        let check = ManifestCheck::new(&cfg).unwrap();
        let view = check.view(&cfg, now(), Some(&fx.signer()));
        assert!(matches!(view, View::Valid(_)), "{view:?}");
        let t = now();
        let current = (t - 10, t + 3600);
        let sign_fp = fx.sign.fingerprint().to_string();
        let attest_fp = fx.attest.public_key().fingerprint().to_string();
        let stranger = SoftwareKey::generate_p256().public_key();

        let good = fx.device(
            &fx.attest,
            current,
            &[&fx.sign, &fx.attest.public_key(), &stranger],
        );
        assert!(view.counts(&good, &sign_fp));
        assert!(
            !view.counts(&good, &attest_fp),
            "attest keys are never advertised"
        );
        assert!(
            !view.counts(&good, &stranger.fingerprint().to_string()),
            "not in the manifest"
        );

        let rogue = fx.device(&SoftwareKey::generate_p256(), current, &[&fx.sign]);
        assert!(
            !view.counts(&rogue, &sign_fp),
            "attested by a key the manifest does not list"
        );

        // An expired attestation still counts: the device renews during its next approval.
        let stale = fx.device(&fx.attest, (t - 7200, t - 3600), &[&fx.sign]);
        assert!(view.counts(&stale, &sign_fp));
    }

    #[test]
    fn invalid_manifest_advertises_nothing_until_fixed() {
        let fx = Fx::new("invalid");
        let cfg = fx.cfg();
        let check = ManifestCheck::new(&cfg).unwrap();
        let t = now();
        let device = fx.device(&fx.attest, (t - 10, t + 3600), &[&fx.sign]);
        let sign_fp = fx.sign.fingerprint().to_string();

        // Missing file.
        assert!(
            matches!(check.view(&cfg, t, Some(&fx.signer())), View::Invalid(e) if e.contains("unreadable"))
        );
        // No hardware attestation while it is required.
        fx.publish(false, t + 86_400);
        let v = check.view(&cfg, t, Some(&fx.signer()));
        assert!(
            matches!(&v, View::Invalid(e) if e.contains("HardwareAttestationInvalid")),
            "{v:?}"
        );
        assert!(!v.counts(&device, &sign_fp));
        // Expired.
        fx.publish(true, t + 30);
        let v = check.view(&cfg, t + 3600, Some(&fx.signer()));
        assert!(
            matches!(&v, View::Invalid(e) if e.contains("ManifestExpired")),
            "{v:?}"
        );
        // Bad signature.
        std::fs::write(fx.dir.join("manifest.json"), b"{}").unwrap();
        let v = check.view(&cfg, t, Some(&fx.signer()));
        assert!(
            matches!(&v, View::Invalid(e) if e.contains("ManifestSignatureInvalid")),
            "{v:?}"
        );
        // Fixed: valid again.
        fx.publish(true, t + 86_400);
        let v = check.view(&cfg, t, Some(&fx.signer()));
        assert!(v.counts(&device, &sign_fp), "{v:?}");
    }
}
