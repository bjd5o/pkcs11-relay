//! The signed trust manifest (wire-format §9).
//!
//! The OpenPGP signature is verified over the file's exact bytes before any JSON parsing.

use std::collections::HashSet;
use std::io::Cursor;

use base64::Engine as _;
use pgp::composed::{Deserializable, DetachedSignature, SignedPublicKey, SignedSecretKey};
use pgp::crypto::hash::HashAlgorithm;
use pgp::packet::SignatureType;
use serde::Deserialize;

use crate::hw_attestation::{
    verify_piv_attestation, HardwareAttestation, HardwarePolicy, PinPolicy, PivAttestation,
    TouchPolicy, FORMAT_YUBIKEY_PIV, MAX_CERT_LEN, MAX_CHAIN, MIN_CHAIN,
};

use crate::error::{Error, Result};
use crate::keys::{Algorithm, Fingerprint, PublicKey, Role};

/// Largest manifest file accepted (wire-format §9.1).
pub const MAX_MANIFEST_LEN: usize = 1 << 20;

/// Bounds of `max_attestation_window_secs` (wire-format §9.2), and its default in new manifests.
pub const MIN_ATTESTATION_WINDOW: u64 = 60;
pub const MAX_ATTESTATION_WINDOW: u64 = 365 * 86_400;
pub const DEFAULT_MAX_ATTESTATION_WINDOW: u64 = 7 * 86_400;

/// Whether `manifest_url` points at the relay's own `/v1/manifest` (same origin as
/// `relay_url`). Fetchers then use the relay's trust anchors for TLS; the manifest's signature,
/// not the transport, is what makes it trustworthy either way.
pub fn served_by_relay(manifest_url: &str, relay_url: &str) -> bool {
    let base = relay_url.trim_end_matches('/');
    manifest_url
        .strip_prefix(base)
        .is_some_and(|rest| rest.starts_with('/'))
}
/// Largest number of keys in one manifest (wire-format §9.2).
pub const MAX_KEYS: usize = 64;

/// The configured OpenPGP signer: the only root of trust.
#[derive(Clone)]
pub struct ManifestSigner {
    key: SignedPublicKey,
}

impl std::fmt::Debug for ManifestSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use pgp::types::KeyDetails;
        write!(
            f,
            "ManifestSigner({:?})",
            self.key.primary_key.fingerprint()
        )
    }
}

impl ManifestSigner {
    /// The primary key's OpenPGP fingerprint, uppercase hex as `gpg --fingerprint` prints it
    /// (without spaces): what a person compares when configuring a client or an app.
    pub fn fingerprint(&self) -> String {
        use pgp::types::KeyDetails;
        hex::encode_upper(self.key.primary_key.fingerprint().as_bytes())
    }

    /// Load an OpenPGP public key, armored or binary, and check its self-signatures and subkey
    /// bindings.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bad =
            |e: pgp::errors::Error| Error::ManifestSignatureInvalid(format!("signer key: {e}"));
        let (key, _) = SignedPublicKey::from_reader_single(Cursor::new(bytes)).map_err(bad)?;
        key.verify_bindings().map_err(bad)?;
        Ok(ManifestSigner { key })
    }

    /// Verify a detached signature over `data` (wire-format §9.1 rules).
    fn verify(&self, data: &[u8], signature: &[u8], now: u64, skew: u64) -> Result<()> {
        let bad = |m: &str| Error::ManifestSignatureInvalid(m.to_string());
        let sigs: Vec<DetachedSignature> =
            DetachedSignature::from_reader_many(Cursor::new(signature))
                .map_err(|e| {
                    Error::ManifestSignatureInvalid(format!("unparseable signature: {e}"))
                })?
                .0
                .collect::<std::result::Result<_, _>>()
                .map_err(|e| {
                    Error::ManifestSignatureInvalid(format!("unparseable signature: {e}"))
                })?;
        let [sig] = sigs.as_slice() else {
            return Err(bad("expected exactly one signature packet"));
        };
        let s = &sig.signature;
        if s.typ() != Some(SignatureType::Binary) {
            return Err(bad("signature must be of type binary document (0x00)"));
        }
        match s.hash_alg() {
            Some(HashAlgorithm::Sha256 | HashAlgorithm::Sha384 | HashAlgorithm::Sha512) => {}
            _ => return Err(bad("signature hash must be SHA-256, SHA-384 or SHA-512")),
        }
        let created = s
            .created()
            .ok_or_else(|| bad("signature has no creation time"))?;
        if u64::from(created.as_secs()) > now.saturating_add(skew) {
            return Err(bad("signature created in the future"));
        }
        if sig.verify(&self.key.primary_key, data).is_ok() {
            return Ok(());
        }
        for sub in &self.key.public_subkeys {
            let signing_capable = sub.signatures.iter().any(|b| b.key_flags().sign());
            if signing_capable && sig.verify(&sub.key, data).is_ok() {
                return Ok(());
            }
        }
        Err(bad(
            "signature does not verify against the configured signer",
        ))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestJson {
    v: u64,
    version: u64,
    issued_at: u64,
    valid_until: u64,
    require_hardware_attestation: bool,
    max_attestation_window_secs: u64,
    keys: Vec<KeyJson>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyJson {
    fingerprint: String,
    role: String,
    label: String,
    id: String,
    token: String,
    algorithm: String,
    public_key: String,
    #[serde(default)]
    hardware_attestation: Option<HardwareAttestationJson>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HardwareAttestationJson {
    format: String,
    chain: Vec<String>,
}

/// One trusted key. Everything security-relevant about a key comes from here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestKey {
    pub fingerprint: Fingerprint,
    pub role: Role,
    pub label: String,
    /// `CKA_ID` bytes.
    pub id: Vec<u8>,
    pub token: String,
    pub algorithm: Algorithm,
    pub public_key: PublicKey,
    /// The key's YubiKey attestation chain, if the manifest carries one.
    pub hardware_attestation: Option<HardwareAttestation>,
    /// What the chain proved, filled in by [`verify_manifest`]. `None` in a manifest that was
    /// not verified, or for a key without a chain.
    pub attested: Option<PivAttestation>,
}

/// A verified manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub version: u64,
    pub issued_at: u64,
    pub valid_until: u64,
    /// Every `attest` key must carry a valid hardware attestation (wire-format §9.4).
    pub require_hardware_attestation: bool,
    /// The longest attestation window clients accept (wire-format §5.1 step 5).
    pub max_attestation_window_secs: u64,
    pub keys: Vec<ManifestKey>,
    bytes: Vec<u8>,
}

impl Manifest {
    /// The exact bytes the signature covered, for the on-disk cache.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn key(&self, fp: &Fingerprint) -> Option<&ManifestKey> {
        self.keys.iter().find(|k| &k.fingerprint == fp)
    }

    /// Token names, sorted: slot order is stable across restarts.
    pub fn tokens(&self) -> Vec<String> {
        let mut t: Vec<String> = self
            .keys
            .iter()
            .filter(|k| k.role != Role::Attest)
            .map(|k| k.token.clone())
            .collect();
        t.sort();
        t.dedup();
        t
    }

    /// Reject a manifest past `valid_until + skew`. Run on every use of a cached copy.
    pub fn check_fresh(&self, now: u64, skew: u64) -> Result<()> {
        if now > self.valid_until.saturating_add(skew) {
            return Err(Error::ManifestExpired {
                valid_until: self.valid_until,
                now,
            });
        }
        Ok(())
    }

    /// Parse and validate JSON without any signature check. Only for tests and vector
    /// generation; never reachable from production code.
    #[cfg(any(test, feature = "test-util"))]
    pub fn from_json_unverified(bytes: &[u8]) -> Result<Self> {
        parse(bytes)
    }

    /// Apply the hardware attestation policy to an unverified manifest, filling `attested`.
    /// Tests only.
    #[cfg(any(test, feature = "test-util"))]
    pub fn check_hardware_unverified(mut self, policy: &HardwarePolicy, now: u64) -> Result<Self> {
        check_hardware(&mut self, policy, now)?;
        Ok(self)
    }
}

fn parse_hardware_attestation(
    h: HardwareAttestationJson,
    fp: &Fingerprint,
) -> Result<HardwareAttestation> {
    if h.format != FORMAT_YUBIKEY_PIV {
        return Err(malformed(format!(
            "unsupported hardware_attestation format {:?} for {fp}",
            h.format
        )));
    }
    if h.chain.len() < MIN_CHAIN || h.chain.len() > MAX_CHAIN {
        return Err(malformed(format!(
            "hardware_attestation chain for {fp} must hold {MIN_CHAIN}-{MAX_CHAIN} certificates"
        )));
    }
    let chain = h
        .chain
        .iter()
        .map(|c| {
            let der = base64::engine::general_purpose::STANDARD
                .decode(c)
                .map_err(|_| malformed(format!("hardware_attestation for {fp} is not base64")))?;
            if der.is_empty() || der.len() > MAX_CERT_LEN {
                return Err(malformed(format!(
                    "hardware_attestation certificate for {fp} must be 1-{MAX_CERT_LEN} bytes"
                )));
            }
            Ok(der)
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(HardwareAttestation { chain })
}

/// Apply the hardware attestation policy (wire-format §9.4) and record what each chain proved.
fn check_hardware(m: &mut Manifest, policy: &HardwarePolicy, now: u64) -> Result<()> {
    let require = m.require_hardware_attestation;
    for k in &mut m.keys {
        let fp = k.fingerprint.clone();
        let Some(h) = &k.hardware_attestation else {
            if k.role == Role::Attest && require {
                return Err(Error::HardwareAttestationInvalid(format!(
                    "attest key {} ({fp}) has no hardware attestation",
                    k.label
                )));
            }
            continue;
        };
        let a = verify_piv_attestation(&h.chain, &k.public_key, &policy.roots, now).map_err(
            |e| match e {
                Error::HardwareAttestationInvalid(m) => {
                    Error::HardwareAttestationInvalid(format!("key {} ({fp}): {m}", k.label))
                }
                other => other,
            },
        )?;
        if k.role == Role::Attest {
            if a.touch_policy != TouchPolicy::Always {
                return Err(Error::HardwareAttestationInvalid(format!(
                    "attest key {} ({fp}) has touch policy {}, not always",
                    k.label,
                    a.touch_policy.as_str()
                )));
            }
            if a.pin_policy == PinPolicy::Never {
                return Err(Error::HardwareAttestationInvalid(format!(
                    "attest key {} ({fp}) has PIN policy never",
                    k.label
                )));
            }
        }
        k.attested = Some(a);
    }
    Ok(())
}

fn malformed(m: impl Into<String>) -> Error {
    Error::ManifestMalformed(m.into())
}

fn parse(bytes: &[u8]) -> Result<Manifest> {
    let j: ManifestJson =
        serde_json::from_slice(bytes).map_err(|e| malformed(format!("invalid JSON: {e}")))?;
    if j.v != 1 {
        return Err(malformed(format!("unsupported manifest v={}", j.v)));
    }
    if j.version < 1 {
        return Err(malformed("version must be at least 1"));
    }
    if j.issued_at >= j.valid_until {
        return Err(malformed("valid_until must be after issued_at"));
    }
    if !(MIN_ATTESTATION_WINDOW..=MAX_ATTESTATION_WINDOW).contains(&j.max_attestation_window_secs) {
        return Err(malformed(format!(
            "max_attestation_window_secs must be {MIN_ATTESTATION_WINDOW}-{MAX_ATTESTATION_WINDOW}"
        )));
    }
    if j.keys.len() > MAX_KEYS {
        return Err(malformed("too many keys"));
    }
    let mut keys = Vec::with_capacity(j.keys.len());
    let mut fps = HashSet::new();
    let mut labels = HashSet::new();
    let mut ids = HashSet::new();
    for k in j.keys {
        let fingerprint =
            Fingerprint::parse(&k.fingerprint).map_err(|e| malformed(e.to_string()))?;
        let role = Role::parse(&k.role).map_err(|e| malformed(e.to_string()))?;
        let algorithm = Algorithm::parse(&k.algorithm).map_err(|e| malformed(e.to_string()))?;
        if k.label.is_empty() || k.label.len() > 128 {
            return Err(malformed("label must be 1-128 bytes"));
        }
        if k.token.is_empty() || k.token.len() > 32 {
            return Err(malformed("token must be 1-32 bytes"));
        }
        if k.id.len() < 2
            || k.id.len() > 128
            || !k.id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(malformed("id must be 2-128 lowercase hex characters"));
        }
        let id = hex::decode(&k.id)
            .map_err(|_| malformed("id must be an even number of hex characters"))?;
        let spki = base64::engine::general_purpose::STANDARD
            .decode(&k.public_key)
            .map_err(|_| malformed("public_key is not base64"))?;
        let public_key =
            PublicKey::from_spki(&spki).map_err(|e| malformed(format!("public_key: {e}")))?;
        let hardware_attestation = k
            .hardware_attestation
            .map(|h| parse_hardware_attestation(h, &fingerprint))
            .transpose()?;
        if public_key.fingerprint() != &fingerprint {
            return Err(malformed(format!(
                "fingerprint does not match public_key for {fingerprint}"
            )));
        }
        if public_key.algorithm() != algorithm {
            return Err(malformed(format!(
                "algorithm does not match public_key for {fingerprint}"
            )));
        }
        if !role.allows(algorithm) {
            return Err(malformed(format!(
                "role {} not allowed for {}",
                role.as_str(),
                algorithm.as_str()
            )));
        }
        if !fps.insert(fingerprint.clone()) {
            return Err(malformed(format!("duplicate fingerprint {fingerprint}")));
        }
        if !labels.insert((k.token.clone(), k.label.clone())) {
            return Err(malformed(format!(
                "duplicate label {} in token {}",
                k.label, k.token
            )));
        }
        if !ids.insert((k.token.clone(), id.clone())) {
            return Err(malformed(format!(
                "duplicate id {} in token {}",
                k.id, k.token
            )));
        }
        keys.push(ManifestKey {
            fingerprint,
            role,
            label: k.label,
            id,
            token: k.token,
            algorithm,
            public_key,
            hardware_attestation,
            attested: None,
        });
    }
    Ok(Manifest {
        version: j.version,
        issued_at: j.issued_at,
        valid_until: j.valid_until,
        require_hardware_attestation: j.require_hardware_attestation,
        max_attestation_window_secs: j.max_attestation_window_secs,
        keys,
        bytes: bytes.to_vec(),
    })
}

/// Verify a fetched manifest (wire-format §9.3): signature first, then JSON, then hardware
/// attestation, then expiry, then rollback against the cached copy. On error the caller keeps
/// its valid cached copy.
pub fn verify_manifest(
    bytes: &[u8],
    signature: &[u8],
    signer: &ManifestSigner,
    policy: &HardwarePolicy,
    cached: Option<&Manifest>,
    now: u64,
    skew: u64,
) -> Result<Manifest> {
    if bytes.len() > MAX_MANIFEST_LEN {
        return Err(malformed("manifest too large"));
    }
    signer.verify(bytes, signature, now, skew)?;
    let mut m = parse(bytes)?;
    check_hardware(&mut m, policy, now)?;
    m.check_fresh(now, skew)?;
    if let Some(c) = cached {
        if m.version < c.version {
            return Err(Error::ManifestRolledBack {
                version: m.version,
                cached: c.version,
            });
        }
        if m.version == c.version && m.bytes != c.bytes {
            return Err(Error::ManifestVersionConflict { version: m.version });
        }
    }
    Ok(m)
}

/// An editable manifest, for `relayctl manifest add|remove` and fixture generation. Produces
/// the JSON that gets signed; it carries no trust of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestDraft {
    pub version: u64,
    pub issued_at: u64,
    pub valid_until: u64,
    pub require_hardware_attestation: bool,
    pub max_attestation_window_secs: u64,
    pub keys: Vec<DraftKey>,
}

impl Default for ManifestDraft {
    /// Hardware attestation required, a 7-day maximum window, no keys.
    fn default() -> Self {
        ManifestDraft {
            version: 0,
            issued_at: 0,
            valid_until: 0,
            require_hardware_attestation: true,
            max_attestation_window_secs: DEFAULT_MAX_ATTESTATION_WINDOW,
            keys: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraftKey {
    pub role: Role,
    pub label: String,
    pub id: Vec<u8>,
    pub token: String,
    pub public_key: PublicKey,
    pub hardware_attestation: Option<HardwareAttestation>,
}

impl ManifestDraft {
    /// Load a draft from existing manifest JSON (validated as strictly as a signed one).
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let m = parse(bytes)?;
        Ok(ManifestDraft {
            version: m.version,
            issued_at: m.issued_at,
            valid_until: m.valid_until,
            require_hardware_attestation: m.require_hardware_attestation,
            max_attestation_window_secs: m.max_attestation_window_secs,
            keys: m
                .keys
                .into_iter()
                .map(|k| DraftKey {
                    role: k.role,
                    label: k.label,
                    id: k.id,
                    token: k.token,
                    public_key: k.public_key,
                    hardware_attestation: k.hardware_attestation,
                })
                .collect(),
        })
    }

    /// Serialise to pretty-printed JSON, then re-parse it to apply every validation rule.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        let keys: Vec<serde_json::Value> = self
            .keys
            .iter()
            .map(|k| {
                let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
                let mut v = serde_json::json!({
                    "fingerprint": k.public_key.fingerprint().as_str(),
                    "role": k.role.as_str(),
                    "label": k.label,
                    "id": hex::encode(&k.id),
                    "token": k.token,
                    "algorithm": k.public_key.algorithm().as_str(),
                    "public_key": b64(k.public_key.spki()),
                });
                if let Some(h) = &k.hardware_attestation {
                    v["hardware_attestation"] = serde_json::json!({
                        "format": FORMAT_YUBIKEY_PIV,
                        "chain": h.chain.iter().map(|c| b64(c)).collect::<Vec<_>>(),
                    });
                }
                v
            })
            .collect();
        let doc = serde_json::json!({
            "v": 1,
            "version": self.version,
            "issued_at": self.issued_at,
            "valid_until": self.valid_until,
            "require_hardware_attestation": self.require_hardware_attestation,
            "max_attestation_window_secs": self.max_attestation_window_secs,
            "keys": keys,
        });
        let mut out = serde_json::to_vec_pretty(&doc).map_err(|e| malformed(e.to_string()))?;
        out.push(b'\n');
        parse(&out)?;
        Ok(out)
    }
}

/// A software OpenPGP signing key: the fixture generator's throwaway signer, and `relayctl`'s
/// signer when no OpenPGP card is used. Signatures are detached, binary-document type, SHA-256.
pub struct PgpSecretKey(SignedSecretKey);

impl PgpSecretKey {
    /// Generate an Ed25519 (v4, gpg-compatible) key that can certify and sign.
    pub fn generate(user_id: &str) -> Result<Self> {
        use pgp::composed::{EncryptionCaps, KeyType, SecretKeyParamsBuilder};
        let params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519Legacy)
            .can_certify(true)
            .can_sign(true)
            .can_encrypt(EncryptionCaps::None)
            .primary_user_id(user_id.into())
            .build()
            .map_err(|e| Error::Crypto(format!("OpenPGP key parameters: {e}")))?;
        let key = params
            .generate(rand_core_06::OsRng)
            .map_err(|e| Error::Crypto(format!("OpenPGP key generation: {e}")))?;
        Ok(PgpSecretKey(key))
    }

    /// Load an armored or binary transferable secret key (unprotected).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (key, _) = SignedSecretKey::from_reader_single(Cursor::new(bytes))
            .map_err(|e| Error::Crypto(format!("OpenPGP secret key: {e}")))?;
        Ok(PgpSecretKey(key))
    }

    pub fn to_armored(&self) -> Result<zeroize::Zeroizing<String>> {
        self.0
            .to_armored_string(Default::default())
            .map(zeroize::Zeroizing::new)
            .map_err(|e| Error::Crypto(e.to_string()))
    }

    /// The public key, armored: what clients configure as the manifest signer.
    pub fn public_armored(&self) -> Result<String> {
        SignedPublicKey::from(self.0.clone())
            .to_armored_string(Default::default())
            .map_err(|e| Error::Crypto(e.to_string()))
    }

    /// An armored detached signature over the exact bytes of `data`.
    pub fn sign_detached(&self, data: &[u8]) -> Result<String> {
        let sig = DetachedSignature::sign_binary_data(
            rand_core_06::OsRng,
            &self.0.primary_key,
            &pgp::types::Password::empty(),
            HashAlgorithm::Sha256,
            data,
        )
        .map_err(|e| Error::Crypto(format!("OpenPGP signing: {e}")))?;
        sig.to_armored_string(Default::default())
            .map_err(|e| Error::Crypto(e.to_string()))
    }
}

#[cfg(test)]
mod pgp_tests {
    use super::*;

    #[test]
    fn software_signer_round_trip() {
        let k = PgpSecretKey::generate("fixture <fixture@test.invalid>").unwrap();
        let k = PgpSecretKey::from_bytes(k.to_armored().unwrap().as_bytes()).unwrap();
        let signer = ManifestSigner::from_bytes(k.public_armored().unwrap().as_bytes()).unwrap();
        let data = b"{}";
        let sig = k.sign_detached(data).unwrap();
        let now = std::time::UNIX_EPOCH.elapsed().unwrap().as_secs();
        signer.verify(data, sig.as_bytes(), now, 60).unwrap();
        assert!(signer.verify(b"{ }", sig.as_bytes(), now, 60).is_err());
    }
}

#[cfg(test)]
mod origin_tests {
    use super::served_by_relay;

    #[test]
    fn served_by_relay_needs_same_origin_and_a_path() {
        let r = "https://relay:8443";
        assert!(served_by_relay("https://relay:8443/v1/manifest", r));
        assert!(served_by_relay(
            "https://relay:8443/v1/manifest",
            "https://relay:8443/"
        ));
        assert!(!served_by_relay("https://relay:84430/v1/manifest", r));
        assert!(!served_by_relay("https://relay:8443.evil/v1/manifest", r));
        assert!(!served_by_relay("https://example.org/manifest.json", r));
        assert!(!served_by_relay("file:///fixtures/manifest.json", r));
    }
}
