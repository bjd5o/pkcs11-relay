//! The signed trust manifest (wire-format §9).
//!
//! The OpenPGP signature is verified over the file's exact bytes before any JSON parsing.

use std::collections::HashSet;
use std::io::Cursor;

use base64::Engine as _;
use pgp::composed::{Deserializable, DetachedSignature, SignedPublicKey};
use pgp::crypto::hash::HashAlgorithm;
use pgp::packet::SignatureType;
use serde::Deserialize;

use crate::error::{Error, Result};
use crate::keys::{Algorithm, Fingerprint, PublicKey, Role};

/// Largest manifest file accepted (wire-format §9.1).
pub const MAX_MANIFEST_LEN: usize = 1 << 20;
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
}

/// A verified manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub version: u64,
    pub issued_at: u64,
    pub valid_until: u64,
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
        });
    }
    Ok(Manifest {
        version: j.version,
        issued_at: j.issued_at,
        valid_until: j.valid_until,
        keys,
        bytes: bytes.to_vec(),
    })
}

/// Verify a fetched manifest (wire-format §9.3): signature first, then JSON, then expiry,
/// then rollback against the cached copy. On error the caller keeps its valid cached copy.
pub fn verify_manifest(
    bytes: &[u8],
    signature: &[u8],
    signer: &ManifestSigner,
    cached: Option<&Manifest>,
    now: u64,
    skew: u64,
) -> Result<Manifest> {
    if bytes.len() > MAX_MANIFEST_LEN {
        return Err(malformed("manifest too large"));
    }
    signer.verify(bytes, signature, now, skew)?;
    let m = parse(bytes)?;
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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ManifestDraft {
    pub version: u64,
    pub issued_at: u64,
    pub valid_until: u64,
    pub keys: Vec<DraftKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraftKey {
    pub role: Role,
    pub label: String,
    pub id: Vec<u8>,
    pub token: String,
    pub public_key: PublicKey,
}

impl ManifestDraft {
    /// Load a draft from existing manifest JSON (validated as strictly as a signed one).
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let m = parse(bytes)?;
        Ok(ManifestDraft {
            version: m.version,
            issued_at: m.issued_at,
            valid_until: m.valid_until,
            keys: m
                .keys
                .into_iter()
                .map(|k| DraftKey {
                    role: k.role,
                    label: k.label,
                    id: k.id,
                    token: k.token,
                    public_key: k.public_key,
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
                serde_json::json!({
                    "fingerprint": k.public_key.fingerprint().as_str(),
                    "role": k.role.as_str(),
                    "label": k.label,
                    "id": hex::encode(&k.id),
                    "token": k.token,
                    "algorithm": k.public_key.algorithm().as_str(),
                    "public_key": base64::engine::general_purpose::STANDARD.encode(k.public_key.spki()),
                })
            })
            .collect();
        let doc = serde_json::json!({
            "v": 1,
            "version": self.version,
            "issued_at": self.issued_at,
            "valid_until": self.valid_until,
            "keys": keys,
        });
        let mut out = serde_json::to_vec_pretty(&doc).map_err(|e| malformed(e.to_string()))?;
        out.push(b'\n');
        parse(&out)?;
        Ok(out)
    }
}
