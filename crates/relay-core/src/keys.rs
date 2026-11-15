//! Public keys, fingerprints, roles and algorithms (wire-format §2).

use std::fmt;

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// `sha256:` + 64 lowercase hex characters over the DER SubjectPublicKeyInfo.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Fingerprint(String);

impl Fingerprint {
    pub fn of_spki(spki: &[u8]) -> Self {
        Fingerprint(format!("sha256:{}", hex::encode(Sha256::digest(spki))))
    }

    /// Parse and validate the text form.
    pub fn parse(s: &str) -> Result<Self> {
        let hex_part = s
            .strip_prefix("sha256:")
            .ok_or_else(|| Error::Decode("fingerprint must start with sha256:".into()))?;
        if hex_part.len() != 64
            || !hex_part
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(Error::Decode(
                "fingerprint must be 64 lowercase hex characters".into(),
            ));
        }
        Ok(Fingerprint(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The 32 hash bytes.
    pub fn digest(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        hex::decode_to_slice(&self.0[7..], &mut out).expect("validated at construction");
        out
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", self.0)
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    Rsa2048,
    Rsa4096,
    P256,
    Ed25519,
}

impl Algorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Algorithm::Rsa2048 => "rsa-2048",
            Algorithm::Rsa4096 => "rsa-4096",
            Algorithm::P256 => "p256",
            Algorithm::Ed25519 => "ed25519",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "rsa-2048" => Algorithm::Rsa2048,
            "rsa-4096" => Algorithm::Rsa4096,
            "p256" => Algorithm::P256,
            "ed25519" => Algorithm::Ed25519,
            _ => return Err(Error::Decode(format!("unknown algorithm `{s}`"))),
        })
    }

    pub fn is_rsa(self) -> bool {
        matches!(self, Algorithm::Rsa2048 | Algorithm::Rsa4096)
    }

    /// RSA modulus length in bytes (`k`), if RSA.
    pub fn rsa_modulus_len(self) -> Option<usize> {
        match self {
            Algorithm::Rsa2048 => Some(256),
            Algorithm::Rsa4096 => Some(512),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    Sign,
    Auth,
    Encrypt,
    Attest,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Sign => "sign",
            Role::Auth => "auth",
            Role::Encrypt => "encrypt",
            Role::Attest => "attest",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "sign" => Role::Sign,
            "auth" => Role::Auth,
            "encrypt" => Role::Encrypt,
            "attest" => Role::Attest,
            _ => return Err(Error::Decode(format!("unknown role `{s}`"))),
        })
    }

    /// Whether a hardware key of `alg` may hold this role (wire-format §2).
    pub fn allows(self, alg: Algorithm) -> bool {
        match self {
            Role::Sign | Role::Auth => matches!(
                alg,
                Algorithm::Rsa2048 | Algorithm::Rsa4096 | Algorithm::P256
            ),
            Role::Encrypt => alg.is_rsa(),
            Role::Attest => alg == Algorithm::P256,
        }
    }
}

#[derive(Clone)]
enum Material {
    Rsa(rsa::PublicKey),
    P256(p256::ecdsa::VerifyingKey),
    Ed25519(ed25519_dalek::VerifyingKey),
}

/// A parsed public key in its single accepted SPKI encoding.
#[derive(Clone)]
pub struct PublicKey {
    spki: Vec<u8>,
    fingerprint: Fingerprint,
    algorithm: Algorithm,
    material: Material,
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PublicKey({}, {})",
            self.algorithm.as_str(),
            self.fingerprint
        )
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.spki == other.spki
    }
}
impl Eq for PublicKey {}

const OID_RSA: &str = "1.2.840.113549.1.1.1";
const OID_EC: &str = "1.2.840.10045.2.1";
const OID_ED25519: &str = "1.3.101.112";

impl PublicKey {
    /// Parse a DER SubjectPublicKeyInfo, accepting only the canonical encoding of each
    /// supported algorithm: the input must equal what the key re-encodes to.
    pub fn from_spki(spki: &[u8]) -> Result<Self> {
        use p256::pkcs8::der::Decode;
        use p256::pkcs8::spki::SubjectPublicKeyInfoRef;

        let info = SubjectPublicKeyInfoRef::from_der(spki)
            .map_err(|e| Error::InvalidKey(format!("not a SubjectPublicKeyInfo: {e}")))?;
        let oid = info.algorithm.oid.to_string();
        let (algorithm, material, reencoded) = match oid.as_str() {
            OID_RSA => {
                use rsa::pkcs8::{DecodePublicKey, EncodePublicKey};
                use rsa::traits::PublicKeyParts;
                let k = rsa::PublicKey::from_public_key_der(spki)
                    .map_err(|e| Error::InvalidKey(format!("bad RSA key: {e}")))?;
                let alg = match k.n().bit_width() {
                    2048 => Algorithm::Rsa2048,
                    4096 => Algorithm::Rsa4096,
                    b => {
                        return Err(Error::InvalidKey(format!(
                            "RSA modulus of {b} bits not supported"
                        )))
                    }
                };
                let e = k.e().to_be_bytes();
                let first = e.iter().position(|b| *b != 0).unwrap_or(e.len());
                if e[first..] != [0x01, 0x00, 0x01] {
                    return Err(Error::InvalidKey(
                        "RSA public exponent must be 65537".into(),
                    ));
                }
                let der = k
                    .to_public_key_der()
                    .map_err(|e| Error::InvalidKey(e.to_string()))?
                    .into_vec();
                (alg, Material::Rsa(k), der)
            }
            OID_EC => {
                use p256::pkcs8::{DecodePublicKey, EncodePublicKey};
                let k = p256::ecdsa::VerifyingKey::from_public_key_der(spki)
                    .map_err(|e| Error::InvalidKey(format!("bad P-256 key: {e}")))?;
                let der = k
                    .to_public_key_der()
                    .map_err(|e| Error::InvalidKey(e.to_string()))?
                    .into_vec();
                (Algorithm::P256, Material::P256(k), der)
            }
            OID_ED25519 => {
                use ed25519_dalek::pkcs8::{DecodePublicKey, EncodePublicKey};
                let k = ed25519_dalek::VerifyingKey::from_public_key_der(spki)
                    .map_err(|e| Error::InvalidKey(format!("bad Ed25519 key: {e}")))?;
                let der = k
                    .to_public_key_der()
                    .map_err(|e| Error::InvalidKey(e.to_string()))?
                    .into_vec();
                (Algorithm::Ed25519, Material::Ed25519(k), der)
            }
            other => {
                return Err(Error::InvalidKey(format!(
                    "unsupported key algorithm {other}"
                )))
            }
        };
        if reencoded != spki {
            return Err(Error::InvalidKey(
                "SubjectPublicKeyInfo is not in its canonical encoding".into(),
            ));
        }
        Ok(PublicKey {
            fingerprint: Fingerprint::of_spki(spki),
            spki: spki.to_vec(),
            algorithm,
            material,
        })
    }

    pub fn spki(&self) -> &[u8] {
        &self.spki
    }

    pub fn fingerprint(&self) -> &Fingerprint {
        &self.fingerprint
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Verify a protocol signature (wire-format §1.4): Ed25519 strict, or ECDSA P-256 with
    /// SHA-256 over `msg` and a raw `r || s` signature. RSA keys never sign protocol messages.
    pub fn verify_message(&self, msg: &[u8], sig: &[u8]) -> Result<()> {
        let bad = || Error::Crypto("signature does not verify".into());
        match &self.material {
            Material::P256(k) => {
                use p256::ecdsa::signature::Verifier;
                let sig = p256::ecdsa::Signature::from_slice(sig).map_err(|_| bad())?;
                k.verify(msg, &sig).map_err(|_| bad())
            }
            Material::Ed25519(k) => {
                let sig: [u8; 64] = sig.try_into().map_err(|_| bad())?;
                k.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(&sig))
                    .map_err(|_| bad())
            }
            Material::Rsa(_) => Err(Error::Crypto(
                "RSA keys do not sign protocol messages".into(),
            )),
        }
    }

    pub(crate) fn rsa(&self) -> Option<&rsa::PublicKey> {
        match &self.material {
            Material::Rsa(k) => Some(k),
            _ => None,
        }
    }

    pub(crate) fn p256(&self) -> Option<&p256::ecdsa::VerifyingKey> {
        match &self.material {
            Material::P256(k) => Some(k),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The device key from wire-format §2.
    const DEVICE_SPKI: &str = "3059301306072a8648ce3d020106082a8648ce3d030107034200048b9432b61c9144081b2eff864829ab0440cbe555b62ada198b8131e4e8fcf1f4226fbd788f8a53a858048fc0751d0e773303972e8a645718d4a3055383456528";

    #[test]
    fn wire_format_example_fingerprint() {
        let k = PublicKey::from_spki(&hex::decode(DEVICE_SPKI).unwrap()).unwrap();
        assert_eq!(k.algorithm(), Algorithm::P256);
        assert_eq!(
            k.fingerprint().as_str(),
            "sha256:d2d3e0fc4b057ee2319854654ec5747eb63a3395343c3d9010afaddb0097f786"
        );
    }

    #[test]
    fn rejects_compressed_point() {
        use p256::pkcs8::der::Encode;
        let k = PublicKey::from_spki(&hex::decode(DEVICE_SPKI).unwrap()).unwrap();
        let point = k.p256().unwrap().to_sec1_point(true);
        let alg = p256::pkcs8::spki::AlgorithmIdentifierOwned {
            oid: "1.2.840.10045.2.1".parse().unwrap(),
            parameters: Some(
                p256::pkcs8::der::Any::encode_from(
                    &p256::pkcs8::der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7"),
                )
                .unwrap(),
            ),
        };
        let spki = p256::pkcs8::spki::SubjectPublicKeyInfoOwned {
            algorithm: alg,
            subject_public_key: p256::pkcs8::der::asn1::BitString::from_bytes(point.as_bytes())
                .unwrap(),
        }
        .to_der()
        .unwrap();
        assert!(PublicKey::from_spki(&spki).is_err());
    }

    #[test]
    fn fingerprint_parse() {
        assert!(Fingerprint::parse(
            "sha256:D2D3e0fc4b057ee2319854654ec5747eb63a3395343c3d9010afaddb0097f786"
        )
        .is_err());
        assert!(Fingerprint::parse("sha1:d2d3").is_err());
        assert!(Fingerprint::parse(
            "sha256:d2d3e0fc4b057ee2319854654ec5747eb63a3395343c3d9010afaddb0097f786"
        )
        .is_ok());
    }

    #[test]
    fn roles_and_algorithms() {
        assert!(!Role::Encrypt.allows(Algorithm::P256));
        assert!(!Role::Attest.allows(Algorithm::Rsa2048));
        assert!(!Role::Sign.allows(Algorithm::Ed25519));
        assert!(Role::Auth.allows(Algorithm::Rsa4096));
    }
}
