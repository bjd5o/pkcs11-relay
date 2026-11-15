//! Software signing keys: the provider's client identity key and the test approver's device
//! key. Hardware-backed signers (Secure Enclave, Keystore, TPM, PIV) live behind platform code;
//! they sign the same `to_be_signed()` bytes and hand back a 64-byte signature.

use rand_core::UnwrapErr;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::keys::PublicKey;

/// Fill `buf` from the OS CSPRNG.
pub fn random_bytes(buf: &mut [u8]) {
    getrandom::fill(buf).expect("OS random number generator failed");
}

pub(crate) fn rng() -> UnwrapErr<getrandom::SysRng> {
    UnwrapErr(getrandom::SysRng)
}

/// A software Ed25519 or P-256 signing key. Private material is zeroized on drop by the
/// underlying crates.
pub enum SoftwareKey {
    Ed25519(ed25519_dalek::SigningKey),
    P256(p256::ecdsa::SigningKey),
}

impl SoftwareKey {
    pub fn generate_ed25519() -> Self {
        SoftwareKey::Ed25519(ed25519_dalek::SigningKey::generate(&mut rng()))
    }

    pub fn generate_p256() -> Self {
        SoftwareKey::P256(
            <p256::ecdsa::SigningKey as p256::elliptic_curve::Generate>::generate_from_rng(
                &mut rng(),
            ),
        )
    }

    /// Load a PKCS#8 PEM private key (Ed25519 or P-256).
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self> {
        if let Ok(k) =
            <ed25519_dalek::SigningKey as ed25519_dalek::pkcs8::DecodePrivateKey>::from_pkcs8_pem(
                pem,
            )
        {
            return Ok(SoftwareKey::Ed25519(k));
        }
        <p256::ecdsa::SigningKey as p256::pkcs8::DecodePrivateKey>::from_pkcs8_pem(pem)
            .map(SoftwareKey::P256)
            .map_err(|_| Error::InvalidKey("not an Ed25519 or P-256 PKCS#8 private key".into()))
    }

    /// PKCS#8 PEM encoding of the private key.
    pub fn to_pkcs8_pem(&self) -> Result<Zeroizing<String>> {
        let le = p256::pkcs8::LineEnding::LF;
        let pem = match self {
            SoftwareKey::Ed25519(k) => ed25519_dalek::pkcs8::EncodePrivateKey::to_pkcs8_pem(k, le),
            SoftwareKey::P256(k) => p256::pkcs8::EncodePrivateKey::to_pkcs8_pem(k, le),
        }
        .map_err(|e| Error::InvalidKey(e.to_string()))?;
        Ok(Zeroizing::new(pem.to_string()))
    }

    pub fn public_key(&self) -> PublicKey {
        let der = match self {
            SoftwareKey::Ed25519(k) => {
                ed25519_dalek::pkcs8::EncodePublicKey::to_public_key_der(&k.verifying_key())
            }
            SoftwareKey::P256(k) => {
                p256::pkcs8::EncodePublicKey::to_public_key_der(k.verifying_key())
            }
        }
        .expect("encoding a valid public key cannot fail");
        PublicKey::from_spki(der.as_bytes()).expect("own public key is canonical")
    }

    /// Sign protocol bytes (wire-format §1.4).
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        match self {
            SoftwareKey::Ed25519(k) => {
                use ed25519_dalek::Signer;
                k.sign(msg).to_bytes()
            }
            SoftwareKey::P256(k) => {
                use p256::ecdsa::signature::Signer;
                let sig: p256::ecdsa::Signature = k.sign(msg);
                sig.to_bytes().into()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_and_pem_round_trip() {
        for key in [
            SoftwareKey::generate_ed25519(),
            SoftwareKey::generate_p256(),
        ] {
            let sig = key.sign(b"hello");
            key.public_key().verify_message(b"hello", &sig).unwrap();
            assert!(key.public_key().verify_message(b"hellO", &sig).is_err());
            let again = SoftwareKey::from_pkcs8_pem(&key.to_pkcs8_pem().unwrap()).unwrap();
            assert_eq!(again.public_key(), key.public_key());
        }
    }
}
