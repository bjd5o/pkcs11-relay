//! Operations, mechanisms and the role checks both the provider and the approver run
//! (wire-format §3).

use crate::cbor::{Fields, MapBuilder};
use crate::error::{Error, Result};
use crate::keys::{Algorithm, Role};

/// Largest message sent for a hash-and-sign mechanism (wire-format §3).
pub const MAX_SIGN_MESSAGE_LEN: usize = 32_768;
/// Largest OAEP label accepted.
pub const MAX_OAEP_LABEL_LEN: usize = 256;
/// Largest X9.63 shared-info for `CKD_SHA256_KDF`.
pub const MAX_ECDH_SHARED_DATA_LEN: usize = 256;
/// Largest derived key requested from ECDH (bytes).
pub const MAX_DERIVE_LEN: u32 = 64;

/// PKCS#11 constants the core needs to interpret mechanisms. Values from PKCS#11 v2.40/3.0.
pub mod ckm {
    pub const RSA_PKCS: u64 = 0x0001;
    pub const RSA_PKCS_OAEP: u64 = 0x0009;
    pub const SHA256_RSA_PKCS: u64 = 0x0040;
    pub const SHA256: u64 = 0x0250;
    pub const ECDSA: u64 = 0x1041;
    pub const ECDSA_SHA256: u64 = 0x1044;
    pub const ECDSA_SHA384: u64 = 0x1045;
    pub const ECDH1_DERIVE: u64 = 0x1050;
    /// `CKM_EDDSA` (PKCS#11 3.0): pure Ed25519 here.
    pub const EDDSA: u64 = 0x1057;
    pub const AES_GCM: u64 = 0x1087;
    /// `CKG_MGF1_SHA256`.
    pub const CKG_MGF1_SHA256: u64 = 0x0002;
    /// `CKZ_DATA_SPECIFIED`.
    pub const CKZ_DATA_SPECIFIED: u64 = 0x0001;
    /// `CKD_NULL`.
    pub const CKD_NULL: u64 = 0x0001;
    /// `CKD_SHA256_KDF` (ANSI X9.63 with SHA-256).
    pub const CKD_SHA256_KDF: u64 = 0x0006;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Sign,
    Decrypt,
    /// ECDH key agreement with an `encrypt` key.
    Derive,
}

impl Op {
    pub fn as_str(self) -> &'static str {
        match self {
            Op::Sign => "sign",
            Op::Decrypt => "decrypt",
            Op::Derive => "derive",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "sign" => Ok(Op::Sign),
            "decrypt" => Ok(Op::Decrypt),
            "derive" => Ok(Op::Derive),
            _ => Err(Error::Decode(format!("unknown op `{s}`"))),
        }
    }
}

/// The key-derivation function applied to an ECDH shared secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kdf {
    /// The raw shared secret (x-coordinate), truncated to the requested length.
    Null,
    /// ANSI X9.63 KDF with SHA-256.
    Sha256,
}

impl Kdf {
    pub fn as_str(self) -> &'static str {
        match self {
            Kdf::Null => "null",
            Kdf::Sha256 => "sha256",
        }
    }
}

/// The supported mechanisms. OAEP always uses SHA-256 and MGF1-SHA256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mechanism {
    RsaPkcsOaep {
        label: Vec<u8>,
    },
    Sha256RsaPkcs,
    EcdsaSha256,
    EcdsaSha384,
    RsaPkcs,
    Ecdsa,
    /// Pure Ed25519 over the whole message (no prehash, no context).
    Eddsa,
    /// ECDH with the hardware key; `input` is the peer public key.
    Ecdh1Derive {
        kdf: Kdf,
        shared_data: Vec<u8>,
        out_len: u32,
    },
}

impl Mechanism {
    pub fn name(&self) -> &'static str {
        match self {
            Mechanism::RsaPkcsOaep { .. } => "CKM_RSA_PKCS_OAEP",
            Mechanism::Sha256RsaPkcs => "CKM_SHA256_RSA_PKCS",
            Mechanism::EcdsaSha256 => "CKM_ECDSA_SHA256",
            Mechanism::EcdsaSha384 => "CKM_ECDSA_SHA384",
            Mechanism::RsaPkcs => "CKM_RSA_PKCS",
            Mechanism::Ecdsa => "CKM_ECDSA",
            Mechanism::Eddsa => "CKM_EDDSA",
            Mechanism::Ecdh1Derive { .. } => "CKM_ECDH1_DERIVE",
        }
    }

    /// Map a PKCS#11 mechanism type (and, for OAEP, its `CK_RSA_PKCS_OAEP_PARAMS` fields) to a
    /// mechanism. Unknown types give `CKR_MECHANISM_INVALID`; unsupported OAEP parameters give
    /// `CKR_MECHANISM_PARAM_INVALID`. ECDH uses [`Mechanism::ecdh_from_pkcs11`].
    pub fn from_pkcs11(mechanism: u64, oaep: Option<OaepParams>) -> Result<Self> {
        Ok(match mechanism {
            ckm::RSA_PKCS_OAEP => {
                let p = oaep.ok_or(Error::MechanismParamInvalid)?;
                if p.hash_alg != ckm::SHA256 || p.mgf != ckm::CKG_MGF1_SHA256 {
                    return Err(Error::MechanismParamInvalid);
                }
                if p.label.len() > MAX_OAEP_LABEL_LEN {
                    return Err(Error::MechanismParamInvalid);
                }
                Mechanism::RsaPkcsOaep { label: p.label }
            }
            ckm::SHA256_RSA_PKCS => Mechanism::Sha256RsaPkcs,
            ckm::ECDSA_SHA256 => Mechanism::EcdsaSha256,
            ckm::ECDSA_SHA384 => Mechanism::EcdsaSha384,
            ckm::RSA_PKCS => Mechanism::RsaPkcs,
            ckm::ECDSA => Mechanism::Ecdsa,
            // CK_EDDSA_PARAMS, when present, must ask for pure Ed25519 (no prehash, no context):
            // the provider passes `None` for absent parameters and rejects others itself.
            ckm::EDDSA => Mechanism::Eddsa,
            _ => return Err(Error::MechanismInvalid),
        })
    }

    /// `CKM_ECDH1_DERIVE` from `CK_ECDH1_DERIVE_PARAMS.kdf`, its shared data, and the
    /// derived-key length the template asks for. `CKD_NULL` takes no shared data.
    pub fn ecdh_from_pkcs11(kdf: u64, shared_data: Vec<u8>, out_len: u32) -> Result<Self> {
        let kdf = match kdf {
            ckm::CKD_NULL if shared_data.is_empty() => Kdf::Null,
            ckm::CKD_SHA256_KDF if shared_data.len() <= MAX_ECDH_SHARED_DATA_LEN => Kdf::Sha256,
            _ => return Err(Error::MechanismParamInvalid),
        };
        if out_len == 0 || out_len > MAX_DERIVE_LEN {
            return Err(Error::MechanismParamInvalid);
        }
        Ok(Mechanism::Ecdh1Derive {
            kdf,
            shared_data,
            out_len,
        })
    }

    /// Mechanisms a key of this role and algorithm supports (wire-format §3).
    pub fn allowed_for(role: Role, alg: Algorithm) -> &'static [u64] {
        use Algorithm::*;
        match (role, alg) {
            (Role::Encrypt, Rsa2048 | Rsa4096) => &[ckm::RSA_PKCS_OAEP],
            (Role::Encrypt, P256 | P384 | X25519) => &[ckm::ECDH1_DERIVE],
            (Role::Sign, Rsa2048 | Rsa4096) => &[ckm::SHA256_RSA_PKCS],
            (Role::Sign, P256) => &[ckm::ECDSA_SHA256],
            (Role::Sign, P384) => &[ckm::ECDSA_SHA384],
            (Role::Auth, Rsa2048 | Rsa4096) => &[ckm::RSA_PKCS],
            (Role::Auth, P256 | P384) => &[ckm::ECDSA],
            (Role::Sign | Role::Auth, Ed25519) => &[ckm::EDDSA],
            _ => &[],
        }
    }

    pub(crate) fn ckm(&self) -> u64 {
        match self {
            Mechanism::RsaPkcsOaep { .. } => ckm::RSA_PKCS_OAEP,
            Mechanism::Sha256RsaPkcs => ckm::SHA256_RSA_PKCS,
            Mechanism::EcdsaSha256 => ckm::ECDSA_SHA256,
            Mechanism::EcdsaSha384 => ckm::ECDSA_SHA384,
            Mechanism::RsaPkcs => ckm::RSA_PKCS,
            Mechanism::Ecdsa => ckm::ECDSA,
            Mechanism::Eddsa => ckm::EDDSA,
            Mechanism::Ecdh1Derive { .. } => ckm::ECDH1_DERIVE,
        }
    }

    /// The operation this mechanism performs.
    pub fn op(&self) -> Op {
        match self {
            Mechanism::RsaPkcsOaep { .. } => Op::Decrypt,
            Mechanism::Ecdh1Derive { .. } => Op::Derive,
            _ => Op::Sign,
        }
    }

    pub(crate) fn to_cbor(&self) -> MapBuilder {
        let b = MapBuilder::new().text("name", self.name());
        match self {
            Mechanism::RsaPkcsOaep { label } => b
                .text("mgf", "mgf1-sha256")
                .text("hash", "sha256")
                .bytes("label", label),
            Mechanism::Ecdh1Derive {
                kdf,
                shared_data,
                out_len,
            } => b
                .text("kdf", kdf.as_str())
                .bytes("shared_data", shared_data)
                .uint("out_len", *out_len as u64),
            _ => b,
        }
    }

    pub(crate) fn from_cbor(mut f: Fields) -> Result<Self> {
        let name = f.text("name")?;
        let m = match name.as_str() {
            "CKM_RSA_PKCS_OAEP" => {
                let mgf = f.text("mgf")?;
                let hash = f.text("hash")?;
                let label = f.bytes("label")?;
                if mgf != "mgf1-sha256" || hash != "sha256" || label.len() > MAX_OAEP_LABEL_LEN {
                    return Err(Error::MechanismParamInvalid);
                }
                Mechanism::RsaPkcsOaep { label }
            }
            "CKM_ECDH1_DERIVE" => {
                let kdf = match f.text("kdf")?.as_str() {
                    "null" => ckm::CKD_NULL,
                    "sha256" => ckm::CKD_SHA256_KDF,
                    _ => return Err(Error::MechanismParamInvalid),
                };
                let shared_data = f.bytes("shared_data")?;
                let out_len =
                    u32::try_from(f.uint("out_len")?).map_err(|_| Error::MechanismParamInvalid)?;
                Mechanism::ecdh_from_pkcs11(kdf, shared_data, out_len)?
            }
            "CKM_SHA256_RSA_PKCS" => Mechanism::Sha256RsaPkcs,
            "CKM_ECDSA_SHA256" => Mechanism::EcdsaSha256,
            "CKM_ECDSA_SHA384" => Mechanism::EcdsaSha384,
            "CKM_RSA_PKCS" => Mechanism::RsaPkcs,
            "CKM_ECDSA" => Mechanism::Ecdsa,
            "CKM_EDDSA" => Mechanism::Eddsa,
            _ => return Err(Error::MechanismInvalid),
        };
        f.finish()?;
        Ok(m)
    }

    /// Whether the result is a signature (check 5 applies).
    pub fn is_signature(&self) -> bool {
        self.op() == Op::Sign
    }
}

/// The fields of `CK_RSA_PKCS_OAEP_PARAMS` the core checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OaepParams {
    pub hash_alg: u64,
    pub mgf: u64,
    pub label: Vec<u8>,
}

/// Check that an ECDH peer public key is a valid point on the key's curve: an uncompressed
/// P-256 or P-384 point, or a 32-byte X25519 u-coordinate. (Low-order X25519 points are
/// refused after the agreement, when the shared secret turns out all-zero.) The peer key is a
/// mechanism parameter in PKCS#11 (`pPublicData`), hence `CKR_MECHANISM_PARAM_INVALID`.
pub fn check_ecdh_peer(alg: Algorithm, peer: &[u8]) -> Result<()> {
    if Some(peer.len()) != alg.ecdh_peer_len() {
        return Err(Error::MechanismParamInvalid);
    }
    let ok = match alg {
        Algorithm::P256 => peer[0] == 0x04 && p256::PublicKey::from_sec1_bytes(peer).is_ok(),
        Algorithm::P384 => peer[0] == 0x04 && p384::PublicKey::from_sec1_bytes(peer).is_ok(),
        Algorithm::X25519 => true,
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(Error::MechanismParamInvalid)
    }
}

/// The role and mechanism half of [`check_operation`], for `C_SignInit` / `C_DecryptInit` /
/// `C_DeriveKey` where the input may not be known yet.
pub fn check_key_mechanism(
    role: Role,
    alg: Algorithm,
    op: Op,
    mechanism: &Mechanism,
) -> Result<()> {
    let role_op_ok = matches!(
        (role, op),
        (Role::Sign | Role::Auth, Op::Sign)
            | (Role::Encrypt, Op::Decrypt)
            | (Role::Encrypt, Op::Derive)
    );
    if !role_op_ok {
        return Err(Error::KeyFunctionNotPermitted);
    }
    if mechanism.op() != op || !Mechanism::allowed_for(role, alg).contains(&mechanism.ckm()) {
        return Err(Error::MechanismInvalid);
    }
    Ok(())
}

/// The check for `C_EncryptInit` with a hardware key: encryption runs in software with an RSA
/// `encrypt` key's public key, OAEP only (spec: role table). EC `encrypt` keys are used for
/// ECDH by the consumer itself.
pub fn check_encrypt(role: Role, alg: Algorithm, mechanism: &Mechanism) -> Result<()> {
    if role != Role::Encrypt || !alg.is_rsa() {
        return Err(Error::KeyFunctionNotPermitted);
    }
    if !matches!(mechanism, Mechanism::RsaPkcsOaep { .. }) {
        return Err(Error::MechanismInvalid);
    }
    Ok(())
}

/// Largest OAEP-SHA256 plaintext for a modulus of `k` bytes (RFC 8017 §7.1.1).
pub fn oaep_max_plaintext(k: usize) -> usize {
    k.saturating_sub(2 * 32 + 2)
}

/// The local check run before any request is sent, and again by the approver: the role
/// permits `op`, the mechanism fits the role and algorithm, and the input fits the
/// mechanism. Failure handling rows "Operation outside the key's role" and "Mechanism not
/// allowed for the key".
pub fn check_operation(
    role: Role,
    alg: Algorithm,
    op: Op,
    mechanism: &Mechanism,
    input: &[u8],
) -> Result<()> {
    check_key_mechanism(role, alg, op, mechanism)?;
    let n = input.len();
    let k = alg.rsa_modulus_len();
    let len_ok = match mechanism {
        Mechanism::RsaPkcsOaep { .. } => Some(n) == k,
        Mechanism::Sha256RsaPkcs
        | Mechanism::EcdsaSha256
        | Mechanism::EcdsaSha384
        | Mechanism::Eddsa => (1..=MAX_SIGN_MESSAGE_LEN).contains(&n),
        Mechanism::RsaPkcs => k.is_some_and(|k| (1..=k - 11).contains(&n)),
        Mechanism::Ecdsa => (1..=64).contains(&n),
        Mechanism::Ecdh1Derive { kdf, out_len, .. } => {
            check_ecdh_peer(alg, input)?;
            match kdf {
                Kdf::Null => alg.ec_field_len().is_some_and(|f| *out_len as usize <= f),
                Kdf::Sha256 => true,
            }
        }
    };
    if !len_ok {
        return Err(Error::DataLenRange);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_violation_comes_before_mechanism() {
        let oaep = Mechanism::RsaPkcsOaep { label: vec![] };
        let e = check_operation(
            Role::Sign,
            Algorithm::Rsa2048,
            Op::Decrypt,
            &oaep,
            &[0; 256],
        );
        assert_eq!(e, Err(Error::KeyFunctionNotPermitted));
        let e = check_operation(
            Role::Attest,
            Algorithm::P256,
            Op::Sign,
            &Mechanism::Ecdsa,
            &[0; 32],
        );
        assert_eq!(e, Err(Error::KeyFunctionNotPermitted));
        let ecdh = Mechanism::ecdh_from_pkcs11(ckm::CKD_NULL, vec![], 32).unwrap();
        let e = check_operation(Role::Sign, Algorithm::P256, Op::Derive, &ecdh, &[0; 65]);
        assert_eq!(e, Err(Error::KeyFunctionNotPermitted));
    }

    #[test]
    fn mechanism_must_fit_role_and_algorithm() {
        let e = check_key_mechanism(
            Role::Auth,
            Algorithm::P256,
            Op::Sign,
            &Mechanism::EcdsaSha256,
        );
        assert_eq!(e, Err(Error::MechanismInvalid));
        let e = check_key_mechanism(
            Role::Sign,
            Algorithm::P256,
            Op::Sign,
            &Mechanism::Sha256RsaPkcs,
        );
        assert_eq!(e, Err(Error::MechanismInvalid));
        let e = check_key_mechanism(
            Role::Sign,
            Algorithm::P384,
            Op::Sign,
            &Mechanism::EcdsaSha256,
        );
        assert_eq!(e, Err(Error::MechanismInvalid));
        assert!(check_key_mechanism(
            Role::Sign,
            Algorithm::P384,
            Op::Sign,
            &Mechanism::EcdsaSha384
        )
        .is_ok());
        let ecdh = Mechanism::ecdh_from_pkcs11(ckm::CKD_NULL, vec![], 32).unwrap();
        assert_eq!(
            check_key_mechanism(Role::Encrypt, Algorithm::Rsa2048, Op::Derive, &ecdh),
            Err(Error::MechanismInvalid)
        );
        assert_eq!(
            check_key_mechanism(Role::Encrypt, Algorithm::P256, Op::Decrypt, &ecdh),
            Err(Error::MechanismInvalid)
        );
        assert!(check_key_mechanism(Role::Encrypt, Algorithm::X25519, Op::Derive, &ecdh).is_ok());
    }

    #[test]
    fn eddsa_for_ed25519_sign_and_auth_only() {
        for role in [Role::Sign, Role::Auth] {
            assert!(
                check_key_mechanism(role, Algorithm::Ed25519, Op::Sign, &Mechanism::Eddsa).is_ok()
            );
            assert_eq!(
                check_key_mechanism(role, Algorithm::P256, Op::Sign, &Mechanism::Eddsa),
                Err(Error::MechanismInvalid)
            );
        }
        assert_eq!(
            check_key_mechanism(
                Role::Encrypt,
                Algorithm::Ed25519,
                Op::Sign,
                &Mechanism::Eddsa
            ),
            Err(Error::KeyFunctionNotPermitted)
        );
    }

    #[test]
    fn oaep_and_ecdh_params() {
        let ok = OaepParams {
            hash_alg: ckm::SHA256,
            mgf: ckm::CKG_MGF1_SHA256,
            label: vec![],
        };
        assert!(Mechanism::from_pkcs11(ckm::RSA_PKCS_OAEP, Some(ok.clone())).is_ok());
        let sha1 = OaepParams {
            hash_alg: 0x220,
            ..ok
        };
        assert_eq!(
            Mechanism::from_pkcs11(ckm::RSA_PKCS_OAEP, Some(sha1)),
            Err(Error::MechanismParamInvalid)
        );
        assert_eq!(
            Mechanism::from_pkcs11(0x1234, None),
            Err(Error::MechanismInvalid)
        );
        assert_eq!(
            Mechanism::ecdh_from_pkcs11(ckm::CKD_NULL, vec![1], 32),
            Err(Error::MechanismParamInvalid)
        );
        assert_eq!(
            Mechanism::ecdh_from_pkcs11(0x2, vec![], 32),
            Err(Error::MechanismParamInvalid)
        );
        assert_eq!(
            Mechanism::ecdh_from_pkcs11(ckm::CKD_SHA256_KDF, vec![1], 65),
            Err(Error::MechanismParamInvalid)
        );
        assert!(Mechanism::ecdh_from_pkcs11(ckm::CKD_SHA256_KDF, vec![1, 2], 16).is_ok());
    }

    #[test]
    fn input_lengths_and_peer_points() {
        let oaep = Mechanism::RsaPkcsOaep { label: vec![] };
        assert_eq!(
            check_operation(
                Role::Encrypt,
                Algorithm::Rsa2048,
                Op::Decrypt,
                &oaep,
                &[0; 255]
            ),
            Err(Error::DataLenRange)
        );
        assert!(check_operation(
            Role::Encrypt,
            Algorithm::Rsa2048,
            Op::Decrypt,
            &oaep,
            &[0; 256]
        )
        .is_ok());
        assert_eq!(
            check_operation(
                Role::Sign,
                Algorithm::Rsa2048,
                Op::Sign,
                &Mechanism::Sha256RsaPkcs,
                &vec![0; MAX_SIGN_MESSAGE_LEN + 1]
            ),
            Err(Error::DataLenRange)
        );
        let ecdh = Mechanism::ecdh_from_pkcs11(ckm::CKD_NULL, vec![], 32).unwrap();
        let point = crate::signing::SoftwareKey::generate_p256()
            .public_key()
            .ec_point()
            .unwrap();
        assert!(check_operation(Role::Encrypt, Algorithm::P256, Op::Derive, &ecdh, &point).is_ok());
        let mut bad = point.clone();
        bad[10] ^= 1;
        assert!(
            check_operation(Role::Encrypt, Algorithm::P256, Op::Derive, &ecdh, &bad).is_err(),
            "off-curve point"
        );
        assert_eq!(
            check_operation(Role::Encrypt, Algorithm::P256, Op::Derive, &ecdh, &[4; 33]),
            Err(Error::MechanismParamInvalid)
        );
        let long = Mechanism::ecdh_from_pkcs11(ckm::CKD_NULL, vec![], 48).unwrap();
        assert_eq!(
            check_operation(
                Role::Encrypt,
                Algorithm::X25519,
                Op::Derive,
                &long,
                &[9; 32]
            ),
            Err(Error::DataLenRange)
        );
    }
}
