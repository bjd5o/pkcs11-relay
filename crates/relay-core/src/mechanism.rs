//! Operations, mechanisms and the role checks both the provider and the approver run
//! (wire-format §3).

use crate::cbor::{Fields, MapBuilder};
use crate::error::{Error, Result};
use crate::keys::{Algorithm, Role};

/// Largest message sent for a hash-and-sign mechanism (wire-format §3).
pub const MAX_SIGN_MESSAGE_LEN: usize = 32_768;
/// Largest OAEP label accepted.
pub const MAX_OAEP_LABEL_LEN: usize = 256;

/// PKCS#11 constants the core needs to interpret mechanisms. Values from PKCS#11 v2.40.
pub mod ckm {
    pub const RSA_PKCS: u64 = 0x0001;
    pub const RSA_PKCS_OAEP: u64 = 0x0009;
    pub const SHA256_RSA_PKCS: u64 = 0x0040;
    pub const SHA256: u64 = 0x0250;
    pub const ECDSA: u64 = 0x1041;
    pub const ECDSA_SHA256: u64 = 0x1044;
    /// `CKG_MGF1_SHA256`.
    pub const CKG_MGF1_SHA256: u64 = 0x0002;
    /// `CKZ_DATA_SPECIFIED`.
    pub const CKZ_DATA_SPECIFIED: u64 = 0x0001;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Sign,
    Decrypt,
}

impl Op {
    pub fn as_str(self) -> &'static str {
        match self {
            Op::Sign => "sign",
            Op::Decrypt => "decrypt",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "sign" => Ok(Op::Sign),
            "decrypt" => Ok(Op::Decrypt),
            _ => Err(Error::Decode(format!("unknown op `{s}`"))),
        }
    }
}

/// The MVP mechanisms. OAEP always uses SHA-256 and MGF1-SHA256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mechanism {
    RsaPkcsOaep { label: Vec<u8> },
    Sha256RsaPkcs,
    EcdsaSha256,
    RsaPkcs,
    Ecdsa,
}

impl Mechanism {
    pub fn name(&self) -> &'static str {
        match self {
            Mechanism::RsaPkcsOaep { .. } => "CKM_RSA_PKCS_OAEP",
            Mechanism::Sha256RsaPkcs => "CKM_SHA256_RSA_PKCS",
            Mechanism::EcdsaSha256 => "CKM_ECDSA_SHA256",
            Mechanism::RsaPkcs => "CKM_RSA_PKCS",
            Mechanism::Ecdsa => "CKM_ECDSA",
        }
    }

    /// Map a PKCS#11 mechanism type (and, for OAEP, its `CK_RSA_PKCS_OAEP_PARAMS` fields) to a
    /// mechanism. Unknown types give `CKR_MECHANISM_INVALID`; unsupported OAEP parameters give
    /// `CKR_MECHANISM_PARAM_INVALID`.
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
            ckm::RSA_PKCS => Mechanism::RsaPkcs,
            ckm::ECDSA => Mechanism::Ecdsa,
            _ => return Err(Error::MechanismInvalid),
        })
    }

    /// Mechanisms a key of this role and algorithm supports (wire-format §3).
    pub fn allowed_for(role: Role, alg: Algorithm) -> &'static [u64] {
        match (role, alg.is_rsa(), alg) {
            (Role::Encrypt, true, _) => &[ckm::RSA_PKCS_OAEP],
            (Role::Sign, true, _) => &[ckm::SHA256_RSA_PKCS],
            (Role::Sign, false, Algorithm::P256) => &[ckm::ECDSA_SHA256],
            (Role::Auth, true, _) => &[ckm::RSA_PKCS],
            (Role::Auth, false, Algorithm::P256) => &[ckm::ECDSA],
            _ => &[],
        }
    }

    fn ckm(&self) -> u64 {
        match self {
            Mechanism::RsaPkcsOaep { .. } => ckm::RSA_PKCS_OAEP,
            Mechanism::Sha256RsaPkcs => ckm::SHA256_RSA_PKCS,
            Mechanism::EcdsaSha256 => ckm::ECDSA_SHA256,
            Mechanism::RsaPkcs => ckm::RSA_PKCS,
            Mechanism::Ecdsa => ckm::ECDSA,
        }
    }

    pub(crate) fn to_cbor(&self) -> MapBuilder {
        let b = MapBuilder::new().text("name", self.name());
        match self {
            Mechanism::RsaPkcsOaep { label } => b
                .text("mgf", "mgf1-sha256")
                .text("hash", "sha256")
                .bytes("label", label),
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
            "CKM_SHA256_RSA_PKCS" => Mechanism::Sha256RsaPkcs,
            "CKM_ECDSA_SHA256" => Mechanism::EcdsaSha256,
            "CKM_RSA_PKCS" => Mechanism::RsaPkcs,
            "CKM_ECDSA" => Mechanism::Ecdsa,
            _ => return Err(Error::MechanismInvalid),
        };
        f.finish()?;
        Ok(m)
    }

    /// Whether the result is a signature (check 5 applies).
    pub fn is_signature(&self) -> bool {
        !matches!(self, Mechanism::RsaPkcsOaep { .. })
    }
}

/// The fields of `CK_RSA_PKCS_OAEP_PARAMS` the core checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OaepParams {
    pub hash_alg: u64,
    pub mgf: u64,
    pub label: Vec<u8>,
}

/// The role and mechanism half of [`check_operation`], for `C_SignInit` / `C_DecryptInit`
/// where the input length is not yet known.
pub fn check_key_mechanism(
    role: Role,
    alg: Algorithm,
    op: Op,
    mechanism: &Mechanism,
) -> Result<()> {
    let role_op_ok = matches!(
        (role, op),
        (Role::Sign | Role::Auth, Op::Sign) | (Role::Encrypt, Op::Decrypt)
    );
    if !role_op_ok {
        return Err(Error::KeyFunctionNotPermitted);
    }
    if !Mechanism::allowed_for(role, alg).contains(&mechanism.ckm()) {
        return Err(Error::MechanismInvalid);
    }
    Ok(())
}

/// The local check run before any request is sent, and again by the approver: the role
/// permits `op`, the mechanism fits the role and algorithm, and the input length fits the
/// mechanism. Failure handling rows "Operation outside the key's role" and "Mechanism not
/// allowed for the key".
pub fn check_operation(
    role: Role,
    alg: Algorithm,
    op: Op,
    mechanism: &Mechanism,
    input_len: usize,
) -> Result<()> {
    check_key_mechanism(role, alg, op, mechanism)?;
    let k = alg.rsa_modulus_len();
    let len_ok = match mechanism {
        Mechanism::RsaPkcsOaep { .. } => Some(input_len) == k,
        Mechanism::Sha256RsaPkcs | Mechanism::EcdsaSha256 => {
            (1..=MAX_SIGN_MESSAGE_LEN).contains(&input_len)
        }
        Mechanism::RsaPkcs => k.is_some_and(|k| (1..=k - 11).contains(&input_len)),
        Mechanism::Ecdsa => (1..=64).contains(&input_len),
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
        // decrypt on a sign key: role violation even though the mechanism is also wrong
        let e = check_operation(
            Role::Sign,
            Algorithm::Rsa2048,
            Op::Decrypt,
            &Mechanism::RsaPkcsOaep { label: vec![] },
            256,
        );
        assert_eq!(e, Err(Error::KeyFunctionNotPermitted));
        let e = check_operation(
            Role::Attest,
            Algorithm::P256,
            Op::Sign,
            &Mechanism::Ecdsa,
            32,
        );
        assert_eq!(e, Err(Error::KeyFunctionNotPermitted));
    }

    #[test]
    fn mechanism_must_fit_role_and_algorithm() {
        let e = check_operation(
            Role::Auth,
            Algorithm::P256,
            Op::Sign,
            &Mechanism::EcdsaSha256,
            32,
        );
        assert_eq!(e, Err(Error::MechanismInvalid));
        let e = check_operation(
            Role::Sign,
            Algorithm::P256,
            Op::Sign,
            &Mechanism::Sha256RsaPkcs,
            32,
        );
        assert_eq!(e, Err(Error::MechanismInvalid));
        assert!(check_operation(
            Role::Sign,
            Algorithm::P256,
            Op::Sign,
            &Mechanism::EcdsaSha256,
            100
        )
        .is_ok());
    }

    #[test]
    fn oaep_params() {
        let ok = OaepParams {
            hash_alg: ckm::SHA256,
            mgf: ckm::CKG_MGF1_SHA256,
            label: vec![],
        };
        assert!(Mechanism::from_pkcs11(ckm::RSA_PKCS_OAEP, Some(ok.clone())).is_ok());
        let sha1 = OaepParams {
            hash_alg: 0x220,
            ..ok.clone()
        };
        assert_eq!(
            Mechanism::from_pkcs11(ckm::RSA_PKCS_OAEP, Some(sha1)),
            Err(Error::MechanismParamInvalid)
        );
        assert_eq!(
            Mechanism::from_pkcs11(0x1234, None),
            Err(Error::MechanismInvalid)
        );
    }

    #[test]
    fn input_lengths() {
        let oaep = Mechanism::RsaPkcsOaep { label: vec![] };
        assert_eq!(
            check_operation(Role::Encrypt, Algorithm::Rsa2048, Op::Decrypt, &oaep, 255),
            Err(Error::DataLenRange)
        );
        assert!(
            check_operation(Role::Encrypt, Algorithm::Rsa2048, Op::Decrypt, &oaep, 256).is_ok()
        );
        assert_eq!(
            check_operation(
                Role::Sign,
                Algorithm::Rsa2048,
                Op::Sign,
                &Mechanism::Sha256RsaPkcs,
                MAX_SIGN_MESSAGE_LEN + 1
            ),
            Err(Error::DataLenRange)
        );
        assert_eq!(
            check_operation(
                Role::Auth,
                Algorithm::Rsa2048,
                Op::Sign,
                &Mechanism::RsaPkcs,
                246
            ),
            Err(Error::DataLenRange)
        );
    }
}
