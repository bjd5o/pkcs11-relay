//! AES-GCM for derived, non-extractable secret keys: the provider runs `C_Encrypt` /
//! `C_Decrypt` with `CKM_AES_GCM` on them so their value never leaves its memory. RustCrypto
//! `aes-gcm`; 96-bit IVs and 128-bit tags only.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, AesGcm};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

type Aes192Gcm = AesGcm<aes_gcm::aes::Aes192, aes_gcm::aead::consts::U12>;

pub const IV_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

/// Valid AES key lengths (`CKA_VALUE_LEN` for `CKK_AES`).
pub fn is_aes_key_len(n: usize) -> bool {
    matches!(n, 16 | 24 | 32)
}

fn run<C: KeyInit + Aead>(
    key: &[u8],
    iv: &[u8],
    f: impl FnOnce(
        &C,
        &aes_gcm::Nonce<aes_gcm::aead::consts::U12>,
    ) -> std::result::Result<Vec<u8>, aes_gcm::Error>,
) -> Result<Vec<u8>> {
    let cipher = C::new_from_slice(key).map_err(|_| Error::Crypto("bad AES key length".into()))?;
    let nonce = aes_gcm::Nonce::<aes_gcm::aead::consts::U12>::try_from(iv)
        .map_err(|_| Error::MechanismParamInvalid)?;
    f(&cipher, &nonce).map_err(|_| Error::Crypto("AES-GCM failed".into()))
}

/// `ciphertext || tag`, as PKCS#11 `CKM_AES_GCM` returns it.
pub fn aes_gcm_seal(key: &[u8], iv: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if iv.len() != IV_LEN {
        return Err(Error::MechanismParamInvalid);
    }
    let p = || Payload {
        msg: plaintext,
        aad,
    };
    match key.len() {
        16 => run::<Aes128Gcm>(key, iv, |c, n| c.encrypt(n, p())),
        24 => run::<Aes192Gcm>(key, iv, |c, n| c.encrypt(n, p())),
        32 => run::<Aes256Gcm>(key, iv, |c, n| c.encrypt(n, p())),
        _ => Err(Error::Crypto("bad AES key length".into())),
    }
}

/// Open `ciphertext || tag`. Any authentication failure is `Error::Crypto`.
pub fn aes_gcm_open(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if iv.len() != IV_LEN {
        return Err(Error::MechanismParamInvalid);
    }
    if sealed.len() < TAG_LEN {
        return Err(Error::DataLenRange);
    }
    let p = || Payload { msg: sealed, aad };
    let pt = match key.len() {
        16 => run::<Aes128Gcm>(key, iv, |c, n| c.decrypt(n, p())),
        24 => run::<Aes192Gcm>(key, iv, |c, n| c.decrypt(n, p())),
        32 => run::<Aes256Gcm>(key, iv, |c, n| c.decrypt(n, p())),
        _ => Err(Error::Crypto("bad AES key length".into())),
    }?;
    Ok(Zeroizing::new(pt))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_tamper() {
        for n in [16, 24, 32] {
            let key = vec![7u8; n];
            let ct = aes_gcm_seal(&key, &[1; 12], b"aad", b"hello").unwrap();
            assert_eq!(ct.len(), 5 + TAG_LEN);
            assert_eq!(
                &*aes_gcm_open(&key, &[1; 12], b"aad", &ct).unwrap(),
                b"hello"
            );
            assert!(aes_gcm_open(&key, &[1; 12], b"AAD", &ct).is_err());
            let mut bad = ct.clone();
            bad[0] ^= 1;
            assert!(aes_gcm_open(&key, &[1; 12], b"aad", &bad).is_err());
        }
        assert_eq!(
            aes_gcm_seal(&[0; 32], &[1; 16], b"", b"x"),
            Err(Error::MechanismParamInvalid)
        );
    }

    /// NIST GCM test case 14 (AES-256, zero key and IV, one zero block).
    #[test]
    fn known_answer() {
        let ct = aes_gcm_seal(&[0; 32], &[0; 12], b"", &[0; 16]).unwrap();
        assert_eq!(
            hex::encode(ct),
            "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"
        );
    }
}
