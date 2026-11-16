//! Format fix-ups around the card's raw operations (spec: Approver, "Run the operation and fix
//! up formats"): OAEP decoding after raw RSA decryption, PKCS#1 v1.5 signature padding before
//! raw RSA signing, and DER to raw `r || s` for ECDSA.
//!
//! # Provenance
//!
//! `mgf1_xor_digest`, `oaep_decode_inner` and `emsa_pkcs1v15_encode` are vendored from the
//! RustCrypto `rsa` crate, version 0.10.0 (`src/algorithms/mgf.rs`, `src/algorithms/oaep.rs`,
//! `src/algorithms/pkcs1v15.rs`), <https://github.com/RustCrypto/RSA>, licensed MIT OR
//! Apache-2.0, Copyright (c) 2018-2026 RustCrypto Developers. `rsa` keeps these functions
//! `pub(crate)`. Changes from upstream (see docs/decisions.md, 2026-11-15):
//!
//! - constant-time primitives come from `subtle` instead of `crypto_bigint`;
//! - the RFC 8017 §7.1.2 step 3g check that the first octet is zero is restored (upstream
//!   deliberately ignores it), folded into the same constant-time validity flag;
//! - fixed to SHA-256 for the label hash and MGF1, the only OAEP parameters the MVP accepts;
//! - every failure returns the same error, and the caller reports it as a generic card error.

use sha2::digest::{Digest, FixedOutputReset};
use sha2::Sha256;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

const H_SIZE: usize = 32;

/// DER prefix of a SHA-256 `DigestInfo` (RFC 8017 §9.2 note 1).
pub const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// Vendored from `rsa` 0.10.0 `algorithms/mgf.rs` (`mgf1_xor_digest`).
fn mgf1_xor_digest<D>(out: &mut [u8], digest: &mut D, seed: &[u8])
where
    D: Digest + FixedOutputReset,
{
    let mut counter = [0u8; 4];
    let mut i = 0;

    const MAX_LEN: u64 = u32::MAX as u64 + 1;
    assert!(out.len() as u64 <= MAX_LEN);

    while i < out.len() {
        Digest::update(digest, seed);
        Digest::update(digest, counter);

        let digest_output = digest.finalize_reset();
        let mut j = 0;
        loop {
            if j >= digest_output.len() || i >= out.len() {
                break;
            }

            out[i] ^= digest_output[j];
            j += 1;
            i += 1;
        }
        inc_counter(&mut counter);
    }
}

fn inc_counter(counter: &mut [u8; 4]) {
    for i in (0..4).rev() {
        counter[i] = counter[i].wrapping_add(1);
        if counter[i] != 0 {
            // No overflow
            return;
        }
    }
}

/// Vendored from `rsa` 0.10.0 `algorithms/oaep.rs` (`decrypt_inner`), with the first-octet
/// check restored. Returns the offset of the message in `em`, valid only if the `CtOption` is
/// some.
fn oaep_decode_inner(em: &mut [u8], expected_p_hash: &[u8], k: usize) -> Option<CtOption<u32>> {
    if k < 11 || k < H_SIZE * 2 + 2 || em.len() != k {
        return None;
    }

    let first_is_zero = em[0].ct_eq(&0u8);
    let (_, payload) = em.split_at_mut(1);
    let (seed, db) = payload.split_at_mut(H_SIZE);

    let mut mgf_digest = Sha256::new();
    mgf1_xor_digest(seed, &mut mgf_digest, db);
    mgf1_xor_digest(db, &mut mgf_digest, seed);

    let hash_are_equal = db[0..H_SIZE].ct_eq(expected_p_hash);

    // The remainder of the plaintext must be zero or more 0x00, followed
    // by 0x01, followed by the message.
    //   looking_for_index: 1 if we are still looking for the 0x01
    //   index: the offset of the first 0x01 byte
    //   zero_before_one: 1 if we saw a non-zero byte before the 1
    let mut looking_for_index = Choice::from(1u8);
    let mut index = 0u32;
    let mut nonzero_before_one = Choice::from(0u8);

    for (i, el) in db.iter().skip(H_SIZE).enumerate() {
        let equals0 = el.ct_eq(&0u8);
        let equals1 = el.ct_eq(&1u8);
        index.conditional_assign(&(i as u32), looking_for_index & equals1);
        looking_for_index &= !equals1;
        nonzero_before_one |= looking_for_index & !equals0;
    }

    let valid = first_is_zero & hash_are_equal & !nonzero_before_one & !looking_for_index;

    Some(CtOption::new(index + 2 + (H_SIZE * 2) as u32, valid))
}

/// EME-OAEP decoding with SHA-256 and MGF1-SHA256 (RFC 8017 §7.1.2 step 3) of the `k`-byte
/// output of a raw RSA decryption. Every failure returns the same error.
pub fn oaep_decode_sha256(em: &[u8], label: &[u8], k: usize) -> Result<Zeroizing<Vec<u8>>> {
    let fail = || Error::Card("decryption failed".into());
    let mut em = Zeroizing::new(em.to_vec());
    let expected_p_hash = Sha256::digest(label);
    let res = oaep_decode_inner(&mut em, &expected_p_hash, k).ok_or_else(fail)?;
    let index: Option<u32> = res.into();
    let index = index.ok_or_else(fail)?;
    Ok(Zeroizing::new(em[index as usize..].to_vec()))
}

/// EMSA-PKCS1-v1_5 encoding: `0x00 || 0x01 || PS || 0x00 || prefix || hashed`, `k` bytes.
/// Vendored from `rsa` 0.10.0 `algorithms/pkcs1v15.rs` (`pkcs1v15_sign_pad`). The input is
/// public (a digest or `DigestInfo`), so this involves no secrets.
pub fn emsa_pkcs1v15_encode(prefix: &[u8], hashed: &[u8], k: usize) -> Result<Vec<u8>> {
    let hash_len = hashed.len();
    let t_len = prefix.len() + hashed.len();
    if k < t_len + 11 {
        return Err(Error::DataLenRange);
    }

    // EM = 0x00 || 0x01 || PS || 0x00 || T
    let mut em = vec![0xff; k];
    em[0] = 0;
    em[1] = 1;
    em[k - t_len - 1] = 0;
    em[k - t_len..k - hash_len].copy_from_slice(prefix);
    em[k - hash_len..k].copy_from_slice(hashed);

    Ok(em)
}

/// RSA-OAEP (SHA-256, MGF1-SHA256) encryption to a manifest `encrypt` key, for the
/// provider's software `C_Encrypt`. Uses the `rsa` crate's own OAEP implementation.
pub fn encrypt_oaep_sha256(
    key: &crate::keys::PublicKey,
    label: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let pk = key.rsa().ok_or(Error::KeyFunctionNotPermitted)?;
    let k = key
        .algorithm()
        .rsa_modulus_len()
        .ok_or(Error::KeyFunctionNotPermitted)?;
    if plaintext.len() > crate::mechanism::oaep_max_plaintext(k) {
        return Err(Error::DataLenRange);
    }
    let padding = rsa::Oaep::<Sha256>::new_with_label(label.to_vec().into_boxed_slice());
    pk.encrypt(&mut crate::signing::rng(), padding, plaintext)
        .map_err(|e| Error::Crypto(e.to_string()))
}

/// DER `ECDSA-Sig-Value` to `r || s` for a P-256 (64 bytes) or P-384 (96 bytes) key.
pub fn ecdsa_der_to_raw_for(alg: crate::keys::Algorithm, der: &[u8]) -> Result<Vec<u8>> {
    let bad = || Error::Card("invalid DER ECDSA signature".into());
    match alg {
        crate::keys::Algorithm::P256 => Ok(ecdsa_der_to_raw(der)?.to_vec()),
        crate::keys::Algorithm::P384 => {
            let sig = p384::ecdsa::Signature::from_der(der).map_err(|_| bad())?;
            Ok(sig.to_bytes().to_vec())
        }
        _ => Err(bad()),
    }
}

/// Convert a DER `ECDSA-Sig-Value` (what PIV, Security.framework and OpenSSL return) to the
/// raw `r || s` form `CKM_ECDSA` callers and the wire format use.
pub fn ecdsa_der_to_raw(der: &[u8]) -> Result<[u8; 64]> {
    let sig = p256::ecdsa::Signature::from_der(der)
        .map_err(|_| Error::Card("invalid DER ECDSA signature".into()))?;
    Ok(sig.to_bytes().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::traits::PublicKeyParts;

    /// Cross-test against rsa's own OAEP encryption, through the raw RSA primitive.
    #[test]
    fn oaep_matches_rsa_crate() {
        let sk = rsa::PrivateKey::new(&mut crate::signing::rng(), 2048).unwrap();
        let pk = sk.to_public_key();
        let k = pk.size();
        for (msg, label) in [
            (&b"hello"[..], &b""[..]),
            (&[0u8; 190][..], &b"lbl"[..]),
            (&b""[..], &b""[..]),
        ] {
            let padding = rsa::Oaep::<Sha256>::new_with_label(label.to_vec().into_boxed_slice());
            let ct = pk
                .encrypt(&mut crate::signing::rng(), padding, msg)
                .unwrap();
            let c = rsa::BoxedUint::from_be_slice(&ct, pk.n_bits_precision()).unwrap();
            let m = rsa::hazmat::rsa_decrypt_and_check(&sk, Some(&mut crate::signing::rng()), &c)
                .unwrap();
            let em = m.to_be_bytes_trimmed_vartime();
            let mut padded = vec![0u8; k - em.len()];
            padded.extend_from_slice(&em);
            assert_eq!(&*oaep_decode_sha256(&padded, label, k).unwrap(), msg);
            // Wrong label, flipped bytes and a non-zero first octet all fail the same way.
            assert!(oaep_decode_sha256(&padded, b"other", k).is_err());
            // Any byte of maskedDB feeds the seed mask, so a flip anywhere breaks the label hash.
            for pos in [1, 33, 40, k / 2, k - 1] {
                let mut bad = padded.clone();
                bad[pos] ^= 1;
                assert!(oaep_decode_sha256(&bad, label, k).is_err(), "flip at {pos}");
            }
            let mut bad = padded.clone();
            bad[0] = 1;
            assert!(oaep_decode_sha256(&bad, label, k).is_err());
        }
    }

    /// Cross-test against rsa's PKCS#1 v1.5 verification.
    #[test]
    fn pkcs1v15_matches_rsa_crate() {
        let sk = rsa::PrivateKey::new(&mut crate::signing::rng(), 2048).unwrap();
        let pk = sk.to_public_key();
        let k = pk.size();
        let digest = Sha256::digest(b"message");
        let em = emsa_pkcs1v15_encode(&SHA256_DIGEST_INFO_PREFIX, &digest, k).unwrap();
        let m = rsa::BoxedUint::from_be_slice(&em, pk.n_bits_precision()).unwrap();
        let s =
            rsa::hazmat::rsa_decrypt_and_check(&sk, Some(&mut crate::signing::rng()), &m).unwrap();
        let sig = s.to_be_bytes().to_vec();
        pk.verify(rsa::Pkcs1v15Sign::new::<Sha256>(), &digest, &sig)
            .unwrap();
        assert_eq!(
            emsa_pkcs1v15_encode(&[], &[0u8; 246], 256),
            Err(Error::DataLenRange)
        );
    }

    #[test]
    fn encrypt_then_card_decode_round_trip() {
        let sk = rsa::PrivateKey::new(&mut crate::signing::rng(), 2048).unwrap();
        let der = rsa::pkcs8::EncodePublicKey::to_public_key_der(&sk.to_public_key()).unwrap();
        let pk = crate::keys::PublicKey::from_spki(der.as_bytes()).unwrap();
        let ct = encrypt_oaep_sha256(&pk, b"L", b"secret").unwrap();
        let pt = sk
            .decrypt(
                rsa::Oaep::<Sha256>::new_with_label(b"L".to_vec().into_boxed_slice()),
                &ct,
            )
            .unwrap();
        assert_eq!(pt, b"secret");
        assert_eq!(
            encrypt_oaep_sha256(&pk, b"", &[0u8; 191]),
            Err(Error::DataLenRange)
        );
        assert!(encrypt_oaep_sha256(&pk, b"", &[0u8; 190]).is_ok());
    }

    #[test]
    fn der_to_raw() {
        use p256::ecdsa::signature::Signer;
        let sk = <p256::ecdsa::SigningKey as p256::elliptic_curve::Generate>::generate_from_rng(
            &mut crate::signing::rng(),
        );
        let sig: p256::ecdsa::Signature = sk.sign(b"x");
        let raw = ecdsa_der_to_raw(sig.to_der().as_bytes()).unwrap();
        assert_eq!(raw, <[u8; 64]>::from(sig.to_bytes()));
        assert!(ecdsa_der_to_raw(&[0x30, 0x00]).is_err());
    }
}
