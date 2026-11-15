//! Sealing results to the request's one-time reply key (wire-format §7).

use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha256;
use hpke::kem::DhP256HkdfSha256;
use hpke::{Deserializable, Kem as _, OpModeR, OpModeS, Serializable};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::signing::rng;

type Kem = DhP256HkdfSha256;

/// Encapsulated key length for DHKEM(P-256): an uncompressed point.
pub const ENC_LEN: usize = 65;
/// Reply public key length (`SerializePublicKey`).
pub const REPLY_PUB_LEN: usize = 65;
const INFO_PREFIX: &[u8] = b"relay-pkcs11/result/v1";

fn info(req_id: &[u8; 16]) -> Vec<u8> {
    let mut v = INFO_PREFIX.to_vec();
    v.extend_from_slice(req_id);
    v
}

/// A one-time reply key pair. The private key is zeroized on drop (by `p256`) and consumed by
/// [`ReplyKey::open`], so it cannot be used twice.
pub struct ReplyKey {
    sk: <Kem as hpke::Kem>::PrivateKey,
    pk: [u8; REPLY_PUB_LEN],
}

impl ReplyKey {
    pub fn generate() -> Self {
        let (sk, pk) = Kem::gen_keypair_with_rng(&mut rng());
        let pk: [u8; REPLY_PUB_LEN] = pk.to_bytes().as_slice().try_into().expect("65-byte point");
        ReplyKey { sk, pk }
    }

    pub fn public_bytes(&self) -> [u8; REPLY_PUB_LEN] {
        self.pk
    }

    /// Open a sealed result and consume the key.
    pub fn open(self, req_id: &[u8; 16], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        open_with(&self.sk, req_id, sealed)
    }

    /// Restore a reply key from its private bytes (test vectors only).
    #[cfg(any(test, feature = "test-util"))]
    pub fn from_private_bytes(sk: &[u8]) -> Result<Self> {
        let sk = <Kem as hpke::Kem>::PrivateKey::from_bytes(sk)
            .map_err(|_| Error::Crypto("bad reply key".into()))?;
        let pk = Kem::sk_to_pk(&sk);
        let pk: [u8; REPLY_PUB_LEN] = pk.to_bytes().as_slice().try_into().expect("65-byte point");
        Ok(ReplyKey { sk, pk })
    }

    /// Private key bytes (test vectors only).
    #[cfg(any(test, feature = "test-util"))]
    pub fn private_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.sk.to_bytes().to_vec())
    }
}

fn open_with(
    sk: &<Kem as hpke::Kem>::PrivateKey,
    req_id: &[u8; 16],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.len() < ENC_LEN + 16 {
        return Err(Error::ResultOpenFailed);
    }
    let (enc, ct) = sealed.split_at(ENC_LEN);
    let enc =
        <Kem as hpke::Kem>::EncappedKey::from_bytes(enc).map_err(|_| Error::ResultOpenFailed)?;
    let pt = hpke::single_shot_open::<AesGcm256, HkdfSha256, Kem>(
        &OpModeR::Base,
        sk,
        &enc,
        &info(req_id),
        ct,
        req_id,
    )
    .map_err(|_| Error::ResultOpenFailed)?;
    Ok(Zeroizing::new(pt))
}

/// Seal `plaintext` to `reply_pub` for request `req_id`: returns `enc || ciphertext`.
pub fn seal(reply_pub: &[u8], req_id: &[u8; 16], plaintext: &[u8]) -> Result<Vec<u8>> {
    let pk = <Kem as hpke::Kem>::PublicKey::from_bytes(reply_pub)
        .map_err(|_| Error::Crypto("invalid reply public key".into()))?;
    let (enc, ct) = hpke::single_shot_seal_with_rng::<AesGcm256, HkdfSha256, Kem>(
        &OpModeS::Base,
        &pk,
        &info(req_id),
        plaintext,
        req_id,
        &mut rng(),
    )
    .map_err(|e| Error::Crypto(format!("seal failed: {e:?}")))?;
    let mut out = enc.to_bytes().to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Validate a reply public key's encoding (an uncompressed P-256 point).
pub(crate) fn check_reply_pub(reply_pub: &[u8]) -> Result<()> {
    if reply_pub.len() != REPLY_PUB_LEN || reply_pub[0] != 0x04 {
        return Err(Error::Decode(
            "reply_pub must be an uncompressed P-256 point".into(),
        ));
    }
    <Kem as hpke::Kem>::PublicKey::from_bytes(reply_pub)
        .map(|_| ())
        .map_err(|_| Error::Decode("reply_pub is not a valid P-256 point".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_binding() {
        let id = [7u8; 16];
        let k = ReplyKey::generate();
        check_reply_pub(&k.public_bytes()).unwrap();
        let sealed = seal(&k.public_bytes(), &id, b"secret").unwrap();
        assert_eq!(sealed.len(), ENC_LEN + 6 + 16);
        // wrong req_id fails (info and aad bind it)
        let k2 = ReplyKey::from_private_bytes(&k.private_bytes()).unwrap();
        assert_eq!(
            k2.open(&[8u8; 16], &sealed).err(),
            Some(Error::ResultOpenFailed)
        );
        assert_eq!(&*k.open(&id, &sealed).unwrap(), b"secret");
    }
}
