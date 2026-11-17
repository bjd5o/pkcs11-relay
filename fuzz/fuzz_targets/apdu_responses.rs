//! PIV response parsing: a card that answers every APDU with fuzzer-chosen bytes, driven
//! through every card path (RSA, ECDSA on P-256 and P-384, EdDSA, ECDH with both KDFs).
#![no_main]
use libfuzzer_sys::fuzz_target;
use relay_core::mechanism::ckm;
use relay_core::piv::{self, CardTransport, PivError, Slot};
use relay_core::{Algorithm, Mechanism};

struct FuzzCard<'a> {
    chunks: std::slice::Split<'a, u8, fn(&u8) -> bool>,
}

impl CardTransport for FuzzCard<'_> {
    fn transmit(&mut self, _apdu: &[u8]) -> Result<Vec<u8>, PivError> {
        self.chunks.next().map(|c| c.to_vec()).ok_or_else(|| PivError::Transport("eof".into()))
    }
    fn session(&mut self, f: &mut dyn FnMut(&mut dyn CardTransport)) -> Result<(), PivError> {
        f(self);
        Ok(())
    }
}

fn card(data: &[u8]) -> FuzzCard<'_> {
    // 0xFE separates the card's successive responses.
    FuzzCard { chunks: data.split((|b: &u8| *b == 0xfe) as fn(&u8) -> bool) }
}

/// A valid peer public key for each ECDH curve (the generator point / basepoint), so the
/// fuzzer reaches the card exchange instead of stopping at peer-key validation.
fn peer(alg: Algorithm) -> Vec<u8> {
    match alg {
        Algorithm::P256 => {
            let mut v = vec![0x04];
            v.extend_from_slice(&hex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"));
            v.extend_from_slice(&hex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"));
            v
        }
        Algorithm::P384 => {
            let mut v = vec![0x04];
            v.extend_from_slice(&hex("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7"));
            v.extend_from_slice(&hex("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"));
            v
        }
        _ => {
            let mut v = vec![0u8; 32];
            v[0] = 9;
            v
        }
    }
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fuzz_target!(|data: &[u8]| {
    let slot = Slot::new(0x9a).unwrap();
    let _ = piv::select(&mut card(data));
    let _ = piv::pin_retries(&mut card(data));
    let _ = piv::read_certificate(&mut card(data), slot);
    let _ = piv::read_public_key(&mut card(data), slot);
    let _ = piv::perform(&mut card(data), slot, Algorithm::P256, &Mechanism::Ecdsa, &[1u8; 32]);
    let _ = piv::perform(&mut card(data), slot, Algorithm::P384, &Mechanism::EcdsaSha384, b"message");
    let _ = piv::perform(&mut card(data), slot, Algorithm::Ed25519, &Mechanism::Eddsa, b"message");
    let _ = piv::perform(&mut card(data), slot, Algorithm::Rsa2048, &Mechanism::RsaPkcsOaep { label: vec![] }, &[0u8; 256]);
    for alg in [Algorithm::P256, Algorithm::P384, Algorithm::X25519] {
        let n = alg.ec_field_len().unwrap() as u32;
        for (kdf, shared, len) in [(ckm::CKD_NULL, vec![], n), (ckm::CKD_SHA256_KDF, b"info".to_vec(), 32)] {
            let m = Mechanism::ecdh_from_pkcs11(kdf, shared, len).unwrap();
            let _ = piv::perform(&mut card(data), slot, alg, &m, &peer(alg));
        }
    }
});
