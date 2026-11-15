//! PIV response parsing: a card that answers every APDU with fuzzer-chosen bytes.
#![no_main]
use libfuzzer_sys::fuzz_target;
use relay_core::piv::{self, CardTransport, PivError, Slot};
use relay_core::{Algorithm, Mechanism};

struct FuzzCard<'a> {
    chunks: std::slice::Split<'a, u8, fn(&u8) -> bool>,
}

impl CardTransport for FuzzCard<'_> {
    fn transmit(&mut self, _apdu: &[u8]) -> Result<Vec<u8>, PivError> {
        self.chunks.next().map(|c| c.to_vec()).ok_or_else(|| PivError::Transport("eof".into()))
    }
}

fn card(data: &[u8]) -> FuzzCard<'_> {
    // 0xFE separates the card's successive responses.
    FuzzCard { chunks: data.split((|b: &u8| *b == 0xfe) as fn(&u8) -> bool) }
}

fuzz_target!(|data: &[u8]| {
    let slot = Slot::new(0x9a).unwrap();
    let _ = piv::select(&mut card(data));
    let _ = piv::pin_retries(&mut card(data));
    let _ = piv::read_certificate(&mut card(data), slot);
    let _ = piv::perform(&mut card(data), slot, Algorithm::P256, &Mechanism::Ecdsa, &[1u8; 32]);
    let _ = piv::perform(&mut card(data), slot, Algorithm::Rsa2048, &Mechanism::RsaPkcsOaep { label: vec![] }, &[0u8; 256]);
});
