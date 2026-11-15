//! Pairing codes (wire-format §10.1): four words from the EFF large wordlist, derived from the
//! client identity key, about 51.7 bits.

use std::sync::OnceLock;

use sha2::{Digest, Sha256};

const WORDLIST: &str = include_str!("../data/eff_large_wordlist.txt");
pub const WORDS: usize = 4;
pub const LIST_LEN: u64 = 7_776;

fn words() -> &'static [&'static str] {
    static W: OnceLock<Vec<&'static str>> = OnceLock::new();
    W.get_or_init(|| {
        let w: Vec<&str> = WORDLIST
            .lines()
            .map(|l| l.split('\t').nth(1).expect("wordlist line has a tab"))
            .collect();
        assert_eq!(w.len() as u64, LIST_LEN);
        w
    })
}

/// The pairing code for a client key's DER SubjectPublicKeyInfo, e.g. `word-word-word-word`.
pub fn pairing_code(client_spki: &[u8]) -> String {
    let h = Sha256::digest(client_spki);
    let mut n = u64::from_be_bytes(h[..8].try_into().expect("8 bytes"));
    let list = words();
    let mut out = Vec::with_capacity(WORDS);
    for _ in 0..WORDS {
        out.push(list[(n % LIST_LEN) as usize]);
        n /= LIST_LEN;
    }
    out.join("-")
}

/// Bits of strength of a code (must stay at least 50; see docs/decisions.md).
pub fn strength_bits() -> f64 {
    WORDS as f64 * (LIST_LEN as f64).log2()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendored_wordlist_is_unmodified() {
        assert_eq!(
            hex::encode(Sha256::digest(WORDLIST.as_bytes())),
            "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e"
        );
        assert_eq!(words()[0], "abacus");
        assert_eq!(words()[7_775], "zoom");
    }

    #[test]
    fn at_least_fifty_bits() {
        assert!(strength_bits() >= 50.0, "{}", strength_bits());
    }

    #[test]
    fn deterministic_and_key_dependent() {
        let a = pairing_code(b"key a");
        assert_eq!(a, pairing_code(b"key a"));
        assert_ne!(a, pairing_code(b"key b"));
        assert_eq!(a.split('-').count(), 4);
    }
}
