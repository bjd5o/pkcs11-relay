//! Relay HTTP authentication (wire-format §8): every authenticated call carries a key
//! fingerprint, a timestamp, a random nonce and a signature over the method, path, time, nonce
//! and body hash.

use std::collections::HashMap;

use base64::Engine as _;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::keys::{Fingerprint, PublicKey};
use crate::signing::{random_bytes, SoftwareKey};

pub const CONTEXT: &str = "relay-pkcs11/relay-auth/v1";
pub const HEADER_KEY: &str = "x-relay-key";
pub const HEADER_TIME: &str = "x-relay-time";
pub const HEADER_NONCE: &str = "x-relay-nonce";
pub const HEADER_SIGNATURE: &str = "x-relay-signature";
/// How long a nonce is remembered: twice the 60 s skew window.
pub const NONCE_WINDOW: u64 = 120;
/// Upper bound on remembered nonces; beyond it the relay fails closed.
pub const MAX_NONCES: usize = 100_000;

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// The parsed authentication headers of one call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthHeaders {
    pub key: Fingerprint,
    pub time: u64,
    pub nonce: [u8; 16],
    pub signature: [u8; 64],
}

/// The bytes a caller signs for one HTTP call.
pub fn to_be_signed(
    method: &str,
    path_and_query: &str,
    time: u64,
    nonce: &[u8; 16],
    body: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(160 + path_and_query.len());
    for part in [
        CONTEXT.as_bytes(),
        method.as_bytes(),
        path_and_query.as_bytes(),
        time.to_string().as_bytes(),
    ] {
        out.extend_from_slice(part);
        out.push(0);
    }
    out.extend_from_slice(nonce);
    out.push(0);
    out.extend_from_slice(&Sha256::digest(body));
    out
}

impl AuthHeaders {
    /// Sign a call with a software key and a fresh nonce.
    pub fn sign(
        key: &SoftwareKey,
        method: &str,
        path_and_query: &str,
        body: &[u8],
        now: u64,
    ) -> Self {
        let mut nonce = [0u8; 16];
        random_bytes(&mut nonce);
        let signature = key.sign(&to_be_signed(method, path_and_query, now, &nonce, body));
        AuthHeaders {
            key: key.public_key().fingerprint().clone(),
            time: now,
            nonce,
            signature,
        }
    }

    /// Header name/value pairs to send.
    pub fn to_headers(&self) -> [(&'static str, String); 4] {
        [
            (HEADER_KEY, self.key.as_str().to_string()),
            (HEADER_TIME, self.time.to_string()),
            (HEADER_NONCE, b64().encode(self.nonce)),
            (HEADER_SIGNATURE, b64().encode(self.signature)),
        ]
    }

    /// Parse header values strictly; `None` for a missing header.
    pub fn parse(
        key: Option<&str>,
        time: Option<&str>,
        nonce: Option<&str>,
        signature: Option<&str>,
    ) -> Result<Self> {
        let bad = |m: &str| Error::RelayAuth(m.to_string());
        let (Some(key), Some(time), Some(nonce), Some(signature)) = (key, time, nonce, signature)
        else {
            return Err(bad("missing authentication headers"));
        };
        let key = Fingerprint::parse(key).map_err(|_| bad("bad key fingerprint"))?;
        if time.is_empty()
            || time.len() > 20
            || !time.bytes().all(|b| b.is_ascii_digit())
            || (time.len() > 1 && time.starts_with('0'))
        {
            return Err(bad("bad time"));
        }
        let time = time.parse().map_err(|_| bad("bad time"))?;
        let nonce: [u8; 16] = b64()
            .decode(nonce)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| bad("bad nonce"))?;
        let signature: [u8; 64] = b64()
            .decode(signature)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| bad("bad signature encoding"))?;
        Ok(AuthHeaders {
            key,
            time,
            nonce,
            signature,
        })
    }
}

/// Nonces seen per key within the window.
#[derive(Debug, Default)]
pub struct NonceCache {
    seen: HashMap<(Fingerprint, [u8; 16]), u64>,
}

impl NonceCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn insert(&mut self, key: &Fingerprint, nonce: [u8; 16], now: u64) -> Result<()> {
        self.seen
            .retain(|_, t| now.saturating_sub(*t) <= NONCE_WINDOW);
        if self.seen.len() >= MAX_NONCES {
            return Err(Error::RelayAuth("nonce cache full".into()));
        }
        if self.seen.insert((key.clone(), nonce), now).is_some() {
            return Err(Error::RelayAuth("replayed nonce".into()));
        }
        Ok(())
    }
}

/// Verify one call's authentication against the key registered for `h.key`. The nonce is
/// recorded only after the signature verifies, so unauthenticated callers cannot fill the cache.
#[allow(clippy::too_many_arguments)]
pub fn verify_relay_auth(
    h: &AuthHeaders,
    method: &str,
    path_and_query: &str,
    body: &[u8],
    key: &PublicKey,
    now: u64,
    skew: u64,
    nonces: &mut NonceCache,
) -> Result<()> {
    if &h.key != key.fingerprint() {
        return Err(Error::RelayAuth(
            "key does not match the registered key".into(),
        ));
    }
    if now.abs_diff(h.time) > skew {
        return Err(Error::RelayAuth(
            "timestamp outside the allowed skew".into(),
        ));
    }
    key.verify_message(
        &to_be_signed(method, path_and_query, h.time, &h.nonce, body),
        &h.signature,
    )
    .map_err(|_| Error::RelayAuth("bad signature".into()))?;
    nonces.insert(&h.key, h.nonce, now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_format_example_bytes() {
        let nonce: [u8; 16] = hex::decode("00112233445566778899aabbccddeeff")
            .unwrap()
            .try_into()
            .unwrap();
        let b = to_be_signed(
            "GET",
            "/v1/requests/9f2c4e1a7b3d5f60a1b2c3d4e5f60718/result?wait=30",
            1_794_744_000,
            &nonce,
            b"",
        );
        assert_eq!(b.len(), 152);
        assert_eq!(
            hex::encode(&b[..27]),
            "72656c61792d706b637331312f72656c61792d617574682f763100"
        );
        assert!(hex::encode(&b)
            .ends_with("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    }

    #[test]
    fn sign_parse_verify_and_replay() {
        let k = SoftwareKey::generate_ed25519();
        let h = AuthHeaders::sign(&k, "POST", "/v1/requests", b"body", 1000);
        let [(_, a), (_, b), (_, c), (_, d)] = h.to_headers();
        let p = AuthHeaders::parse(Some(&a), Some(&b), Some(&c), Some(&d)).unwrap();
        assert_eq!(p, h);
        let mut n = NonceCache::new();
        let pk = k.public_key();
        verify_relay_auth(&p, "POST", "/v1/requests", b"body", &pk, 1030, 60, &mut n).unwrap();
        assert!(
            verify_relay_auth(&p, "POST", "/v1/requests", b"body", &pk, 1031, 60, &mut n).is_err(),
            "replay"
        );
        let h2 = AuthHeaders::sign(&k, "POST", "/v1/requests", b"body", 1000);
        assert!(
            verify_relay_auth(&h2, "POST", "/v1/requests", b"bodY", &pk, 1000, 60, &mut n).is_err(),
            "body"
        );
        assert!(
            verify_relay_auth(&h2, "GET", "/v1/requests", b"body", &pk, 1000, 60, &mut n).is_err(),
            "method"
        );
        assert!(
            verify_relay_auth(&h2, "POST", "/v1/requests", b"body", &pk, 1061, 60, &mut n).is_err(),
            "skew"
        );
        verify_relay_auth(&h2, "POST", "/v1/requests", b"body", &pk, 1060, 60, &mut n).unwrap();
    }

    #[test]
    fn rejects_malformed_headers() {
        let ok_nonce = b64().encode([0u8; 16]);
        let ok_sig = b64().encode([0u8; 64]);
        let fp = Fingerprint::of_spki(b"x");
        for time in ["", "01", "1e3", "-1", "99999999999999999999999"] {
            assert!(
                AuthHeaders::parse(
                    Some(fp.as_str()),
                    Some(time),
                    Some(&ok_nonce),
                    Some(&ok_sig)
                )
                .is_err(),
                "{time}"
            );
        }
        assert!(
            AuthHeaders::parse(Some(fp.as_str()), Some("1"), Some("AAAA"), Some(&ok_sig)).is_err()
        );
        assert!(AuthHeaders::parse(None, Some("1"), Some(&ok_nonce), Some(&ok_sig)).is_err());
    }
}
