//! Is the manifest signer's OpenPGP key still usable? (wire-format §11.4)
//!
//! Clients never ask this, because headless hosts can't be relied on to reach a keyserver. The
//! relay asks it continuously and the app asks it at setup. Every signature that counts is
//! verified under the key itself, so neither a keyserver nor a relay can fake a revocation or an
//! expiry.

use std::io::Cursor;

use pgp::composed::{Deserializable, SignedPublicKey};
use pgp::packet::{Signature, SignatureType};
use pgp::types::{KeyDetails, Tag};

use crate::error::{Error, Result};

/// The signer key's status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerStatus {
    /// Usable; `expires` is when the key that would sign stops being valid, if it expires.
    Usable { expires: Option<u64> },
    /// Revoked at `at` (the revocation's creation time); `reason` as the key's owner gave it.
    Revoked { at: u64, reason: String },
    /// Expired at `at`.
    Expired { at: u64 },
    /// Neither the primary key nor any subkey may sign.
    CannotSign,
}

impl SignerStatus {
    pub fn is_usable(&self) -> bool {
        matches!(self, SignerStatus::Usable { .. })
    }

    /// What a person should be told when the key is not usable.
    pub fn describe(&self) -> String {
        match self {
            SignerStatus::Usable { expires: None } => "usable".into(),
            SignerStatus::Usable { expires: Some(t) } => format!("usable until {t}"),
            SignerStatus::Revoked { at, reason } if reason.is_empty() => {
                format!("revoked at {at}")
            }
            SignerStatus::Revoked { at, reason } => format!("revoked at {at}: {reason}"),
            SignerStatus::Expired { at } => format!("expired at {at}"),
            SignerStatus::CannotSign => "has no key that may sign".into(),
        }
    }
}

fn bad(m: impl Into<String>) -> Error {
    Error::ManifestSignatureInvalid(m.into())
}

/// Parse one copy of a public key, armored or binary, without requiring its bindings to verify
/// (a revoked or expired key is exactly what this module must still read).
pub fn parse_key(bytes: &[u8]) -> Result<SignedPublicKey> {
    SignedPublicKey::from_reader_single(Cursor::new(bytes))
        .map(|(k, _)| k)
        .map_err(|e| bad(format!("signer key: {e}")))
}

/// Uppercase hex fingerprint of a key's primary key.
pub fn fingerprint(key: &SignedPublicKey) -> String {
    hex::encode_upper(key.primary_key.fingerprint().as_bytes())
}

fn secs(s: &Signature) -> u64 {
    s.created().map(|t| u64::from(t.as_secs())).unwrap_or(0)
}

/// `created + expiration`, or `None` when the signature sets no expiry (or zero).
fn expiry(created: u64, s: &Signature) -> Option<u64> {
    s.key_expiration_time()
        .map(|d| u64::from(d.as_secs()))
        .filter(|d| *d > 0)
        .map(|d| created.saturating_add(d))
}

fn reason(s: &Signature) -> String {
    let code = s
        .revocation_reason_code()
        .map(|c| format!("{c:?}"))
        .unwrap_or_default();
    let text = s
        .revocation_reason_string()
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .unwrap_or_default();
    match (code.is_empty(), text.is_empty()) {
        (true, _) => text,
        (false, true) => code,
        (false, false) => format!("{code}: {text}"),
    }
}

/// The status over every copy seen (wire-format §11.4). All copies must have the same primary
/// key; the first copy's primary key verifies every signature.
pub fn signer_status(copies: &[SignedPublicKey], now: u64) -> Result<SignerStatus> {
    let first = copies
        .first()
        .ok_or_else(|| bad("no copy of the signer key"))?;
    let primary = &first.primary_key;
    let fpr = fingerprint(first);
    if let Some(other) = copies.iter().find(|c| fingerprint(c) != fpr) {
        return Err(bad(format!(
            "copies of different keys: {fpr} and {}",
            fingerprint(other)
        )));
    }

    // Revocation of the primary key, from any copy.
    let mut revoked: Option<&Signature> = None;
    for c in copies {
        for s in &c.details.revocation_signatures {
            if s.typ() == Some(SignatureType::KeyRevocation)
                && s.verify_key(primary).is_ok()
                && revoked.is_none_or(|r| secs(s) < secs(r))
            {
                revoked = Some(s);
            }
        }
    }
    if let Some(r) = revoked {
        return Ok(SignerStatus::Revoked {
            at: secs(r),
            reason: reason(r),
        });
    }

    // The newest verifying self-signature on the primary key, across copies: a stripped copy
    // can't hide a newer one that renewed the key.
    let mut candidates: Vec<&Signature> = Vec::new();
    for c in copies {
        for s in &c.details.direct_signatures {
            if s.typ() == Some(SignatureType::Key) && s.verify_key(primary).is_ok() {
                candidates.push(s);
            }
        }
        for u in &c.details.users {
            for s in &u.signatures {
                let cert = matches!(
                    s.typ(),
                    Some(
                        SignatureType::CertGeneric
                            | SignatureType::CertPersona
                            | SignatureType::CertCasual
                            | SignatureType::CertPositive
                    )
                );
                if cert && s.verify_certification(primary, Tag::UserId, &u.id).is_ok() {
                    candidates.push(s);
                }
            }
        }
    }
    let newest = candidates.into_iter().max_by_key(|s| secs(s));
    let Some(self_sig) = newest else {
        return Err(bad("signer key has no valid self-signature"));
    };
    let created = u64::from(primary.created_at().as_secs());
    let primary_expiry = expiry(created, self_sig);
    if let Some(at) = primary_expiry {
        if at <= now {
            return Ok(SignerStatus::Expired { at });
        }
    }
    if self_sig.key_flags().sign() {
        return Ok(SignerStatus::Usable {
            expires: primary_expiry,
        });
    }

    // The primary key may not sign: a signing subkey must be bound, unrevoked and unexpired.
    let mut any_signing = false;
    let mut latest_revocation: Option<&Signature> = None;
    let mut latest_expiry: Option<u64> = None;
    let mut subkeys: Vec<(String, &pgp::packet::PublicSubkey)> = Vec::new();
    for c in copies {
        for sk in &c.public_subkeys {
            let f = hex::encode_upper(sk.key.fingerprint().as_bytes());
            if !subkeys.iter().any(|(g, _)| *g == f) {
                subkeys.push((f, &sk.key));
            }
        }
    }
    for (f, key) in subkeys {
        let sigs = copies
            .iter()
            .flat_map(|c| c.public_subkeys.iter())
            .filter(|sk| hex::encode_upper(sk.key.fingerprint().as_bytes()) == f)
            .flat_map(|sk| sk.signatures.iter());
        let mut binding: Option<&Signature> = None;
        let mut sub_revoked: Option<&Signature> = None;
        for s in sigs {
            if s.verify_subkey_binding(primary, key).is_err() {
                continue;
            }
            match s.typ() {
                Some(SignatureType::SubkeyBinding) if binding.is_none_or(|b| secs(s) > secs(b)) => {
                    binding = Some(s)
                }
                Some(SignatureType::SubkeyRevocation) => sub_revoked = Some(s),
                _ => {}
            }
        }
        let Some(b) = binding else { continue };
        if !b.key_flags().sign() {
            continue;
        }
        any_signing = true;
        if let Some(r) = sub_revoked {
            if latest_revocation.is_none_or(|l| secs(r) > secs(l)) {
                latest_revocation = Some(r);
            }
            continue;
        }
        let sub_expiry = expiry(u64::from(key.created_at().as_secs()), b);
        match sub_expiry {
            Some(at) if at <= now => {
                latest_expiry = Some(latest_expiry.map_or(at, |l: u64| l.max(at)));
            }
            _ => {
                let expires = match (primary_expiry, sub_expiry) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                };
                return Ok(SignerStatus::Usable { expires });
            }
        }
    }
    if !any_signing {
        return Ok(SignerStatus::CannotSign);
    }
    match (latest_revocation, latest_expiry) {
        (Some(r), None) => Ok(SignerStatus::Revoked {
            at: secs(r),
            reason: reason(r),
        }),
        (_, Some(at)) => Ok(SignerStatus::Expired { at }),
        (None, None) => Ok(SignerStatus::CannotSign),
    }
}

/// The user IDs a copy of the key carries, as text (for display: keys.openpgp.org publishes
/// only addresses their owner confirmed).
pub fn user_ids(key: &SignedPublicKey) -> Vec<String> {
    key.details
        .users
        .iter()
        .map(|u| String::from_utf8_lossy(u.id.id()).into_owned())
        .collect()
}
