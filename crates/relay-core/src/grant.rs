//! Client grants and revocations (wire-format §12).
//!
//! A grant says which manifest keys a client identity key may use. It is signed by a manifest
//! `attest` key, on the card, when a person approves a pairing or changes a client, so devices
//! trust grants the way they trust attestations: through the manifest, never through the relay.
//! A revocation, signed the same way, cancels every grant for a client key up to a sequence
//! number.

use crate::attestation::check_id;
use crate::cbor::{self, Fields, MapBuilder};
use crate::error::{Error, Result};
use crate::keys::{Fingerprint, PublicKey, Role};
use crate::manifest::{Manifest, MAX_CLIENT_GRANT_WINDOW, MIN_CLIENT_GRANT_WINDOW};

pub const GRANT_CONTEXT: &str = "relay-pkcs11/client-grant/v1";
pub const REVOCATION_CONTEXT: &str = "relay-pkcs11/client-revocation/v1";

/// Most keys one grant may list (wire-format §12.1).
pub const MAX_GRANT_KEYS: usize = 64;

/// The fields of a grant without its signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedGrant {
    pub client_id: String,
    pub client_key: PublicKey,
    /// Sorted bytewise, no duplicates, 1–64.
    pub keys: Vec<Fingerprint>,
    pub seq: u64,
    pub window_secs: u64,
    pub issued_at: u64,
    /// Always `issued_at + window_secs`.
    pub not_after: u64,
    /// The approving device, for display only.
    pub approved_by: String,
    pub attest_key_fingerprint: Fingerprint,
}

impl UnsignedGrant {
    /// Build a grant. `keys` may come in any order and is sorted here; duplicates are refused.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client_id: &str,
        client_key: PublicKey,
        mut keys: Vec<Fingerprint>,
        seq: u64,
        window_secs: u64,
        issued_at: u64,
        approved_by: &str,
        attest_key_fingerprint: Fingerprint,
    ) -> Result<Self> {
        keys.sort();
        Self::checked(
            client_id,
            client_key,
            keys,
            seq,
            window_secs,
            issued_at,
            None,
            approved_by,
            attest_key_fingerprint,
        )
    }

    /// The same client and keys with `seq + 1`, issued at `now`: a renewal.
    pub fn renewed(&self, now: u64, approved_by: &str, attest: Fingerprint) -> Result<Self> {
        let seq = self
            .seq
            .checked_add(1)
            .ok_or_else(|| Error::Decode("grant sequence overflow".into()))?;
        Self::new(
            &self.client_id,
            self.client_key.clone(),
            self.keys.clone(),
            seq,
            self.window_secs,
            now,
            approved_by,
            attest,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn checked(
        client_id: &str,
        client_key: PublicKey,
        keys: Vec<Fingerprint>,
        seq: u64,
        window_secs: u64,
        issued_at: u64,
        not_after: Option<u64>,
        approved_by: &str,
        attest_key_fingerprint: Fingerprint,
    ) -> Result<Self> {
        check_id(client_id)?;
        check_id(approved_by)?;
        if keys.is_empty() || keys.len() > MAX_GRANT_KEYS {
            return Err(Error::Decode(format!(
                "a grant lists 1-{MAX_GRANT_KEYS} keys"
            )));
        }
        if keys.windows(2).any(|w| w[0] >= w[1]) {
            return Err(Error::Decode(
                "grant keys must be sorted with no duplicates".into(),
            ));
        }
        if seq == 0 {
            return Err(Error::Decode("grant seq starts at 1".into()));
        }
        if !(MIN_CLIENT_GRANT_WINDOW..=MAX_CLIENT_GRANT_WINDOW).contains(&window_secs) {
            return Err(Error::Decode(format!(
                "window_secs must be {MIN_CLIENT_GRANT_WINDOW}-{MAX_CLIENT_GRANT_WINDOW}"
            )));
        }
        let expected = issued_at
            .checked_add(window_secs)
            .ok_or_else(|| Error::Decode("not_after overflows".into()))?;
        if not_after.is_some_and(|n| n != expected) {
            return Err(Error::Decode(
                "not_after must equal issued_at + window_secs".into(),
            ));
        }
        Ok(UnsignedGrant {
            client_id: client_id.into(),
            client_key,
            keys,
            seq,
            window_secs,
            issued_at,
            not_after: expected,
            approved_by: approved_by.into(),
            attest_key_fingerprint,
        })
    }

    fn map(&self) -> MapBuilder {
        let keys: Vec<String> = self.keys.iter().map(|k| k.as_str().to_string()).collect();
        MapBuilder::new()
            .uint("v", 1)
            .uint("seq", self.seq)
            .text_array("keys", &keys)
            .text("client_id", &self.client_id)
            .uint("issued_at", self.issued_at)
            .uint("not_after", self.not_after)
            .bytes("client_key", self.client_key.spki())
            .text("approved_by", &self.approved_by)
            .uint("window_secs", self.window_secs)
            .text(
                "attest_key_fingerprint",
                self.attest_key_fingerprint.as_str(),
            )
    }

    /// The bytes the attest key signs (ECDSA P-256 over SHA-256 of these).
    pub fn to_be_signed(&self) -> Vec<u8> {
        cbor::signed_bytes(GRANT_CONTEXT, &self.map().encode())
    }

    /// Attach a 64-byte `r || s` signature and encode the grant.
    pub fn with_signature(self, sig: [u8; 64]) -> ClientGrant {
        let bytes = self.map().bytes("sig", &sig).encode();
        ClientGrant {
            fields: self,
            sig,
            bytes,
        }
    }
}

/// A decoded (not yet verified) grant, with its exact bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientGrant {
    pub fields: UnsignedGrant,
    pub sig: [u8; 64],
    bytes: Vec<u8>,
}

impl ClientGrant {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Strict decode: canonical CBOR, every field present and well formed, keys sorted, and
    /// `not_after = issued_at + window_secs`.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut f = Fields::new(cbor::decode_map(bytes)?);
        f.version()?;
        let seq = f.uint("seq")?;
        let sig = f.fixed::<64>("sig")?;
        let keys = f
            .text_array("keys")?
            .iter()
            .map(|k| Fingerprint::parse(k))
            .collect::<Result<Vec<_>>>()?;
        let client_id = f.text("client_id")?;
        let issued_at = f.uint("issued_at")?;
        let not_after = f.uint("not_after")?;
        let client_key = PublicKey::from_spki(&f.bytes("client_key")?)?;
        let approved_by = f.text("approved_by")?;
        let window_secs = f.uint("window_secs")?;
        let attest_key_fingerprint = Fingerprint::parse(&f.text("attest_key_fingerprint")?)?;
        f.finish()?;
        let fields = UnsignedGrant::checked(
            &client_id,
            client_key,
            keys,
            seq,
            window_secs,
            issued_at,
            Some(not_after),
            &approved_by,
            attest_key_fingerprint,
        )?;
        Ok(ClientGrant {
            fields,
            sig,
            bytes: bytes.to_vec(),
        })
    }

    /// The client identity key's fingerprint, which grants and revocations are keyed by.
    pub fn client_fingerprint(&self) -> &Fingerprint {
        self.fields.client_key.fingerprint()
    }
}

/// What [`verify_client_grant`] found: a grant that verifies, and whether its window has
/// passed. A lapsed grant still identifies the client and its keys; the approver shows its
/// requests only with the renewal notice (wire-format §12.2 step 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedGrant {
    pub grant: ClientGrant,
    pub lapsed: bool,
}

fn invalid(m: impl Into<String>) -> Error {
    Error::GrantInvalid(m.into())
}

/// Steps 1–3 of wire-format §12.2: decode, the attest key's signature, the window rules and the
/// keys against the manifest.
fn verify_grant_signature(bytes: &[u8], manifest: &Manifest) -> Result<ClientGrant> {
    let g = ClientGrant::decode(bytes).map_err(|e| invalid(e.to_string()))?;
    let attest = manifest
        .key(&g.fields.attest_key_fingerprint)
        .filter(|k| k.role == Role::Attest)
        .ok_or_else(|| invalid("not signed by a manifest attest key"))?;
    attest
        .public_key
        .verify_message(&g.fields.to_be_signed(), &g.sig)
        .map_err(|_| invalid("signature does not verify"))?;
    if g.fields.window_secs > manifest.max_client_grant_window_secs {
        return Err(invalid(format!(
            "window of {} s exceeds the manifest's maximum of {} s",
            g.fields.window_secs, manifest.max_client_grant_window_secs
        )));
    }
    for k in &g.fields.keys {
        match manifest.key(k) {
            Some(m) if m.role != Role::Attest => {}
            Some(_) => return Err(invalid(format!("{k} is an attest key"))),
            None => return Err(invalid(format!("{k} is not in the manifest"))),
        }
    }
    Ok(g)
}

/// `verify_client_grant(grant, manifest, now, skew)` (wire-format §12.2).
pub fn verify_client_grant(
    bytes: &[u8],
    manifest: &Manifest,
    now: u64,
    skew: u64,
) -> Result<VerifiedGrant> {
    let g = verify_grant_signature(bytes, manifest)?;
    if manifest.client_revoked(g.client_fingerprint()) {
        return Err(Error::ClientRevoked);
    }
    if now.saturating_add(skew) < g.fields.issued_at {
        return Err(invalid("issued in the future"));
    }
    let lapsed = now > g.fields.not_after.saturating_add(skew);
    Ok(VerifiedGrant { grant: g, lapsed })
}

/// Steps 1–3 of §12.2, without revocation or time: for the relay, which stores and serves
/// grants but whose word devices never take.
pub fn verify_client_grant_signer(bytes: &[u8], manifest: &Manifest) -> Result<ClientGrant> {
    verify_grant_signature(bytes, manifest)
}

/// The fields of a revocation without its signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedRevocation {
    pub client_key: PublicKey,
    /// The highest grant `seq` it cancels.
    pub seq: u64,
    pub issued_at: u64,
    pub attest_key_fingerprint: Fingerprint,
}

impl UnsignedRevocation {
    pub fn new(
        client_key: PublicKey,
        seq: u64,
        issued_at: u64,
        attest_key_fingerprint: Fingerprint,
    ) -> Result<Self> {
        if seq == 0 {
            return Err(Error::Decode("a revocation cancels seq 1 or higher".into()));
        }
        Ok(UnsignedRevocation {
            client_key,
            seq,
            issued_at,
            attest_key_fingerprint,
        })
    }

    fn map(&self) -> MapBuilder {
        MapBuilder::new()
            .uint("v", 1)
            .uint("seq", self.seq)
            .uint("issued_at", self.issued_at)
            .bytes("client_key", self.client_key.spki())
            .text(
                "attest_key_fingerprint",
                self.attest_key_fingerprint.as_str(),
            )
    }

    pub fn to_be_signed(&self) -> Vec<u8> {
        cbor::signed_bytes(REVOCATION_CONTEXT, &self.map().encode())
    }

    pub fn with_signature(self, sig: [u8; 64]) -> ClientRevocation {
        let bytes = self.map().bytes("sig", &sig).encode();
        ClientRevocation {
            fields: self,
            sig,
            bytes,
        }
    }
}

/// A decoded revocation, with its exact bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRevocation {
    pub fields: UnsignedRevocation,
    pub sig: [u8; 64],
    bytes: Vec<u8>,
}

impl ClientRevocation {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut f = Fields::new(cbor::decode_map(bytes)?);
        f.version()?;
        let seq = f.uint("seq")?;
        let sig = f.fixed::<64>("sig")?;
        let issued_at = f.uint("issued_at")?;
        let client_key = PublicKey::from_spki(&f.bytes("client_key")?)?;
        let attest_key_fingerprint = Fingerprint::parse(&f.text("attest_key_fingerprint")?)?;
        f.finish()?;
        Ok(ClientRevocation {
            fields: UnsignedRevocation::new(client_key, seq, issued_at, attest_key_fingerprint)?,
            sig,
            bytes: bytes.to_vec(),
        })
    }

    pub fn client_fingerprint(&self) -> &Fingerprint {
        self.fields.client_key.fingerprint()
    }

    /// Whether this revocation cancels `grant`: same client key, and `grant.seq <= seq`.
    pub fn cancels(&self, grant: &ClientGrant) -> bool {
        self.fields.client_key == grant.fields.client_key && grant.fields.seq <= self.fields.seq
    }
}

/// `verify_client_revocation(revocation, manifest)` (wire-format §12.3). No time check: a
/// device keeps a verified revocation for good.
pub fn verify_client_revocation(bytes: &[u8], manifest: &Manifest) -> Result<ClientRevocation> {
    let bad = |m: String| Error::RevocationInvalid(m);
    let r = ClientRevocation::decode(bytes).map_err(|e| bad(e.to_string()))?;
    let attest = manifest
        .key(&r.fields.attest_key_fingerprint)
        .filter(|k| k.role == Role::Attest)
        .ok_or_else(|| bad("not signed by a manifest attest key".into()))?;
    attest
        .public_key
        .verify_message(&r.fields.to_be_signed(), &r.sig)
        .map_err(|_| bad("signature does not verify".into()))?;
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::SoftwareKey;

    fn fp(n: u8) -> Fingerprint {
        Fingerprint::parse(&format!("sha256:{}", hex::encode([n; 32]))).unwrap()
    }

    fn grant(keys: Vec<Fingerprint>, seq: u64) -> Result<UnsignedGrant> {
        UnsignedGrant::new(
            "openbao-pi5",
            SoftwareKey::generate_ed25519().public_key(),
            keys,
            seq,
            3_600,
            1_000,
            "brian-iphone",
            fp(9),
        )
    }

    #[test]
    fn keys_are_sorted_and_duplicates_refused() {
        let g = grant(vec![fp(3), fp(1)], 1).unwrap();
        assert_eq!(g.keys, vec![fp(1), fp(3)]);
        assert_eq!(g.not_after, 4_600);
        assert!(grant(vec![fp(1), fp(1)], 1).is_err());
        assert!(grant(vec![], 1).is_err());
        assert!(grant(vec![fp(1)], 0).is_err());
    }

    #[test]
    fn signed_grant_round_trips() {
        let attest = SoftwareKey::generate_p256();
        let g = grant(vec![fp(1), fp(2)], 4).unwrap();
        let sig = attest.sign(&g.to_be_signed());
        let signed = g.clone().with_signature(sig);
        let back = ClientGrant::decode(signed.bytes()).unwrap();
        assert_eq!(back.fields, g);
        assert_eq!(back.bytes(), signed.bytes());
        assert!(signed.bytes().len() < 1_024);
        assert!(g
            .to_be_signed()
            .starts_with(b"relay-pkcs11/client-grant/v1\0"));
    }

    #[test]
    fn renewal_keeps_client_keys_and_window() {
        let g = grant(vec![fp(1)], 4).unwrap();
        let r = g.renewed(50_000, "brian-ipad", fp(8)).unwrap();
        assert_eq!(r.seq, 5);
        assert_eq!((r.issued_at, r.not_after), (50_000, 53_600));
        assert_eq!((&r.keys, &r.client_key), (&g.keys, &g.client_key));
        assert_eq!(r.approved_by, "brian-ipad");
        assert_eq!(r.attest_key_fingerprint, fp(8));
    }

    #[test]
    fn a_revocation_cancels_up_to_its_seq_for_its_client_only() {
        let attest = SoftwareKey::generate_p256();
        let g = grant(vec![fp(1)], 3).unwrap();
        let other = grant(vec![fp(1)], 1).unwrap();
        let sign = |u: UnsignedGrant| {
            let s = attest.sign(&u.to_be_signed());
            u.with_signature(s)
        };
        let client_key = g.client_key.clone();
        let rev = |seq| {
            let u = UnsignedRevocation::new(client_key.clone(), seq, 0, fp(9)).unwrap();
            let s = attest.sign(&u.to_be_signed());
            u.with_signature(s)
        };
        let g = sign(g);
        assert!(rev(3).cancels(&g));
        assert!(rev(7).cancels(&g));
        assert!(!rev(2).cancels(&g));
        assert!(!rev(9).cancels(&sign(other)));
        let r = rev(3);
        assert_eq!(ClientRevocation::decode(r.bytes()).unwrap(), r);
        assert!(UnsignedRevocation::new(g.fields.client_key.clone(), 0, 0, fp(9)).is_err());
    }
}
