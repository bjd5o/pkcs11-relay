//! The device's store of client grants and revocations (docs/client-grants.md).
//!
//! Every grant and revocation is verified by `relay-core` against the current manifest before
//! it is kept, and grants are verified again on every use, so a grant whose attest key left the
//! manifest stops working at once. The store adds what is local to this device: which grant is
//! the newest for each client key (sequence numbers never go back), which revocations it has
//! seen (kept for good), and which clients the person has accepted on this device.

use std::collections::{HashMap, HashSet};

use relay_core::grant::{ClientGrant, ClientRevocation};
use relay_core::{verify_client_grant, verify_client_revocation, Error, Fingerprint, Manifest};

/// What to persist: every grant's bytes with whether its client was accepted here, and every
/// revocation's bytes.
pub type Exported = (Vec<(Vec<u8>, bool)>, Vec<Vec<u8>>);

/// What the store did with an offered grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ingested {
    /// Kept: new, or newer than the one held.
    Stored,
    /// The same bytes, or an older sequence number: nothing changed.
    Unchanged,
}

/// Why a grant was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GrantRefused {
    #[error("{0}")]
    Invalid(String),
    #[error("a revocation this device holds cancels it")]
    Revoked,
    #[error("a different grant with the same sequence number is already held")]
    Conflict,
}

/// One client as the store sees it.
#[derive(Debug, Clone)]
pub struct Entry {
    pub grant: ClientGrant,
    pub accepted: bool,
}

#[derive(Debug, Default)]
pub struct GrantStore {
    /// Latest grant per client identity key.
    grants: HashMap<Fingerprint, ClientGrant>,
    revocations: Vec<ClientRevocation>,
    accepted: HashSet<Fingerprint>,
}

impl GrantStore {
    /// Offer a grant from the relay or the card. It must verify against `manifest` (a lapsed
    /// grant is kept: it still says who the client is), not be cancelled by a held revocation,
    /// and not go back in sequence.
    pub fn ingest(
        &mut self,
        bytes: &[u8],
        manifest: &Manifest,
        now: u64,
        skew: u64,
    ) -> Result<Ingested, GrantRefused> {
        let v = verify_client_grant(bytes, manifest, now, skew).map_err(|e| match e {
            Error::ClientRevoked => GrantRefused::Revoked,
            e => GrantRefused::Invalid(e.to_string()),
        })?;
        let g = v.grant;
        if self.revocations.iter().any(|r| r.cancels(&g)) {
            return Err(GrantRefused::Revoked);
        }
        let fp = g.client_fingerprint().clone();
        if let Some(held) = self.grants.get(&fp) {
            if held.bytes() == g.bytes() || g.fields.seq < held.fields.seq {
                return Ok(Ingested::Unchanged);
            }
            if g.fields.seq == held.fields.seq {
                return Err(GrantRefused::Conflict);
            }
        }
        self.grants.insert(fp, g);
        Ok(Ingested::Stored)
    }

    /// Offer a revocation. A verified one is kept for good; it drops every grant it cancels and
    /// the client's acceptance. Returns whether it was new.
    pub fn revoke(&mut self, bytes: &[u8], manifest: &Manifest) -> Result<bool, Error> {
        let r = verify_client_revocation(bytes, manifest)?;
        if self.revocations.iter().any(|h| h.bytes() == r.bytes()) {
            return Ok(false);
        }
        let fp = r.client_fingerprint().clone();
        if self.grants.get(&fp).is_some_and(|g| r.cancels(g)) {
            self.grants.remove(&fp);
        }
        self.accepted.remove(&fp);
        self.revocations.push(r);
        Ok(true)
    }

    /// The newest grant held for a client id (a client id maps to one key; if two keys ever
    /// carried the same id, the newer grant wins).
    pub fn by_client_id(&self, client_id: &str) -> Option<Entry> {
        self.grants
            .values()
            .filter(|g| g.fields.client_id == client_id)
            .max_by_key(|g| g.fields.issued_at)
            .map(|g| self.entry(g))
    }

    pub fn by_key(&self, fp: &Fingerprint) -> Option<Entry> {
        self.grants.get(fp).map(|g| self.entry(g))
    }

    fn entry(&self, g: &ClientGrant) -> Entry {
        Entry {
            grant: g.clone(),
            accepted: self.accepted.contains(g.client_fingerprint()),
        }
    }

    /// The person accepted this client on this device.
    pub fn accept(&mut self, fp: &Fingerprint) {
        self.accepted.insert(fp.clone());
    }

    pub fn all(&self) -> Vec<Entry> {
        let mut v: Vec<Entry> = self.grants.values().map(|g| self.entry(g)).collect();
        v.sort_by(|a, b| a.grant.fields.client_id.cmp(&b.grant.fields.client_id));
        v
    }

    pub fn revocations(&self) -> &[ClientRevocation] {
        &self.revocations
    }

    /// What to persist: every grant's bytes with its acceptance, and every revocation's bytes.
    pub fn export(&self) -> Exported {
        (
            self.all()
                .into_iter()
                .map(|e| (e.grant.bytes().to_vec(), e.accepted))
                .collect(),
            self.revocations
                .iter()
                .map(|r| r.bytes().to_vec())
                .collect(),
        )
    }

    /// Restore what [`export`](Self::export) saved. Revocations first, so they cancel grants;
    /// anything that no longer verifies against `manifest` is dropped.
    pub fn restore(
        &mut self,
        grants: &[(Vec<u8>, bool)],
        revocations: &[Vec<u8>],
        manifest: &Manifest,
        now: u64,
        skew: u64,
    ) {
        for r in revocations {
            let _ = self.revoke(r, manifest);
        }
        for (g, accepted) in grants {
            if self.ingest(g, manifest, now, skew).is_ok() && *accepted {
                if let Ok(d) = ClientGrant::decode(g) {
                    self.accept(d.client_fingerprint());
                }
            }
        }
    }
}
