//! The approver engine: everything an approver does between the relay and the card, shared by
//! the apps (through `relay-ffi`) and the headless test approver.
//!
//! Every check and every signed message comes from `relay-core`; this crate decides the order:
//! check a request, show it, run the PIN and the card operation in one card session, seal the
//! result, sign the response, and renew the attestation in the same session when it is due
//! (spec: "Approver application"). It does no I/O itself except through [`relay::RelayClient`],
//! a blocking client the apps use; the test approver keeps its own async transport.
//!
//! The platform supplies two things: a [`CardTransport`] (APDUs to the YubiKey) and a
//! [`DeviceSigner`] (the Secure Enclave key). The PIN arrives as bytes for one approval and the
//! plaintext result never leaves [`Engine::approve`] except sealed to the client.
#![forbid(unsafe_code)]

pub mod grants;
pub mod relay;
pub mod setup;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use relay_core::attestation::{AttestationStatement, UnsignedAttestation};
use relay_core::content::{approval_view, ApprovalView};
use relay_core::grant::{ClientGrant, UnsignedGrant, UnsignedRevocation};
use relay_core::piv::{self, CardTransport, PivError, Slot};
use relay_core::request::{ApproverPolicy, ReplayCache, SignedRequest};
use relay_core::response::{Reason, UnsignedResponse};
use relay_core::signing::{sign_checked, DeviceSigner};
use relay_core::{
    verify_attestation, verify_request, Algorithm, Error, Fingerprint, Manifest, ManifestKey,
    PublicKey, Role,
};
use serde_json::json;

/// How long request ids are remembered (spec: replay cache kept 24 h).
pub const REPLAY_TTL_SECS: u64 = 86_400;

/// Every PIV key slot an approver looks at, in order.
pub fn key_slots() -> impl Iterator<Item = Slot> {
    [0x9a, 0x9c, 0x9d, 0x9e]
        .into_iter()
        .chain(0x82..=0x95)
        .map(|s| Slot::new(s).expect("valid slot"))
}

#[derive(Debug, thiserror::Error)]
pub enum ApproverError {
    #[error("not enrolled: this device has no attestation yet")]
    NotEnrolled,
    /// The detail says what the last discovery read, for diagnosis.
    #[error("the card holds no manifest attest key ({0})")]
    NoAttestKey(String),
    #[error("PIN rejected ({retries} tries left); no further attempt is made automatically")]
    PinRejected { retries: u8 },
    #[error("PIN blocked")]
    PinBlocked,
    #[error("card: {0}")]
    Card(PivError),
    #[error("device key: {0}")]
    Signer(String),
    #[error("{0}")]
    Invalid(String),
    #[error("relay: {0}")]
    Relay(String),
}

type Result<T> = std::result::Result<T, ApproverError>;

impl From<PivError> for ApproverError {
    fn from(e: PivError) -> Self {
        match e {
            PivError::WrongPin { retries } => ApproverError::PinRejected { retries },
            PivError::PinBlocked => ApproverError::PinBlocked,
            e => ApproverError::Card(e),
        }
    }
}

fn invalid(e: impl std::fmt::Display) -> ApproverError {
    ApproverError::Invalid(e.to_string())
}

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub device_id: String,
    /// Length of each attestation window; renewal is due after 75% of it.
    pub attestation_window_secs: u64,
    pub skew_secs: u64,
    /// Renew the attestation during an approval once it is due (spec). Off only for test
    /// fixtures that must stay stale.
    pub renew_attestation: bool,
}

/// The current attestation's window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationInfo {
    pub not_before: u64,
    pub not_after: u64,
    pub renew_at: u64,
    pub attest_key: Fingerprint,
}

impl AttestationInfo {
    fn of(st: &AttestationStatement) -> Self {
        let f = &st.fields;
        AttestationInfo {
            not_before: f.not_before,
            not_after: f.not_after,
            renew_at: f.not_before + (f.not_after - f.not_before) * 3 / 4,
            attest_key: f.attest_key_fingerprint.clone(),
        }
    }
}

/// What the approval screen says about the client when this device hasn't accepted it yet, or
/// its grant has lapsed (docs/client-grants.md). Approving accepts the client and, if lapsed,
/// renews its grant in the same card session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientNotice {
    /// The client's first request on this device: approving also accepts the client here.
    pub first_on_device: bool,
    /// When the grant lapsed (`not_after`), if it has: approving renews it.
    pub lapsed_since: Option<u64>,
    pub client_id: String,
    /// The device that signed the grant: display only, the grant doesn't vouch for it.
    pub approved_by: String,
    pub issued_at: u64,
    pub window_secs: u64,
    pub keys: Vec<Fingerprint>,
}

/// A request that passed every check, waiting for the person's decision.
#[derive(Debug, Clone)]
pub struct PendingRequest {
    pub request: SignedRequest,
    /// What the approval screen shows (computed by the core from the request itself).
    pub view: ApprovalView,
    /// Shown with the request when set.
    pub notice: Option<ClientNotice>,
    slot: Slot,
    alg: Algorithm,
    /// The client's grant.
    grant: ClientGrant,
}

impl PendingRequest {
    pub fn req_id(&self) -> [u8; 16] {
        self.request.fields.req_id
    }
}

/// A request that failed a check. Answer it with [`Engine::sign_rejection`] (a device-key
/// signature, so possibly a biometric prompt) when the person is present, or let it expire.
#[derive(Debug, Clone)]
pub struct Rejection {
    pub req_id: [u8; 16],
    request: SignedRequest,
    reason: Reason,
    /// For the local log.
    pub why: String,
}

impl Rejection {
    /// The reason code the signed denial will carry.
    pub fn reason(&self) -> Reason {
        self.reason
    }

    pub fn client_id(&self) -> &str {
        &self.request.fields.client_id
    }

    pub fn expires_at(&self) -> u64 {
        self.request.fields.expires_at
    }
}

/// The outcome of [`Engine::check_request`]. Checking signs nothing.
#[derive(Debug)]
pub enum Checked {
    /// Show it to the person, then call [`Engine::approve`] or [`Engine::deny`].
    Show(Box<PendingRequest>),
    /// It failed a check.
    Rejected(Box<Rejection>),
}

/// The result of [`Engine::approve`]: always a signed response to post.
#[derive(Debug)]
pub struct Approval {
    pub req_id: [u8; 16],
    pub response: Vec<u8>,
    /// True when the operation ran and its sealed result is in the response.
    pub approved: bool,
    /// Why the card part failed, when it did (the response is then a signed error).
    pub card_error: Option<PivError>,
    /// A new attestation signed in the same card session; register it with the relay.
    pub renewed_attestation: Option<Vec<u8>>,
    /// Why a due renewal did not happen (the response carries the old attestation).
    pub renewal_error: Option<String>,
    /// The client's grant renewed in the same card session: post it with
    /// [`Engine::grant_post`] (the relay-auth key may sign that call).
    pub renewed_grant: Option<Vec<u8>>,
    /// Why a due grant renewal did not happen.
    pub grant_renewal_error: Option<String>,
}

/// A grant or revocation to post to the relay: `POST path` with `body`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Post {
    pub path: String,
    pub body: serde_json::Value,
}

/// One client on the Clients screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientStatus {
    pub client_id: String,
    pub client_key: PublicKey,
    pub keys: Vec<Fingerprint>,
    pub grant: GrantSummary,
    pub accepted: bool,
    pub state: ClientState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantSummary {
    pub seq: u64,
    pub window_secs: u64,
    pub issued_at: u64,
    pub not_after: u64,
    pub renew_at: u64,
    pub approved_by: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientState {
    Valid,
    RenewsSoon,
    /// Unused for a whole window: renewed at its next approved request.
    Lapsed,
    /// Its grant no longer verifies (its attest key left the manifest).
    CannotVerify,
    /// In the manifest's `revoked_clients`.
    RevokedInManifest,
}

fn renew_at(g: &ClientGrant) -> u64 {
    g.fields.issued_at + g.fields.window_secs * 3 / 4
}

/// The device key's signature letting a separate key authenticate this device's relay calls
/// (wire-format §8.4). Made once at enrollment and sent with every registration, so routine
/// relay traffic never needs the device key (which may require a biometric per signature).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthBinding {
    pub auth_key: PublicKey,
    pub signature: Vec<u8>,
}

/// A pending pairing, checked: the code is derived here from the client's key, never taken
/// from the relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingView {
    pub client_id: String,
    pub host: String,
    pub public_key: PublicKey,
    pub code: String,
}

pub struct Engine {
    cfg: EngineConfig,
    manifest: Mutex<Manifest>,
    signer: Arc<dyn DeviceSigner>,
    grants: Mutex<grants::GrantStore>,
    /// Manifest key fingerprint -> slot and algorithm on the card (spec: "Key map").
    key_map: Mutex<HashMap<Fingerprint, (Slot, Algorithm)>>,
    attestation: Mutex<Option<AttestationStatement>>,
    replay: Mutex<ReplayCache>,
    /// Set after a rejected PIN: no card operation until the person retries explicitly.
    pin_failed: AtomicBool,
    /// What the last discovery read: slots, fingerprints, errors. Public data only.
    last_discovery: Mutex<String>,
}

impl Engine {
    pub fn new(cfg: EngineConfig, manifest: Manifest, signer: Arc<dyn DeviceSigner>) -> Self {
        Engine {
            cfg,
            manifest: Mutex::new(manifest),
            signer,
            grants: Mutex::new(grants::GrantStore::default()),
            key_map: Mutex::new(HashMap::new()),
            attestation: Mutex::new(None),
            replay: Mutex::new(ReplayCache::new(REPLAY_TTL_SECS)),
            pin_failed: AtomicBool::new(false),
            last_discovery: Mutex::new("no discovery yet".into()),
        }
    }

    pub fn config(&self) -> &EngineConfig {
        &self.cfg
    }

    pub fn device_key(&self) -> PublicKey {
        self.signer.public_key()
    }

    pub fn manifest(&self) -> Manifest {
        self.manifest.lock().expect("lock").clone()
    }

    /// Replace the manifest with a newer one the caller verified against the current copy
    /// (`relay_core::verify_manifest` with this one as `cached`).
    pub fn set_manifest(&self, m: Manifest) {
        *self.manifest.lock().expect("lock") = m;
    }

    /// Whether a rejected PIN has stopped card operations.
    pub fn pin_failed(&self) -> bool {
        self.pin_failed.load(Ordering::SeqCst)
    }

    /// The person chose to try again: allow one more PIN attempt.
    pub fn clear_pin_failure(&self) {
        self.pin_failed.store(false, Ordering::SeqCst);
    }

    fn note_pin(&self, e: &PivError) {
        if matches!(e, PivError::WrongPin { .. } | PivError::PinBlocked) {
            self.pin_failed.store(true, Ordering::SeqCst);
        }
    }

    /// Read every slot's certificate (one card session, no PIN) and keep the keys the manifest
    /// lists. Returns them with their slots.
    pub fn discover(&self, card: &mut dyn CardTransport) -> Result<Vec<(Slot, ManifestKey)>> {
        let manifest = self.manifest();
        let mut report = Vec::new();
        let mut serial = None;
        let found = piv::in_session(card, |c| {
            piv::select(c)?;
            serial = piv::get_serial(c).ok();
            Ok(key_slots()
                .filter_map(|s| match piv::read_public_key(c, s) {
                    Ok(pk) => {
                        let k = manifest.key(pk.fingerprint());
                        report.push(format!(
                            "{:02x}: {} {}",
                            s.id(),
                            &pk.fingerprint().as_str()[..15],
                            k.map_or("not in manifest".to_string(), |k| k.label.clone())
                        ));
                        k.map(|k| (s, k.clone()))
                    }
                    Err(PivError::NotFound) => None,
                    Err(e) => {
                        report.push(format!("{:02x}: {e}", s.id()));
                        None
                    }
                })
                .collect::<Vec<_>>())
        })?;
        // A sanity check, not a boundary: clients enforce the manifest's attestation. An attest
        // key whose chain names another card was not generated on this one.
        for (s, k) in &found {
            if let (Some(a), Some(serial)) = (k.attested, serial) {
                if a.serial != serial {
                    report.push(format!(
                        "{:02x}: {}'s hardware attestation names YubiKey {}, but this card is {serial}",
                        s.id(),
                        k.label,
                        a.serial
                    ));
                }
            }
        }
        *self.last_discovery.lock().expect("lock") = if report.is_empty() {
            "no certificates read in any slot".into()
        } else {
            report.join("; ")
        };
        *self.key_map.lock().expect("lock") = found
            .iter()
            .map(|(s, k)| (k.fingerprint.clone(), (*s, k.algorithm)))
            .collect();
        Ok(found)
    }

    /// What the last discovery read, slot by slot (public data only), for the person to see.
    pub fn last_discovery(&self) -> String {
        self.last_discovery.lock().expect("lock").clone()
    }

    /// The key map as `(fingerprint, slot)` pairs, to persist (spec: approver "Key map").
    pub fn key_map(&self) -> Vec<(Fingerprint, Slot)> {
        let mut v: Vec<_> = self
            .key_map
            .lock()
            .expect("lock")
            .iter()
            .map(|(fp, (s, _))| (fp.clone(), *s))
            .collect();
        v.sort_by_key(|(_, s)| s.id());
        v
    }

    /// Restore a saved key map without the card. Entries the current manifest does not list
    /// are dropped. A stale entry is harmless: the card would sign with whatever key is in the
    /// slot, and clients check every result against the manifest key (response check 5).
    pub fn restore_key_map(&self, entries: &[(Fingerprint, Slot)]) {
        let m = self.manifest();
        *self.key_map.lock().expect("lock") = entries
            .iter()
            .filter_map(|(fp, s)| m.key(fp).map(|k| (fp.clone(), (*s, k.algorithm))))
            .collect();
    }

    /// The keys found by [`discover`](Self::discover) that clients can use (not the attest key).
    pub fn operable_keys(&self) -> Vec<ManifestKey> {
        let m = self.manifest();
        let mut v: Vec<_> = self
            .key_map
            .lock()
            .expect("lock")
            .keys()
            .filter_map(|fp| m.key(fp).cloned())
            .filter(|k| k.role != Role::Attest)
            .collect();
        v.sort_by(|a, b| a.label.cmp(&b.label));
        v
    }

    /// The manifest attest key found on the card, and its slot.
    pub fn attest_key(&self) -> Option<(Slot, Fingerprint)> {
        let m = self.manifest();
        self.key_map
            .lock()
            .expect("lock")
            .iter()
            .find(|(fp, _)| m.key(fp).is_some_and(|k| k.role == Role::Attest))
            .map(|(fp, (s, _))| (*s, fp.clone()))
    }

    pub fn attestation(&self) -> Option<Vec<u8>> {
        self.attestation
            .lock()
            .expect("lock")
            .as_ref()
            .map(|a| a.bytes().to_vec())
    }

    pub fn attestation_info(&self) -> Option<AttestationInfo> {
        self.attestation
            .lock()
            .expect("lock")
            .as_ref()
            .map(AttestationInfo::of)
    }

    /// No attestation yet, past 75% of its window, or a window longer than the manifest now
    /// allows (it lowered `max_attestation_window_secs`): clients reject it until it is renewed.
    pub fn renewal_due(&self, now: u64) -> bool {
        let max = self.manifest().max_attestation_window_secs;
        self.attestation_info()
            .is_none_or(|i| now >= i.renew_at || i.not_after - i.not_before > max)
    }

    /// Restore a stored attestation: an `attest` key in the current manifest must have signed it,
    /// and it must vouch for this device's key. An expired one is kept too (spec: "An expired
    /// device can still fetch requests"): the next approval renews it (`renewal_due`), and
    /// clients reject this device's responses until then. Dropping it would leave the device
    /// unable to answer at all, so it could never renew.
    pub fn load_attestation(&self, bytes: &[u8]) -> Result<AttestationInfo> {
        let mut manifest = self.manifest();
        // A window longer than the manifest now allows is kept, and renewed at the next approval
        // (`renewal_due`); everything else about it must verify.
        manifest.max_attestation_window_secs = u64::MAX;
        let v = relay_core::attestation::verify_attestation_signer(bytes, &manifest)
            .map_err(invalid)?;
        if v.device_key != self.signer.public_key() {
            return Err(invalid("the stored attestation is for another device key"));
        }
        let st = AttestationStatement::decode(bytes).map_err(invalid)?;
        let info = AttestationInfo::of(&st);
        *self.attestation.lock().expect("lock") = Some(st);
        Ok(info)
    }

    fn unsigned_attestation(
        &self,
        not_before: u64,
        not_after: u64,
    ) -> Result<(Slot, UnsignedAttestation)> {
        let (slot, fp) = self.attest_key().ok_or_else(|| {
            ApproverError::NoAttestKey(self.last_discovery.lock().expect("lock").clone())
        })?;
        let max = self.manifest().max_attestation_window_secs;
        if not_after.saturating_sub(not_before) > max {
            return Err(invalid(format!(
                "an attestation window of {} s is longer than the manifest allows ({max} s); choose a shorter one",
                not_after.saturating_sub(not_before)
            )));
        }
        let st = UnsignedAttestation::new(
            &self.cfg.device_id,
            self.signer.public_key(),
            not_before,
            not_after,
            fp,
        )
        .map_err(invalid)?;
        Ok((slot, st))
    }

    /// Check a statement the card just signed (signature and manifest attest key, at a time
    /// inside its window) and make it current.
    fn accept_attestation(&self, st: AttestationStatement) -> Result<Vec<u8>> {
        let manifest = self.manifest();
        verify_attestation(
            st.bytes(),
            &manifest,
            st.fields.not_before,
            self.cfg.skew_secs,
        )
        .map_err(|e| invalid(format!("own attestation: {e}")))?;
        let bytes = st.bytes().to_vec();
        *self.attestation.lock().expect("lock") = Some(st);
        Ok(bytes)
    }

    /// Enrollment: have the card's attest key sign a statement for this device key over
    /// `[not_before, not_after]`. One card session: `SELECT`, one `VERIFY`, the signature.
    /// Call [`discover`](Self::discover) first.
    pub fn attest(
        &self,
        card: &mut dyn CardTransport,
        pin: &[u8],
        not_before: u64,
        not_after: u64,
    ) -> Result<Vec<u8>> {
        if self.pin_failed() {
            return Err(ApproverError::PinRejected { retries: 0 });
        }
        let (slot, st) = self.unsigned_attestation(not_before, not_after)?;
        let signed = piv::in_session(card, |c| {
            piv::select(c)?;
            if let Err(e) = piv::verify_pin(c, pin) {
                self.note_pin(&e);
                return Err(e);
            }
            piv::sign_attestation(c, slot, st)
        })?;
        self.accept_attestation(signed)
    }

    /// Have the device key vouch for `auth_key` as this device's relay-auth key: one device-key
    /// signature, at enrollment. Store the result and pass it to every
    /// [`registration`](Self::registration).
    pub fn bind_auth_key(&self, auth_key: &PublicKey) -> Result<AuthBinding> {
        let msg = relay_core::relay_auth::auth_key_binding(&self.cfg.device_id, auth_key);
        let sig = sign_checked(self.signer.as_ref(), &msg)
            .map_err(|e| ApproverError::Signer(e.to_string()))?;
        Ok(AuthBinding {
            auth_key: auth_key.clone(),
            signature: sig.to_vec(),
        })
    }

    /// Have the device key vouch for `admin_key` as this device's admin-auth key (wire-format
    /// §8.5): one device-key signature, at enrollment. Pass it to every
    /// [`registration`](Self::registration).
    pub fn bind_admin_key(&self, admin_key: &PublicKey) -> Result<AuthBinding> {
        let msg = relay_core::relay_auth::admin_key_binding(&self.cfg.device_id, admin_key);
        let sig = sign_checked(self.signer.as_ref(), &msg)
            .map_err(|e| ApproverError::Signer(e.to_string()))?;
        Ok(AuthBinding {
            auth_key: admin_key.clone(),
            signature: sig.to_vec(),
        })
    }

    /// The body of `POST /v1/devices`: device key, attestation, the keys this device operates,
    /// the push registration (`{"kind": "none"}` when there is none), the relay-auth key binding
    /// when the device uses one (the call must then be signed by that key), and the admin-auth
    /// key binding.
    pub fn registration(
        &self,
        push: serde_json::Value,
        auth: Option<&AuthBinding>,
        setup_link: Option<&str>,
    ) -> Result<serde_json::Value> {
        self.registration_with_admin(push, auth, None, setup_link)
    }

    pub fn registration_with_admin(
        &self,
        push: serde_json::Value,
        auth: Option<&AuthBinding>,
        admin: Option<&AuthBinding>,
        setup_link: Option<&str>,
    ) -> Result<serde_json::Value> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let att = self.attestation().ok_or(ApproverError::NotEnrolled)?;
        let keys: Vec<_> = self
            .operable_keys()
            .iter()
            .map(|k| json!({"public_key": b64.encode(k.public_key.spki()), "token": k.token}))
            .collect();
        let mut body = json!({
            "device_id": self.cfg.device_id,
            "device_key": b64.encode(self.signer.public_key().spki()),
            "attestation": b64.encode(att),
            "keys": keys,
            "push": if push.is_null() { json!({"kind": "none"}) } else { push },
        });
        if let Some(a) = auth {
            body["auth_key"] = b64.encode(a.auth_key.spki()).into();
            body["auth_key_sig"] = b64.encode(&a.signature).into();
        }
        if let Some(a) = admin {
            body["admin_key"] = b64.encode(a.auth_key.spki()).into();
            body["admin_key_sig"] = b64.encode(&a.signature).into();
        }
        // Only a device id the relay doesn't hold needs it; sending it again is harmless.
        if let Some(l) = setup_link {
            body["setup_link"] = l.into();
        }
        Ok(body)
    }

    fn current_attestation(&self) -> Result<AttestationStatement> {
        self.attestation
            .lock()
            .expect("lock")
            .clone()
            .ok_or(ApproverError::NotEnrolled)
    }

    fn sign_response(&self, u: UnsignedResponse) -> Result<Vec<u8>> {
        let sig = sign_checked(self.signer.as_ref(), &u.to_be_signed())
            .map_err(|e| ApproverError::Signer(e.to_string()))?;
        Ok(u.with_signature(sig).bytes().to_vec())
    }

    /// Run every approver check on a request from the relay (spec: "Check every request").
    /// One that passes comes back with its approval view; one that fails as a [`Rejection`].
    /// Nothing is signed here.
    pub fn check_request(&self, bytes: &[u8], now: u64) -> Result<Checked> {
        let req = SignedRequest::decode(bytes).map_err(invalid)?;
        let id = req.fields.req_id;
        let deny = |reason: Reason, why: String| -> Result<Checked> {
            Ok(Checked::Rejected(Box::new(Rejection {
                req_id: id,
                request: req.clone(),
                reason,
                why,
            })))
        };
        let manifest = self.manifest();
        let client_id = req.fields.client_id.clone();
        // The client: its newest grant, verified again now.
        let Some(e) = self.grants.lock().expect("lock").by_client_id(&client_id) else {
            return deny(
                Reason::ClientNotGranted,
                format!("no grant for client {client_id}"),
            );
        };
        let v = match relay_core::verify_client_grant(
            e.grant.bytes(),
            &manifest,
            now,
            self.cfg.skew_secs,
        ) {
            Ok(v) => v,
            Err(Error::ClientRevoked) => {
                return deny(
                    Reason::ClientRevoked,
                    format!("client {client_id} is revoked in the manifest"),
                )
            }
            Err(err) => {
                return deny(
                    Reason::ClientNotGranted,
                    format!("client {client_id}'s grant no longer verifies: {err}"),
                )
            }
        };
        let grant = e.grant;
        let f = &grant.fields;
        let notice = (!e.accepted || v.lapsed).then(|| ClientNotice {
            first_on_device: !e.accepted,
            lapsed_since: v.lapsed.then_some(f.not_after),
            client_id: f.client_id.clone(),
            approved_by: f.approved_by.clone(),
            issued_at: f.issued_at,
            window_secs: f.window_secs,
            keys: f.keys.clone(),
        });
        let key_map = self.key_map.lock().expect("lock").clone();
        let operable: Vec<Fingerprint> = key_map.keys().cloned().collect();
        let policy = ApproverPolicy {
            client_id: &f.client_id,
            client_key: &f.client_key,
            approved_keys: &f.keys,
            operable_keys: &operable,
        };
        let verified = {
            let mut replay = self.replay.lock().expect("lock");
            verify_request(
                bytes,
                &policy,
                &manifest,
                &mut replay,
                now,
                self.cfg.skew_secs,
            )
        };
        let v = match verified {
            Ok(v) => v,
            Err(e) => {
                // The key is outside the grant only if this device operates it; a key it doesn't
                // operate is a routing problem, not the client's.
                let outside_grant = !f.keys.contains(&req.fields.key_fingerprint)
                    && operable.contains(&req.fields.key_fingerprint);
                let reason = match e {
                    Error::RequestExpired => Reason::Expired,
                    Error::KeyNotApproved if outside_grant => Reason::KeyNotGranted,
                    _ => Reason::Policy,
                };
                return deny(reason, e.kind().to_string());
            }
        };
        let (slot, alg) = key_map[&v.key.fingerprint];
        Ok(Checked::Show(Box::new(PendingRequest {
            view: approval_view(&v, now),
            request: v.request,
            notice,
            slot,
            alg,
            grant,
        })))
    }

    /// The signed denial for a request that failed its checks.
    pub fn sign_rejection(&self, r: &Rejection, now: u64) -> Result<Vec<u8>> {
        let att = self.current_attestation()?;
        self.sign_response(UnsignedResponse::denied(
            &r.request,
            Some(r.reason),
            &att,
            now,
        ))
    }

    /// The person denied it.
    pub fn deny(&self, p: &PendingRequest, now: u64) -> Result<Vec<u8>> {
        let att = self.current_attestation()?;
        self.sign_response(UnsignedResponse::denied(
            &p.request,
            Some(Reason::UserDenied),
            &att,
            now,
        ))
    }

    /// The person approved it and typed `pin`. One card session: `SELECT`, one `VERIFY`, the
    /// operation, and the renewal signature when renewal is due; then the result is sealed to
    /// the client's reply key and the response signed. A card failure (wrong PIN, card gone)
    /// becomes a signed error response; after a rejected PIN no card operation runs until
    /// [`clear_pin_failure`](Self::clear_pin_failure).
    pub fn approve(
        &self,
        p: &PendingRequest,
        card: &mut dyn CardTransport,
        pin: &[u8],
        now: u64,
    ) -> Result<Approval> {
        let req = &p.request;
        let mut att = self.current_attestation()?;
        let mut out = Approval {
            req_id: p.req_id(),
            response: Vec::new(),
            approved: false,
            card_error: None,
            renewed_attestation: None,
            renewal_error: None,
            renewed_grant: None,
            grant_renewal_error: None,
        };
        if self.pin_failed() {
            out.card_error = Some(PivError::WrongPin { retries: 0 });
            out.response = self.sign_response(UnsignedResponse::error(
                req,
                Some(Reason::WrongPin),
                &att,
                now,
            ))?;
            return Ok(out);
        }
        let renewal = if self.cfg.renew_attestation && self.renewal_due(now) {
            match self.unsigned_attestation(now, now + self.cfg.attestation_window_secs) {
                Ok(r) => Some(r),
                Err(e) => {
                    out.renewal_error = Some(e.to_string());
                    None
                }
            }
        } else {
            None
        };
        // The client's grant renews at 75% of its window, or after a lapse, in the same session.
        let grant_renewal = if now >= renew_at(&p.grant) {
            match self.renewed_grant(&p.grant, now) {
                Ok(r) => Some(r),
                Err(e) => {
                    out.grant_renewal_error = Some(e.to_string());
                    None
                }
            }
        } else {
            None
        };
        let ran = piv::in_session(card, |c| {
            piv::select(c)?;
            if let Err(e) = piv::verify_pin(c, pin) {
                self.note_pin(&e);
                return Err(e);
            }
            let result = piv::perform(c, p.slot, p.alg, &req.fields.mechanism, &req.fields.input)?;
            let renewed = renewal.map(|(slot, st)| piv::sign_attestation(c, slot, st));
            let grant = grant_renewal
                .clone()
                .map(|(slot, g)| piv::sign_grant(c, slot, g));
            Ok((result, renewed, grant))
        });
        match ran {
            Ok((result, renewed, grant)) => {
                // Approving accepts the client on this device.
                self.grants
                    .lock()
                    .expect("lock")
                    .accept(p.grant.client_fingerprint());
                match grant {
                    Some(Ok(g)) => match self.take_grant(g.bytes(), now) {
                        Ok(()) => out.renewed_grant = Some(g.bytes().to_vec()),
                        Err(e) => out.grant_renewal_error = Some(e.to_string()),
                    },
                    Some(Err(e)) => out.grant_renewal_error = Some(e.to_string()),
                    None => {}
                }
                match renewed {
                    Some(Ok(st)) => match self.accept_attestation(st) {
                        Ok(bytes) => {
                            att = self.current_attestation()?;
                            out.renewed_attestation = Some(bytes);
                        }
                        Err(e) => out.renewal_error = Some(e.to_string()),
                    },
                    Some(Err(e)) => out.renewal_error = Some(e.to_string()),
                    None => {}
                }
                out.response = match UnsignedResponse::approved(req, &result, &att, now) {
                    Ok(u) => {
                        out.approved = true;
                        self.sign_response(u)?
                    }
                    Err(_) => self.sign_response(UnsignedResponse::error(
                        req,
                        Some(Reason::Internal),
                        &att,
                        now,
                    ))?,
                };
            }
            Err(e) => {
                out.response =
                    self.sign_response(UnsignedResponse::error(req, Some(e.reason()), &att, now))?;
                out.card_error = Some(e);
            }
        }
        Ok(out)
    }

    /// Check a pending pairing from the relay's `/pending` list: the fingerprint must be the
    /// client key's, and the code shown is derived here from that key. A relay that sends a code
    /// other than the derived one is refused.
    pub fn pairing_view(&self, p: &serde_json::Value) -> Result<PairingView> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let field = |k: &str| {
            p[k].as_str()
                .ok_or_else(|| invalid(format!("pairing without {k}")))
        };
        let spki = b64.decode(field("public_key")?).map_err(invalid)?;
        let public_key = PublicKey::from_spki(&spki).map_err(invalid)?;
        if public_key.fingerprint().as_str() != field("fingerprint")? {
            return Err(invalid("pairing fingerprint does not match the client key"));
        }
        let code = relay_core::pairing::pairing_code(public_key.spki());
        if code != field("code")? {
            return Err(invalid(
                "the relay's pairing code differs from the one derived from the key",
            ));
        }
        Ok(PairingView {
            client_id: field("client_id")?.to_string(),
            host: p["host"].as_str().unwrap_or("").to_string(),
            public_key,
            code,
        })
    }

    /// Approve a pairing: the card's attest key signs a grant (seq 1) for `keys` with a window
    /// of `window_secs`, in one card session (`SELECT`, one `VERIFY`, the signature). The grant
    /// is kept, the client accepted on this device, and the call to post returned.
    pub fn pairing_approval(
        &self,
        v: &PairingView,
        keys: &[Fingerprint],
        window_secs: u64,
        card: &mut dyn CardTransport,
        pin: &[u8],
        now: u64,
    ) -> Result<Post> {
        let (slot, attest) = self.grant_signer()?;
        let g = UnsignedGrant::new(
            &v.client_id,
            v.public_key.clone(),
            self.check_grant_keys(keys)?,
            1,
            self.check_grant_window(window_secs)?,
            now,
            &self.cfg.device_id,
            attest,
        )
        .map_err(invalid)?;
        let signed = self.on_card(card, pin, |c| piv::sign_grant(c, slot, g))?;
        self.take_grant(signed.bytes(), now)?;
        self.grants
            .lock()
            .expect("lock")
            .accept(signed.client_fingerprint());
        Ok(Post {
            path: format!("/v1/clients/{}/approval", v.client_id),
            body: json!({"grant": b64(signed.bytes())}),
        })
    }

    /// Change a client's keys or window from the Clients screen: a new grant with `seq + 1`.
    /// Post the result with the admin-auth key.
    pub fn change_client(
        &self,
        client_id: &str,
        keys: &[Fingerprint],
        window_secs: u64,
        card: &mut dyn CardTransport,
        pin: &[u8],
        now: u64,
    ) -> Result<Post> {
        let (slot, attest) = self.grant_signer()?;
        let (key, seq) = self.client_key_and_next_seq(client_id)?;
        let g = UnsignedGrant::new(
            client_id,
            key,
            self.check_grant_keys(keys)?,
            seq,
            self.check_grant_window(window_secs)?,
            now,
            &self.cfg.device_id,
            attest,
        )
        .map_err(invalid)?;
        let signed = self.on_card(card, pin, |c| piv::sign_grant(c, slot, g))?;
        self.take_grant(signed.bytes(), now)?;
        self.grants
            .lock()
            .expect("lock")
            .accept(signed.client_fingerprint());
        Ok(self.grant_post(client_id, signed.bytes()))
    }

    /// Renew a client's grant from the Clients screen: same keys and window, `seq + 1`.
    pub fn renew_client(
        &self,
        client_id: &str,
        card: &mut dyn CardTransport,
        pin: &[u8],
        now: u64,
    ) -> Result<Post> {
        let s = self
            .client_list(now)
            .into_iter()
            .find(|c| c.client_id == client_id)
            .ok_or_else(|| invalid(format!("no client {client_id}")))?;
        self.change_client(client_id, &s.keys, s.grant.window_secs, card, pin, now)
    }

    /// Revoke a client from the Clients screen: the attest key signs a revocation of every
    /// grant up to the newest this device holds. It takes effect here at once; post the result
    /// with the admin-auth key.
    pub fn revoke_client(
        &self,
        client_id: &str,
        card: &mut dyn CardTransport,
        pin: &[u8],
        now: u64,
    ) -> Result<Post> {
        let (slot, attest) = self.grant_signer()?;
        let (key, next) = self.client_key_and_next_seq(client_id)?;
        let r = UnsignedRevocation::new(key, next - 1, now, attest).map_err(invalid)?;
        let signed = self.on_card(card, pin, |c| piv::sign_revocation(c, slot, r))?;
        self.grants
            .lock()
            .expect("lock")
            .revoke(signed.bytes(), &self.manifest())
            .map_err(invalid)?;
        Ok(Post {
            path: format!("/v1/clients/{client_id}/revocation"),
            body: json!({"revocation": b64(signed.bytes())}),
        })
    }

    /// The call that stores a changed or renewed grant at the relay.
    pub fn grant_post(&self, client_id: &str, grant: &[u8]) -> Post {
        Post {
            path: format!("/v1/clients/{client_id}/grant"),
            body: json!({"grant": b64(grant)}),
        }
    }

    /// Take in what the relay sent: `grants` and `revocations` from `/pending` or
    /// `GET /v1/clients` (base64 CBOR). Each is verified; ones that fail are skipped and
    /// reported, never trusted.
    pub fn ingest(&self, v: &serde_json::Value, now: u64) -> Vec<String> {
        let mut problems = Vec::new();
        let manifest = self.manifest();
        let list = |k: &str| -> Vec<Vec<u8>> {
            v[k].as_array()
                .into_iter()
                .flatten()
                .filter_map(|x| x.as_str())
                .filter_map(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
                .collect()
        };
        let mut store = self.grants.lock().expect("lock");
        for r in list("revocations") {
            if let Err(e) = store.revoke(&r, &manifest) {
                problems.push(format!("revocation refused: {e}"));
            }
        }
        let mut grants = list("grants");
        for c in v["clients"].as_array().into_iter().flatten() {
            if let Some(g) = c["grant"]
                .as_str()
                .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
            {
                grants.push(g);
            }
        }
        for g in grants {
            if let Err(e) = store.ingest(&g, &manifest, now, self.cfg.skew_secs) {
                problems.push(format!("grant refused: {e}"));
            }
        }
        problems
    }

    /// Every client this device knows, for the Clients screen.
    pub fn client_list(&self, now: u64) -> Vec<ClientStatus> {
        let manifest = self.manifest();
        let store = self.grants.lock().expect("lock");
        let mut out: Vec<ClientStatus> = store
            .all()
            .into_iter()
            .map(|e| {
                let f = &e.grant.fields;
                let state = match relay_core::verify_client_grant(
                    e.grant.bytes(),
                    &manifest,
                    now,
                    self.cfg.skew_secs,
                ) {
                    Err(Error::ClientRevoked) => ClientState::RevokedInManifest,
                    Err(_) => ClientState::CannotVerify,
                    Ok(v) if v.lapsed => ClientState::Lapsed,
                    Ok(_) if now >= renew_at(&e.grant) => ClientState::RenewsSoon,
                    Ok(_) => ClientState::Valid,
                };
                ClientStatus {
                    client_id: f.client_id.clone(),
                    client_key: f.client_key.clone(),
                    keys: f.keys.clone(),
                    grant: GrantSummary {
                        seq: f.seq,
                        window_secs: f.window_secs,
                        issued_at: f.issued_at,
                        not_after: f.not_after,
                        renew_at: renew_at(&e.grant),
                        approved_by: f.approved_by.clone(),
                    },
                    accepted: e.accepted,
                    state,
                }
            })
            .collect();
        out.sort_by(|a, b| a.client_id.cmp(&b.client_id));
        out
    }

    /// What to persist about grants: `(grant bytes, accepted)` and revocation bytes.
    pub fn grant_state(&self) -> grants::Exported {
        self.grants.lock().expect("lock").export()
    }

    /// Restore what [`grant_state`](Self::grant_state) saved, against the current manifest.
    pub fn restore_grants(&self, grants: &[(Vec<u8>, bool)], revocations: &[Vec<u8>], now: u64) {
        let manifest = self.manifest();
        self.grants.lock().expect("lock").restore(
            grants,
            revocations,
            &manifest,
            now,
            self.cfg.skew_secs,
        );
    }

    fn grant_signer(&self) -> Result<(Slot, Fingerprint)> {
        self.attest_key().ok_or_else(|| {
            ApproverError::NoAttestKey(self.last_discovery.lock().expect("lock").clone())
        })
    }

    fn check_grant_keys(&self, keys: &[Fingerprint]) -> Result<Vec<Fingerprint>> {
        let m = self.manifest();
        if keys.is_empty() {
            return Err(invalid("choose at least one key"));
        }
        for k in keys {
            match m.key(k) {
                Some(mk) if mk.role != Role::Attest => {}
                _ => return Err(invalid(format!("{k} is not a usable manifest key"))),
            }
        }
        let mut v = keys.to_vec();
        v.sort();
        v.dedup();
        Ok(v)
    }

    fn check_grant_window(&self, window_secs: u64) -> Result<u64> {
        let max = self.manifest().max_client_grant_window_secs;
        if !(relay_core::manifest::MIN_CLIENT_GRANT_WINDOW..=max).contains(&window_secs) {
            return Err(invalid(format!(
                "a grant window must be {}-{max} s",
                relay_core::manifest::MIN_CLIENT_GRANT_WINDOW
            )));
        }
        Ok(window_secs)
    }

    /// The client's identity key and the next grant sequence number.
    fn client_key_and_next_seq(&self, client_id: &str) -> Result<(PublicKey, u64)> {
        self.grants
            .lock()
            .expect("lock")
            .by_client_id(client_id)
            .map(|e| (e.grant.fields.client_key.clone(), e.grant.fields.seq + 1))
            .ok_or_else(|| invalid(format!("no client {client_id}")))
    }

    /// The client's grant renewed at `now`: same keys and window, `seq + 1`, signed by this
    /// card's attest key.
    fn renewed_grant(&self, g: &ClientGrant, now: u64) -> Result<(Slot, UnsignedGrant)> {
        let (slot, attest) = self.grant_signer()?;
        let r = g
            .fields
            .renewed(now, &self.cfg.device_id, attest)
            .map_err(invalid)?;
        Ok((slot, r))
    }

    /// Keep a grant this device just signed (it must verify like any other).
    fn take_grant(&self, bytes: &[u8], now: u64) -> Result<()> {
        let manifest = self.manifest();
        self.grants
            .lock()
            .expect("lock")
            .ingest(bytes, &manifest, now, self.cfg.skew_secs)
            .map_err(|e| invalid(format!("the signed grant was refused: {e}")))?;
        Ok(())
    }

    /// One card session: `SELECT`, one `VERIFY`, then `f`.
    fn on_card<T>(
        &self,
        card: &mut dyn CardTransport,
        pin: &[u8],
        f: impl FnOnce(&mut dyn CardTransport) -> std::result::Result<T, PivError>,
    ) -> Result<T> {
        if self.pin_failed() {
            return Err(ApproverError::PinRejected { retries: 0 });
        }
        let mut f = Some(f);
        Ok(piv::in_session(card, |c| {
            piv::select(c)?;
            if let Err(e) = piv::verify_pin(c, pin) {
                self.note_pin(&e);
                return Err(e);
            }
            (f.take().expect("called once"))(c)
        })?)
    }
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}
