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

pub mod relay;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use relay_core::attestation::{AttestationStatement, UnsignedAttestation};
use relay_core::content::{approval_view, ApprovalView};
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
    #[error("the card holds no manifest attest key")]
    NoAttestKey,
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

/// A client approved at pairing, and the manifest keys it may use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairedClient {
    pub client_id: String,
    pub public_key: PublicKey,
    pub keys: Vec<Fingerprint>,
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

/// A request that passed every check, waiting for the person's decision.
#[derive(Debug, Clone)]
pub struct PendingRequest {
    pub request: SignedRequest,
    /// What the approval screen shows (computed by the core from the request itself).
    pub view: ApprovalView,
    slot: Slot,
    alg: Algorithm,
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
    clients: Mutex<HashMap<String, PairedClient>>,
    /// Manifest key fingerprint -> slot and algorithm on the card (spec: "Key map").
    key_map: Mutex<HashMap<Fingerprint, (Slot, Algorithm)>>,
    attestation: Mutex<Option<AttestationStatement>>,
    replay: Mutex<ReplayCache>,
    /// Set after a rejected PIN: no card operation until the person retries explicitly.
    pin_failed: AtomicBool,
}

impl Engine {
    pub fn new(
        cfg: EngineConfig,
        manifest: Manifest,
        signer: Arc<dyn DeviceSigner>,
        clients: Vec<PairedClient>,
    ) -> Self {
        Engine {
            cfg,
            manifest: Mutex::new(manifest),
            signer,
            clients: Mutex::new(
                clients
                    .into_iter()
                    .map(|c| (c.client_id.clone(), c))
                    .collect(),
            ),
            key_map: Mutex::new(HashMap::new()),
            attestation: Mutex::new(None),
            replay: Mutex::new(ReplayCache::new(REPLAY_TTL_SECS)),
            pin_failed: AtomicBool::new(false),
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

    pub fn clients(&self) -> Vec<PairedClient> {
        let mut v: Vec<_> = self
            .clients
            .lock()
            .expect("lock")
            .values()
            .cloned()
            .collect();
        v.sort_by(|a, b| a.client_id.cmp(&b.client_id));
        v
    }

    pub fn add_client(&self, c: PairedClient) {
        self.clients
            .lock()
            .expect("lock")
            .insert(c.client_id.clone(), c);
    }

    pub fn remove_client(&self, client_id: &str) -> bool {
        self.clients
            .lock()
            .expect("lock")
            .remove(client_id)
            .is_some()
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
        let found = piv::in_session(card, |c| {
            piv::select(c)?;
            Ok(key_slots()
                .filter_map(|s| {
                    let pk = piv::read_public_key(c, s).ok()?;
                    manifest.key(pk.fingerprint()).map(|k| (s, k.clone()))
                })
                .collect::<Vec<_>>())
        })?;
        *self.key_map.lock().expect("lock") = found
            .iter()
            .map(|(s, k)| (k.fingerprint.clone(), (*s, k.algorithm)))
            .collect();
        Ok(found)
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

    /// No attestation yet, or past 75% of its window.
    pub fn renewal_due(&self, now: u64) -> bool {
        self.attestation_info().is_none_or(|i| now >= i.renew_at)
    }

    /// Restore a stored attestation: it must verify against the manifest now and vouch for this
    /// device's key.
    pub fn load_attestation(&self, bytes: &[u8], now: u64) -> Result<AttestationInfo> {
        let manifest = self.manifest();
        let v = verify_attestation(bytes, &manifest, now, self.cfg.skew_secs).map_err(invalid)?;
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
        let (slot, fp) = self.attest_key().ok_or(ApproverError::NoAttestKey)?;
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

    /// The body of `POST /v1/devices`: device key, attestation, the keys this device operates,
    /// the push registration (`{"kind": "none"}` when there is none), and the relay-auth key
    /// binding when the device uses one (the call must then be signed by that key).
    pub fn registration(
        &self,
        push: serde_json::Value,
        auth: Option<&AuthBinding>,
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
        let Some(client) = self
            .clients
            .lock()
            .expect("lock")
            .get(&req.fields.client_id)
            .cloned()
        else {
            return deny(
                Reason::Policy,
                format!("unpaired client {}", req.fields.client_id),
            );
        };
        let key_map = self.key_map.lock().expect("lock").clone();
        let operable: Vec<Fingerprint> = key_map.keys().cloned().collect();
        let policy = ApproverPolicy {
            client_id: &client.client_id,
            client_key: &client.public_key,
            approved_keys: &client.keys,
            operable_keys: &operable,
        };
        let manifest = self.manifest();
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
                let reason = if e == Error::RequestExpired {
                    Reason::Expired
                } else {
                    Reason::Policy
                };
                return deny(reason, e.kind().to_string());
            }
        };
        let (slot, alg) = key_map[&v.key.fingerprint];
        Ok(Checked::Show(Box::new(PendingRequest {
            view: approval_view(&v, now),
            request: v.request,
            slot,
            alg,
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
        let ran = piv::in_session(card, |c| {
            piv::select(c)?;
            if let Err(e) = piv::verify_pin(c, pin) {
                self.note_pin(&e);
                return Err(e);
            }
            let result = piv::perform(c, p.slot, p.alg, &req.fields.mechanism, &req.fields.input)?;
            let renewed = renewal.map(|(slot, st)| piv::sign_attestation(c, slot, st));
            Ok((result, renewed))
        });
        match ran {
            Ok((result, renewed)) => {
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

    /// The call that approves a pairing for `keys` (manifest keys other than attest keys):
    /// `(path, body)` for `POST`. After the relay accepts it, [`add_client`](Self::add_client).
    pub fn pairing_approval(
        &self,
        v: &PairingView,
        keys: &[Fingerprint],
    ) -> Result<(String, serde_json::Value, PairedClient)> {
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
        let fp = v.public_key.fingerprint().as_str().to_string();
        let keys_s: Vec<&str> = keys.iter().map(|k| k.as_str()).collect();
        Ok((
            format!("/v1/clients/{}/approval", v.client_id),
            json!({"fingerprint": fp, "keys": keys_s}),
            PairedClient {
                client_id: v.client_id.clone(),
                public_key: v.public_key.clone(),
                keys: keys.to_vec(),
            },
        ))
    }
}
