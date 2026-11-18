//! UniFFI interface to the approver engine (`relay-approver`) for the native apps.
//!
//! The app implements two traits and calls one object:
//!
//! - [`DeviceKey`]: a P-256 key that signs bytes Rust hands it. The app supplies two, both in
//!   the Secure Enclave: the device key (biometric per signature; signs responses, denials and
//!   the auth-key binding) and the relay-auth key (no biometric; signs relay calls only).
//! - [`CardChannel`]: APDUs to the YubiKey (CoreNFC, TKSmartCard), with a session around each
//!   group of commands.
//! - [`Approver`]: enrollment, polling, approval, denial, pairing. Every check, every signed
//!   message and all PIV logic stay in Rust; the PIN arrives as bytes for one approval and the
//!   plaintext result never crosses this boundary.
//!
//! Every method may block on the network or the card: call them off the main thread.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use relay_approver::relay::RelayClient;
use relay_approver::{
    ApproverError, Checked, Engine, EngineConfig, PairedClient, PairingView, PendingRequest,
    Rejection,
};
use relay_core::piv::{self, PivError};
use relay_core::signing::DeviceSigner;
use relay_core::{
    verify_manifest, Algorithm, Fingerprint, HardwarePolicy, Manifest, ManifestSigner, PublicKey,
};
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------- errors ----------

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum RelayError {
    #[error("not enrolled")]
    NotEnrolled,
    #[error("the YubiKey holds no attest key from the manifest: {detail}")]
    NoAttestKey { detail: String },
    #[error("wrong PIN, {retries} tries left; no further attempt until you retry")]
    PinRejected { retries: u8 },
    #[error("PIN blocked")]
    PinBlocked,
    #[error("YubiKey: {message}")]
    Card { message: String },
    #[error("device key: {message}")]
    Signer { message: String },
    #[error("{message}")]
    Invalid { message: String },
    #[error("relay: {message}")]
    Relay { message: String },
    #[error("no such pending item")]
    Unknown,
}

impl From<ApproverError> for RelayError {
    fn from(e: ApproverError) -> Self {
        match e {
            ApproverError::NotEnrolled => RelayError::NotEnrolled,
            ApproverError::NoAttestKey(detail) => RelayError::NoAttestKey { detail },
            ApproverError::PinRejected { retries } => RelayError::PinRejected { retries },
            ApproverError::PinBlocked => RelayError::PinBlocked,
            ApproverError::Card(e) => RelayError::Card {
                message: e.to_string(),
            },
            ApproverError::Signer(m) => RelayError::Signer { message: m },
            ApproverError::Invalid(m) => RelayError::Invalid { message: m },
            ApproverError::Relay(m) => RelayError::Relay { message: m },
        }
    }
}

fn invalid(e: impl std::fmt::Display) -> RelayError {
    RelayError::Invalid {
        message: e.to_string(),
    }
}

/// A failure inside the app's own trait implementations.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum PlatformError {
    /// The platform refused (biometric cancelled, key invalidated, NFC session ended).
    #[error("{message}")]
    Failed { message: String },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for PlatformError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        PlatformError::Failed { message: e.reason }
    }
}

// ---------- foreign traits ----------

/// A P-256 key held by the platform. `sign` returns the raw 64-byte `r || s` ECDSA signature
/// over SHA-256 of `message` (CryptoKit's `rawRepresentation`).
#[uniffi::export(with_foreign)]
pub trait DeviceKey: Send + Sync {
    /// DER SubjectPublicKeyInfo.
    fn public_key(&self) -> Vec<u8>;
    fn sign(&self, message: Vec<u8>) -> Result<Vec<u8>, PlatformError>;
}

/// APDUs to the YubiKey. `begin_session` / `end_session` bracket each group of commands that
/// belongs together; the card must be held exclusively in between and left with no PIN
/// verified after `end_session` (an NFC tap does this by powering down).
#[uniffi::export(with_foreign)]
pub trait CardChannel: Send + Sync {
    fn begin_session(&self) -> Result<(), PlatformError>;
    fn transmit(&self, apdu: Vec<u8>) -> Result<Vec<u8>, PlatformError>;
    fn end_session(&self);
}

struct Signer {
    inner: Arc<dyn DeviceKey>,
    public_key: PublicKey,
}

impl Signer {
    fn new(inner: Arc<dyn DeviceKey>) -> Result<Arc<Self>, RelayError> {
        let public_key = PublicKey::from_spki(&inner.public_key()).map_err(invalid)?;
        if public_key.algorithm() != Algorithm::P256 {
            return Err(invalid("device keys are P-256"));
        }
        Ok(Arc::new(Signer { inner, public_key }))
    }
}

impl DeviceSigner for Signer {
    fn public_key(&self) -> PublicKey {
        self.public_key.clone()
    }
    fn sign_message(&self, msg: &[u8]) -> Result<[u8; 64], String> {
        let sig = self.inner.sign(msg.to_vec()).map_err(|e| e.to_string())?;
        sig.as_slice()
            .try_into()
            .map_err(|_| format!("signature is {} bytes, not 64", sig.len()))
    }
}

struct Card(Arc<dyn CardChannel>);

impl piv::CardTransport for Card {
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, PivError> {
        self.0
            .transmit(apdu.to_vec())
            .map_err(|e| PivError::Transport(e.to_string()))
    }
    fn session(&mut self, f: &mut dyn FnMut(&mut dyn piv::CardTransport)) -> Result<(), PivError> {
        self.0
            .begin_session()
            .map_err(|e| PivError::Transport(e.to_string()))?;
        f(self);
        self.0.end_session();
        Ok(())
    }
}

// ---------- records ----------

#[derive(Debug, Clone, uniffi::Record)]
pub struct ApproverConfig {
    pub relay_url: String,
    /// PEM trust anchors for the relay (its private CA).
    pub relay_ca_pem: Option<String>,
    /// Usually `<relay_url>/v1/manifest`.
    pub manifest_url: String,
    /// The manifest signer's OpenPGP public key, armored.
    pub manifest_signer: String,
    pub device_id: String,
    pub attestation_window_secs: u64,
    pub skew_secs: u64,
    /// Testing only: PEM roots that replace Yubico's attestation root.
    pub attestation_roots_pem: Option<String>,
}

/// Everything the app persists between launches (Application Support, file protection
/// complete). Nothing secret: no PIN, no results, no private keys.
#[derive(Debug, Clone, Default, uniffi::Record)]
pub struct SavedState {
    /// The last verified manifest and its signature: the rollback floor.
    pub manifest: Option<Vec<u8>>,
    pub manifest_signature: Option<Vec<u8>>,
    pub attestation: Option<Vec<u8>>,
    /// The device key's signature binding the relay-auth key (wire-format §8.4).
    pub auth_binding: Option<Vec<u8>>,
    pub clients: Vec<SavedClient>,
    /// Which slot holds each manifest key on the YubiKey (spec: approver "Key map").
    pub keys: Vec<SavedKey>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct SavedKey {
    pub fingerprint: String,
    pub slot: u8,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct SavedClient {
    pub client_id: String,
    /// DER SubjectPublicKeyInfo of the client identity key.
    pub public_key: Vec<u8>,
    /// Manifest key fingerprints the client may use.
    pub keys: Vec<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct KeyInfo {
    pub fingerprint: String,
    pub label: String,
    pub role: String,
    pub algorithm: String,
    pub token: String,
    /// The PIV slot on this YubiKey, when discovered.
    pub slot: Option<u8>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct AttestationStatus {
    pub not_before: u64,
    pub not_after: u64,
    pub renew_at: u64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct Status {
    pub device_id: String,
    pub manifest_version: u64,
    pub manifest_valid_until: u64,
    pub attestation: Option<AttestationStatus>,
    pub keys: Vec<KeyInfo>,
    pub clients: Vec<SavedClient>,
    pub pin_failed: bool,
}

/// The approval screen for one request. Everything here comes from the core's checks; the
/// `claimed_*` fields are the requester's own words.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RequestView {
    pub request_id: String,
    pub client_id: String,
    pub key_label: String,
    pub key_role: String,
    pub token: String,
    pub operation: String,
    pub mechanism: String,
    pub seconds_left: u64,
    pub input_len: u64,
    pub input_sha256: String,
    pub input_preview_hex: String,
    pub input_truncated: bool,
    pub claimed_host: String,
    pub claimed_purpose: String,
    pub claimed_consumer: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct PairingInfo {
    pub client_id: String,
    pub host: String,
    pub fingerprint: String,
    /// Derived here from the client's key; compare it with the client's log.
    pub code: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct Inbox {
    pub requests: Vec<RequestView>,
    pub pairings: Vec<PairingInfo>,
    /// Requests that failed checks, waiting for `answer_rejections` (or to expire).
    pub rejected: u32,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ApprovalOutcome {
    pub approved: bool,
    /// Why the card part failed; the client then gets a signed error.
    pub card_error: Option<String>,
    pub renewed: bool,
    pub renewal_error: Option<String>,
}

fn key_info(k: &relay_core::ManifestKey, slot: Option<u8>) -> KeyInfo {
    KeyInfo {
        fingerprint: k.fingerprint.as_str().to_string(),
        label: k.label.clone(),
        role: k.role.as_str().to_string(),
        algorithm: k.algorithm.as_str().to_string(),
        token: k.token.clone(),
        slot,
    }
}

fn request_view(p: &PendingRequest) -> RequestView {
    let v = &p.view;
    RequestView {
        request_id: hex::encode(p.req_id()),
        client_id: v.client_id.clone(),
        key_label: v.key_label.clone(),
        key_role: v.key_role.to_string(),
        token: v.token.clone(),
        operation: v.op.to_string(),
        mechanism: v.mechanism.to_string(),
        seconds_left: v.seconds_left,
        input_len: v.input_len as u64,
        input_sha256: v.input_sha256.clone(),
        input_preview_hex: v.input_preview_hex.clone(),
        input_truncated: v.input_truncated,
        claimed_host: v.claims.host.clone(),
        claimed_purpose: v.claims.purpose.clone(),
        claimed_consumer: v.claims.consumer.clone(),
    }
}

/// The manifest signer's OpenPGP fingerprint (uppercase hex), for the setup screen to show
/// before the person confirms it.
#[uniffi::export]
pub fn manifest_signer_fingerprint(armored: String) -> Result<String, RelayError> {
    Ok(ManifestSigner::from_bytes(armored.as_bytes())
        .map_err(invalid)?
        .fingerprint())
}

// ---------- the approver ----------

#[derive(Default)]
struct Inflight {
    requests: HashMap<String, PendingRequest>,
    rejections: HashMap<String, Rejection>,
    pairings: HashMap<String, PairingView>,
    /// Request ids already handled, so a re-listed request is not shown twice.
    seen: std::collections::HashSet<String>,
}

#[derive(uniffi::Object)]
pub struct Approver {
    cfg: ApproverConfig,
    engine: Engine,
    relay: RelayClient,
    signer: ManifestSigner,
    policy: HardwarePolicy,
    auth_key: PublicKey,
    manifest_sig: Mutex<Vec<u8>>,
    auth_binding: Mutex<Option<Vec<u8>>>,
    inflight: Mutex<Inflight>,
}

#[uniffi::export]
impl Approver {
    /// Fetch and verify the manifest (against the saved copy for rollback), then restore the
    /// saved state. Blocks on the network.
    #[uniffi::constructor]
    pub fn new(
        config: ApproverConfig,
        device_key: Arc<dyn DeviceKey>,
        auth_key: Arc<dyn DeviceKey>,
        saved: SavedState,
    ) -> Result<Arc<Self>, RelayError> {
        let device = Signer::new(device_key)?;
        let auth = Signer::new(auth_key)?;
        let auth_pub = auth.public_key.clone();
        let signer =
            ManifestSigner::from_bytes(config.manifest_signer.as_bytes()).map_err(invalid)?;
        let policy = hardware_policy(&config)?;
        let relay = RelayClient::new(
            &config.relay_url,
            config.relay_ca_pem.as_deref().map(str::as_bytes),
            auth,
        )?;
        let t = now();
        // The saved copy is a rollback floor while it is still valid.
        let cached = match (&saved.manifest, &saved.manifest_signature) {
            (Some(m), Some(s)) => {
                verify_manifest(m, s, &signer, &policy, None, t, config.skew_secs).ok()
            }
            _ => None,
        };
        let (manifest, sig) =
            fetch_manifest(&relay, &config, &signer, &policy, cached.as_ref(), t)?;
        let mut clients = Vec::new();
        for c in &saved.clients {
            clients.push(PairedClient {
                client_id: c.client_id.clone(),
                public_key: PublicKey::from_spki(&c.public_key).map_err(invalid)?,
                keys: c
                    .keys
                    .iter()
                    .map(|k| Fingerprint::parse(k).map_err(invalid))
                    .collect::<Result<_, _>>()?,
            });
        }
        let engine = Engine::new(
            EngineConfig {
                device_id: config.device_id.clone(),
                attestation_window_secs: config.attestation_window_secs,
                skew_secs: config.skew_secs,
                renew_attestation: true,
            },
            manifest,
            device,
            clients,
        );
        let mut key_map = Vec::new();
        for k in &saved.keys {
            key_map.push((
                Fingerprint::parse(&k.fingerprint).map_err(invalid)?,
                relay_core::piv::Slot::new(k.slot).map_err(invalid)?,
            ));
        }
        engine.restore_key_map(&key_map);
        if let Some(a) = &saved.attestation {
            // An attestation that no longer verifies (expired, attest key removed) is dropped;
            // the status then shows the device as not enrolled.
            let _ = engine.load_attestation(a, t);
        }
        Ok(Arc::new(Approver {
            cfg: config,
            engine,
            relay,
            signer,
            policy,
            auth_key: auth_pub,
            manifest_sig: Mutex::new(sig),
            auth_binding: Mutex::new(saved.auth_binding),
            inflight: Mutex::new(Inflight::default()),
        }))
    }

    /// What to persist now (call after enrollment, pairing, approval and refresh).
    pub fn saved_state(&self) -> SavedState {
        SavedState {
            manifest: Some(self.engine.manifest().bytes().to_vec()),
            manifest_signature: Some(self.manifest_sig.lock().expect("lock").clone()),
            attestation: self.engine.attestation(),
            auth_binding: self.auth_binding.lock().expect("lock").clone(),
            clients: self
                .engine
                .clients()
                .into_iter()
                .map(|c| SavedClient {
                    client_id: c.client_id,
                    public_key: c.public_key.spki().to_vec(),
                    keys: c.keys.iter().map(|k| k.as_str().to_string()).collect(),
                })
                .collect(),
            keys: self
                .engine
                .key_map()
                .into_iter()
                .map(|(fp, s)| SavedKey {
                    fingerprint: fp.as_str().to_string(),
                    slot: s.id(),
                })
                .collect(),
        }
    }

    pub fn status(&self) -> Status {
        let m = self.engine.manifest();
        Status {
            device_id: self.cfg.device_id.clone(),
            manifest_version: m.version,
            manifest_valid_until: m.valid_until,
            attestation: self.engine.attestation_info().map(|i| AttestationStatus {
                not_before: i.not_before,
                not_after: i.not_after,
                renew_at: i.renew_at,
            }),
            keys: self
                .engine
                .operable_keys()
                .iter()
                .map(|k| key_info(k, None))
                .collect(),
            clients: self.saved_state().clients,
            pin_failed: self.engine.pin_failed(),
        }
    }

    /// Fetch the manifest again (verified against the current one).
    pub fn refresh_manifest(&self) -> Result<u64, RelayError> {
        let current = self.engine.manifest();
        let (m, sig) = fetch_manifest(
            &self.relay,
            &self.cfg,
            &self.signer,
            &self.policy,
            Some(&current),
            now(),
        )?;
        let v = m.version;
        self.engine.set_manifest(m);
        *self.manifest_sig.lock().expect("lock") = sig;
        Ok(v)
    }

    /// Read the YubiKey's certificates (no PIN) and list the manifest keys it holds.
    pub fn discover(&self, card: Arc<dyn CardChannel>) -> Result<Vec<KeyInfo>, RelayError> {
        let found = self.engine.discover(&mut Card(card))?;
        Ok(found
            .iter()
            .map(|(s, k)| key_info(k, Some(s.id())))
            .collect())
    }

    /// What the last `discover` read, slot by slot: fingerprints and whether each is in the
    /// manifest, plus any read errors. Public data only.
    pub fn last_discovery(&self) -> String {
        self.engine.last_discovery()
    }

    /// Enrollment, after `discover` (the first tap, no PIN): have the attest key sign this
    /// device's statement (PIN; over NFC the tap is the touch), bind the relay-auth key
    /// (device-key signature) and register. Also renews an existing enrollment. Reads the card
    /// first only when no discovery has found the attest key yet.
    pub fn enroll(
        &self,
        card: Arc<dyn CardChannel>,
        pin: Vec<u8>,
    ) -> Result<AttestationStatus, RelayError> {
        let pin = Zeroizing::new(pin);
        let mut card = Card(card);
        if self.engine.attest_key().is_none() {
            self.engine.discover(&mut card)?;
        }
        let t = now();
        self.engine
            .attest(&mut card, &pin, t, t + self.cfg.attestation_window_secs)?;
        self.register()?;
        let i = self
            .engine
            .attestation_info()
            .ok_or(RelayError::NotEnrolled)?;
        Ok(AttestationStatus {
            not_before: i.not_before,
            not_after: i.not_after,
            renew_at: i.renew_at,
        })
    }

    /// Register (or update) this device with the relay: keys, attestation, auth key.
    pub fn register(&self) -> Result<(), RelayError> {
        let binding = {
            let mut b = self.auth_binding.lock().expect("lock");
            if b.is_none() {
                *b = Some(self.engine.bind_auth_key(&self.auth_key)?.signature);
            }
            relay_approver::AuthBinding {
                auth_key: self.auth_key.clone(),
                signature: b.clone().expect("set above"),
            }
        };
        let body = self
            .engine
            .registration(serde_json::Value::Null, Some(&binding))?;
        Ok(self.relay.register(&body)?)
    }

    /// Fetch pending requests and pairings (waiting up to `wait_secs`) and check each request.
    /// Signs nothing.
    pub fn poll(&self, wait_secs: u64) -> Result<Inbox, RelayError> {
        let items = self.relay.pending(&self.cfg.device_id, wait_secs.min(30))?;
        let t = now();
        let mut inflight = self.inflight.lock().expect("lock");
        for bytes in items.requests {
            let Ok(req) = relay_core::request::SignedRequest::decode(&bytes) else {
                continue;
            };
            let id = hex::encode(req.fields.req_id);
            if !inflight.seen.insert(id.clone()) {
                continue;
            }
            match self.engine.check_request(&bytes, t)? {
                Checked::Show(p) => {
                    inflight.requests.insert(id, *p);
                }
                Checked::Rejected(r) => {
                    inflight.rejections.insert(id, *r);
                }
            }
        }
        inflight.pairings.clear();
        for p in &items.pairings {
            if let Ok(v) = self.engine.pairing_view(p) {
                inflight.pairings.insert(v.client_id.clone(), v);
            }
        }
        // Drop requests that expired while waiting.
        inflight
            .requests
            .retain(|_, p| p.request.fields.expires_at > t);
        let mut requests: Vec<RequestView> = inflight
            .requests
            .values()
            .map(|p| {
                let mut v = request_view(p);
                v.seconds_left = p.request.fields.expires_at.saturating_sub(t);
                v
            })
            .collect();
        requests.sort_by_key(|r| r.seconds_left);
        let mut pairings: Vec<PairingInfo> = inflight
            .pairings
            .values()
            .map(|v| PairingInfo {
                client_id: v.client_id.clone(),
                host: v.host.clone(),
                fingerprint: v.public_key.fingerprint().as_str().to_string(),
                code: v.code.clone(),
            })
            .collect();
        pairings.sort_by(|a, b| a.client_id.cmp(&b.client_id));
        Ok(Inbox {
            requests,
            pairings,
            rejected: inflight.rejections.len() as u32,
        })
    }

    /// The person approved `request_id` and typed `pin`: one card session (PIN, operation, and
    /// the attestation renewal when due), then the sealed, signed response is posted.
    pub fn approve(
        &self,
        request_id: String,
        card: Arc<dyn CardChannel>,
        pin: Vec<u8>,
    ) -> Result<ApprovalOutcome, RelayError> {
        let pin = Zeroizing::new(pin);
        let p = self.take_request(&request_id)?;
        let a = self.engine.approve(&p, &mut Card(card), &pin, now())?;
        self.relay.post_response(a.req_id, &a.response)?;
        let renewed = a.renewed_attestation.is_some();
        if renewed {
            self.register()?;
        }
        Ok(ApprovalOutcome {
            approved: a.approved,
            card_error: a.card_error.map(|e| e.to_string()),
            renewed,
            renewal_error: a.renewal_error,
        })
    }

    /// The person denied `request_id`.
    pub fn deny(&self, request_id: String) -> Result<(), RelayError> {
        let p = self.take_request(&request_id)?;
        let r = self.engine.deny(&p, now())?;
        Ok(self.relay.post_response(p.req_id(), &r)?)
    }

    /// Sign and post denials for requests that failed their checks (device-key signatures).
    /// Expired ones are dropped. Returns how many were answered.
    pub fn answer_rejections(&self) -> Result<u32, RelayError> {
        let pending: Vec<Rejection> = {
            let mut i = self.inflight.lock().expect("lock");
            i.rejections.drain().map(|(_, r)| r).collect()
        };
        let mut n = 0;
        let t = now();
        for r in pending {
            let resp = self.engine.sign_rejection(&r, t)?;
            if self.relay.post_response(r.req_id, &resp).is_ok() {
                n += 1;
            }
        }
        Ok(n)
    }

    /// Approve a pending client for `keys` (manifest key fingerprints) after the person compared
    /// its code. The client is remembered for its requests.
    pub fn approve_pairing(&self, client_id: String, keys: Vec<String>) -> Result<(), RelayError> {
        let view = self
            .inflight
            .lock()
            .expect("lock")
            .pairings
            .get(&client_id)
            .cloned()
            .ok_or(RelayError::Unknown)?;
        let keys: Vec<Fingerprint> = keys
            .iter()
            .map(|k| Fingerprint::parse(k).map_err(invalid))
            .collect::<Result<_, _>>()?;
        let (path, body, client) = self.engine.pairing_approval(&view, &keys)?;
        self.relay.approve_pairing(&path, &body)?;
        self.engine.add_client(client);
        self.inflight
            .lock()
            .expect("lock")
            .pairings
            .remove(&client_id);
        Ok(())
    }

    /// Forget a paired client locally (revoke it at the relay with `relayctl relay clients`).
    pub fn remove_client(&self, client_id: String) -> bool {
        self.engine.remove_client(&client_id)
    }

    /// The person chose to try the PIN again after a rejection.
    pub fn clear_pin_failure(&self) {
        self.engine.clear_pin_failure();
    }

    /// The manifest keys clients may be approved for (not attest keys).
    pub fn manifest_keys(&self) -> Vec<KeyInfo> {
        self.engine
            .manifest()
            .keys
            .iter()
            .filter(|k| k.role != relay_core::Role::Attest)
            .map(|k| key_info(k, None))
            .collect()
    }
}

impl Approver {
    fn take_request(&self, id: &str) -> Result<PendingRequest, RelayError> {
        self.inflight
            .lock()
            .expect("lock")
            .requests
            .remove(id)
            .ok_or(RelayError::Unknown)
    }
}

fn fetch_manifest(
    relay: &RelayClient,
    cfg: &ApproverConfig,
    signer: &ManifestSigner,
    policy: &HardwarePolicy,
    cached: Option<&Manifest>,
    t: u64,
) -> Result<(Manifest, Vec<u8>), RelayError> {
    Ok(relay.fetch_manifest(&cfg.manifest_url, signer, policy, cached, t, cfg.skew_secs)?)
}

/// The hardware attestation policy from the setup file: Yubico's root unless test roots are
/// given.
fn hardware_policy(cfg: &ApproverConfig) -> Result<HardwarePolicy, RelayError> {
    match &cfg.attestation_roots_pem {
        None => Ok(HardwarePolicy::yubico()),
        Some(pem) => {
            let roots = relay_core::hw_attestation::certificates_from_pem(pem.as_bytes())
                .map_err(invalid)?;
            HardwarePolicy::with_roots(roots).map_err(invalid)
        }
    }
}

// ---------- test card (simulator end-to-end only) ----------

/// A software PIV card from PEM files, for the simulator end-to-end test. Only in builds with
/// the `test-card` feature; the release XCFramework never contains it.
#[cfg(feature = "test-card")]
mod test_card {
    use super::*;
    use relay_core::piv::{CardTransport, Slot};
    use relay_softcard::SoftCard;

    struct SoftChannel(Mutex<SoftCard>);

    impl CardChannel for SoftChannel {
        fn begin_session(&self) -> Result<(), PlatformError> {
            Ok(())
        }
        fn transmit(&self, apdu: Vec<u8>) -> Result<Vec<u8>, PlatformError> {
            self.0
                .lock()
                .expect("lock")
                .transmit(&apdu)
                .map_err(|e| PlatformError::Failed {
                    message: e.to_string(),
                })
        }
        /// Like an NFC tap ending: the card powers down.
        fn end_session(&self) {
            self.0.lock().expect("lock").reset();
        }
    }

    /// `slots_json`: `{"pin": "123456", "slots": [{"slot": "9d", "key_pem": ..., "cert_pem": ...}]}`.
    #[uniffi::export]
    pub fn test_card(slots_json: String) -> Result<Arc<dyn CardChannel>, RelayError> {
        let v: serde_json::Value = serde_json::from_str(&slots_json).map_err(invalid)?;
        let pin = v["pin"].as_str().ok_or_else(|| invalid("pin"))?;
        let mut card = SoftCard::new(pin.as_bytes());
        for s in v["slots"].as_array().into_iter().flatten() {
            let slot = Slot::parse(s["slot"].as_str().unwrap_or("")).map_err(invalid)?;
            card.load_pem(
                slot,
                s["key_pem"].as_str().unwrap_or(""),
                s["cert_pem"].as_str().unwrap_or(""),
            )
            .map_err(invalid)?;
        }
        Ok(Arc::new(SoftChannel(Mutex::new(card))))
    }
}
