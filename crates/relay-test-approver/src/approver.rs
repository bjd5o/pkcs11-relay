//! The headless approver: the same checks the apps will run, with an auto-approve policy.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use futures_util::StreamExt;
use relay_core::attestation::{AttestationStatement, UnsignedAttestation};
use relay_core::piv::{self, CardTransport, PivError, Slot};
use relay_core::request::{ApproverPolicy, ReplayCache, SignedRequest};
use relay_core::response::{Reason, UnsignedResponse};
use relay_core::signing::SoftwareKey;
use relay_core::{
    verify_request, Algorithm, Error, Fingerprint, Manifest, ManifestSigner, PublicKey, Role,
};
use serde::Deserialize;
use serde_json::json;
use zeroize::Zeroizing;

use crate::relay::{load_manifest, now, Relay};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub relay_url: String,
    /// PEM trust anchors for the relay's TLS certificate.
    pub relay_ca_file: Option<PathBuf>,
    pub device_id: String,
    /// Holds the device key and the current attestation.
    pub data_dir: PathBuf,
    pub manifest_url: String,
    pub manifest_signer: PathBuf,
    /// Softcard directory (`slot-XX.key.pem`, `slot-XX.cert.pem`); ignored with `--pcsc`.
    pub softcard_dir: Option<PathBuf>,
    /// With `--pcsc`: the YubiKey serial to use. It must equal `RELAY_TEST_YUBIKEY_SERIAL`.
    pub pcsc_serial: Option<u32>,
    /// The PIV PIN, read at startup. Leave it out and pass `--pin-stdin` to keep the PIN off
    /// disk.
    pub pin_file: Option<PathBuf>,
    pub attest_slot: String,
    #[serde(default = "default_window")]
    pub attestation_window_secs: u64,
    #[serde(default = "default_skew")]
    pub skew_secs: u64,
    #[serde(default)]
    pub trusted_clients: Vec<TrustedClient>,
    #[serde(default)]
    pub push: serde_json::Value,
}

fn default_window() -> u64 {
    30 * 86_400
}
fn default_skew() -> u64 {
    60
}

/// A paired client: in the apps this comes from pairing; here from config.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedClient {
    pub client_id: String,
    /// Base64 DER SPKI of the client identity key.
    pub public_key: String,
    /// Keys the client may use.
    pub keys: Vec<String>,
    /// Approve this client's pending pairing when its key matches (the test stand-in for a
    /// person comparing the code).
    #[serde(default)]
    pub approve_pairing: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Behavior {
    pub deny: bool,
    pub delay: Duration,
    pub expired_attestation: bool,
    pub long_poll: bool,
}

struct Client {
    key: PublicKey,
    keys: Vec<Fingerprint>,
}

/// Prefix of startup errors that must not be retried (a rejected PIN).
pub const FATAL: &str = "fatal: ";

/// Everything a request needs; shared by the tasks handling requests.
pub struct Approver {
    cfg: Config,
    behavior: Behavior,
    relay: Relay,
    device_key: Arc<SoftwareKey>,
    attestation: Mutex<AttestationStatement>,
    manifest: Manifest,
    card: Mutex<Box<dyn CardTransport + Send>>,
    /// Hardware key fingerprint -> slot and algorithm (spec: approver "Key map").
    key_map: HashMap<Fingerprint, (Slot, Algorithm)>,
    clients: HashMap<String, Client>,
    pin: Zeroizing<Vec<u8>>,
    /// Set after one wrong PIN: never try again automatically (CLAUDE.md hardware safety).
    pin_failed: AtomicBool,
    replay: Mutex<ReplayCache>,
    handled: Mutex<HashSet<[u8; 16]>>,
    approved_pairings: Mutex<HashSet<String>>,
}

fn load_or_create_device_key(dir: &Path) -> Result<SoftwareKey, String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let path = dir.join("device-key.pem");
    if let Ok(pem) = std::fs::read_to_string(&path) {
        return SoftwareKey::from_pkcs8_pem(&pem).map_err(|e| e.to_string());
    }
    // Software P-256 device key: the test stand-in for the Secure Enclave or a TPM.
    let k = SoftwareKey::generate_p256();
    std::fs::write(
        &path,
        k.to_pkcs8_pem().map_err(|e| e.to_string())?.as_bytes(),
    )
    .map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(k)
}

/// Read every PIV slot's public key and keep those the manifest lists.
fn discover_keys(
    card: &mut dyn CardTransport,
    manifest: &Manifest,
) -> HashMap<Fingerprint, (Slot, Algorithm)> {
    let slots = [0x9a, 0x9c, 0x9d, 0x9e].into_iter().chain(0x82..=0x95);
    let mut map = HashMap::new();
    for s in slots {
        let slot = Slot::new(s).expect("valid slot");
        if let Ok(pk) = piv::read_public_key(card, slot) {
            if let Some(k) = manifest.key(pk.fingerprint()) {
                map.insert(k.fingerprint.clone(), (slot, k.algorithm));
            }
        }
    }
    map
}

impl Approver {
    pub async fn start(
        cfg: Config,
        behavior: Behavior,
        card: Box<dyn CardTransport + Send>,
    ) -> Result<Arc<Self>, String> {
        let path = cfg
            .pin_file
            .clone()
            .ok_or("pin_file is not set (use --pin-stdin)")?;
        let pin = Zeroizing::new(
            std::fs::read_to_string(path)
                .map_err(|e| e.to_string())?
                .trim()
                .as_bytes()
                .to_vec(),
        );
        Self::start_with_pin(cfg, behavior, card, pin).await
    }

    /// `start` with a PIN the caller already holds (read from stdin, never written to disk).
    pub async fn start_with_pin(
        cfg: Config,
        behavior: Behavior,
        mut card: Box<dyn CardTransport + Send>,
        pin: Zeroizing<Vec<u8>>,
    ) -> Result<Arc<Self>, String> {
        let signer = ManifestSigner::from_bytes(
            &std::fs::read(&cfg.manifest_signer).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let ca = match &cfg.relay_ca_file {
            Some(p) => Some(std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?),
            None => None,
        };
        let manifest = load_manifest(
            &cfg.manifest_url,
            &signer,
            cfg.skew_secs,
            (&cfg.relay_url, ca.as_deref()),
        )
        .await?;
        let device_key = Arc::new(load_or_create_device_key(&cfg.data_dir)?);
        let key_map = piv::in_session(card.as_mut(), |c| {
            piv::select(c)?;
            Ok(discover_keys(c, &manifest))
        })
        .map_err(|e| e.to_string())?;
        let attest_slot = Slot::parse(&cfg.attest_slot).map_err(|e| e.to_string())?;
        let attest_fp = key_map
            .iter()
            .find(|(fp, (s, _))| {
                *s == attest_slot && manifest.key(fp).is_some_and(|k| k.role == Role::Attest)
            })
            .map(|(fp, _)| fp.clone())
            .ok_or("no manifest attest key in the attest slot")?;
        let mut clients = HashMap::new();
        for c in &cfg.trusted_clients {
            let spki = base64::engine::general_purpose::STANDARD
                .decode(&c.public_key)
                .map_err(|e| e.to_string())?;
            let key = PublicKey::from_spki(&spki).map_err(|e| e.to_string())?;
            let keys = c
                .keys
                .iter()
                .map(|k| Fingerprint::parse(k).map_err(|e| e.to_string()))
                .collect::<Result<_, _>>()?;
            clients.insert(c.client_id.clone(), Client { key, keys });
        }
        let relay = Relay::new(&cfg.relay_url, device_key.clone(), ca.as_deref())?;
        let attestation = Self::attest(
            &cfg,
            &behavior,
            card.as_mut(),
            &pin,
            &device_key,
            attest_slot,
            attest_fp,
            &manifest,
        )?;
        let a = Arc::new(Approver {
            cfg,
            behavior,
            relay,
            device_key,
            attestation: Mutex::new(attestation),
            manifest,
            card: Mutex::new(card),
            key_map,
            clients,
            pin,
            pin_failed: AtomicBool::new(false),
            replay: Mutex::new(ReplayCache::new(86_400)),
            handled: Mutex::new(HashSet::new()),
            approved_pairings: Mutex::new(HashSet::new()),
        });
        a.register().await?;
        Ok(a)
    }

    /// Reuse the stored attestation, or have the card's attest key sign a new one when there is
    /// none, it is past 75% of its window, or `--expired-attestation` wants a stale one.
    #[allow(clippy::too_many_arguments)]
    fn attest(
        cfg: &Config,
        b: &Behavior,
        card: &mut dyn CardTransport,
        pin: &[u8],
        device_key: &SoftwareKey,
        slot: Slot,
        attest_fp: Fingerprint,
        manifest: &Manifest,
    ) -> Result<AttestationStatement, String> {
        let path = cfg.data_dir.join("attestation.cbor");
        let t = now();
        if !b.expired_attestation {
            if let Ok(bytes) = std::fs::read(&path) {
                if let Ok(v) = relay_core::verify_attestation(&bytes, manifest, t, cfg.skew_secs) {
                    let renew_at = v.not_before + (v.not_after - v.not_before) * 3 / 4;
                    if v.device_key == device_key.public_key() && t < renew_at {
                        return AttestationStatement::decode(&bytes).map_err(|e| e.to_string());
                    }
                }
            }
        }
        let (nb, na) = if b.expired_attestation {
            (t - 2 * 86_400, t - 86_400)
        } else {
            (t, t + cfg.attestation_window_secs)
        };
        let st =
            UnsignedAttestation::new(&cfg.device_id, device_key.public_key(), nb, na, attest_fp)
                .map_err(|e| e.to_string())?;
        // A wrong PIN here is fatal: startup is not retried (CLAUDE.md hardware safety).
        // PIN and signature in one card session, which clears the PIN state when it ends.
        let st = piv::in_session(card, |c| {
            piv::select(c)?;
            if let Err(e) = piv::verify_pin(c, pin) {
                return Ok(Err(format!("{FATAL}PIN for attestation: {e}")));
            }
            Ok(piv::sign_attestation(c, slot, st).map_err(|e| e.to_string()))
        })
        .map_err(|e| e.to_string())??;
        if !b.expired_attestation {
            relay_core::verify_attestation(st.bytes(), manifest, t, cfg.skew_secs)
                .map_err(|e| format!("own attestation: {e}"))?;
        }
        std::fs::write(&path, st.bytes()).map_err(|e| e.to_string())?;
        tracing::info!(not_before = nb, not_after = na, "new attestation");
        Ok(st)
    }

    async fn register(&self) -> Result<(), String> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let keys: Vec<serde_json::Value> = self
            .key_map
            .keys()
            .filter_map(|fp| self.manifest.key(fp))
            .filter(|k| k.role != Role::Attest)
            .map(|k| json!({"public_key": b64.encode(k.public_key.spki()), "token": k.token}))
            .collect();
        let push = if self.cfg.push.is_null() {
            json!({"kind": "none"})
        } else {
            self.cfg.push.clone()
        };
        let body = json!({
            "device_id": self.cfg.device_id,
            "device_key": b64.encode(self.device_key.public_key().spki()),
            "attestation": b64.encode(self.attestation.lock().expect("lock").bytes()),
            "keys": keys,
            "push": push,
        });
        let r = self.relay.post_json("/v1/devices", &body).await?;
        if !r.status.is_success() {
            return Err(format!(
                "device registration failed: {} {}",
                r.status,
                String::from_utf8_lossy(&r.body)
            ));
        }
        tracing::info!(
            device_id = self.cfg.device_id,
            keys = keys.len(),
            "registered with relay"
        );
        Ok(())
    }

    /// Run forever: wake on the WebSocket (or long-poll), fetch, handle.
    pub async fn run(self: Arc<Self>) {
        loop {
            let r = if self.behavior.long_poll {
                self.clone().long_poll_loop().await
            } else {
                self.clone().ws_loop().await
            };
            if let Err(e) = r {
                tracing::warn!(error = e, "relay connection lost; retrying");
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    async fn long_poll_loop(self: Arc<Self>) -> Result<(), String> {
        loop {
            // The relay returns at once while anything is listed, including requests this
            // device is already handling and pairings meant for someone else: back off then.
            if !self.clone().fetch_and_handle(25).await? {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }

    async fn ws_loop(self: Arc<Self>) -> Result<(), String> {
        let path = format!("/v1/devices/{}/ws", self.cfg.device_id);
        let mut ws = self.relay.ws_connect(&path).await?;
        tracing::info!("WebSocket connected");
        self.clone().fetch_and_handle(0).await?;
        while let Some(msg) = ws.next().await {
            match msg.map_err(|e| e.to_string())? {
                tokio_tungstenite::tungstenite::Message::Text(_) => {
                    self.clone().fetch_and_handle(0).await?;
                }
                tokio_tungstenite::tungstenite::Message::Close(_) => break,
                _ => {}
            }
        }
        Err("WebSocket closed".into())
    }

    /// Fetch pending items and start handling new requests. Returns whether anything new
    /// was found.
    async fn fetch_and_handle(self: Arc<Self>, wait: u64) -> Result<bool, String> {
        let r = self
            .relay
            .get(&format!(
                "/v1/devices/{}/pending?wait={wait}",
                self.cfg.device_id
            ))
            .await?;
        if !r.status.is_success() {
            return Err(format!(
                "pending: {} {}",
                r.status,
                String::from_utf8_lossy(&r.body)
            ));
        }
        let v = r.json();
        let mut new_work = false;
        for p in v["pairings"].as_array().into_iter().flatten() {
            self.handle_pairing(p).await;
        }
        let b64 = base64::engine::general_purpose::STANDARD;
        for req in v["requests"].as_array().into_iter().flatten() {
            let Some(bytes) = req.as_str().and_then(|s| b64.decode(s).ok()) else {
                continue;
            };
            let Ok(decoded) = SignedRequest::decode(&bytes) else {
                tracing::warn!("undecodable request from relay; ignored");
                continue;
            };
            if !self
                .handled
                .lock()
                .expect("lock")
                .insert(decoded.fields.req_id)
            {
                continue;
            }
            new_work = true;
            let me = self.clone();
            tokio::spawn(async move { me.handle_request(bytes).await });
        }
        Ok(new_work)
    }

    async fn handle_pairing(&self, p: &serde_json::Value) {
        let (Some(id), Some(fp), Some(code)) = (
            p["client_id"].as_str(),
            p["fingerprint"].as_str(),
            p["code"].as_str(),
        ) else {
            return;
        };
        let Some(tc) = self
            .cfg
            .trusted_clients
            .iter()
            .find(|c| c.client_id == id && c.approve_pairing)
        else {
            return;
        };
        let Some(client) = self.clients.get(id) else {
            return;
        };
        if client.key.fingerprint().as_str() != fp
            || !self
                .approved_pairings
                .lock()
                .expect("lock")
                .insert(fp.to_string())
        {
            return;
        }
        // The core derives the code the person would compare.
        let expected = relay_core::pairing::pairing_code(client.key.spki());
        if expected != code {
            tracing::warn!(client_id = id, "pairing code mismatch; not approving");
            return;
        }
        let r = self
            .relay
            .post_json(
                &format!("/v1/clients/{id}/approval"),
                &json!({"fingerprint": fp, "keys": tc.keys}),
            )
            .await;
        match r {
            Ok(r) if r.status.is_success() => {
                tracing::info!(client_id = id, code, "pairing approved")
            }
            Ok(r) => {
                tracing::warn!(client_id = id, status = %r.status, body = %String::from_utf8_lossy(&r.body), "pairing approval failed")
            }
            Err(e) => tracing::warn!(client_id = id, error = e, "pairing approval failed"),
        }
    }

    async fn handle_request(self: Arc<Self>, bytes: Vec<u8>) {
        if !self.behavior.delay.is_zero() {
            tokio::time::sleep(self.behavior.delay).await;
        }
        let me = self.clone();
        let out = tokio::task::spawn_blocking(move || me.decide(&bytes)).await;
        let Ok(Some((req_id, resp))) = out else {
            return;
        };
        match self
            .relay
            .post_cbor(
                &format!("/v1/requests/{}/response", hex::encode(req_id)),
                &resp,
            )
            .await
        {
            Ok(r) if r.status.is_success() => {}
            Ok(r) => {
                tracing::warn!(req_id = hex::encode(req_id), status = %r.status, error = r.error_kind(), "response not accepted")
            }
            Err(e) => tracing::warn!(
                req_id = hex::encode(req_id),
                error = e,
                "posting response failed"
            ),
        }
    }

    /// Verify the request, then approve, deny or report an error. Returns the signed response.
    fn decide(&self, bytes: &[u8]) -> Option<([u8; 16], Vec<u8>)> {
        let req = SignedRequest::decode(bytes).ok()?;
        let id = req.fields.req_id;
        let att = self.attestation.lock().expect("lock").clone();
        let t = now();
        let sign = |u: UnsignedResponse| {
            let sig = self.device_key.sign(&u.to_be_signed());
            Some((id, u.with_signature(sig).bytes().to_vec()))
        };
        let Some(client) = self.clients.get(&req.fields.client_id) else {
            tracing::warn!(
                client_id = req.fields.client_id,
                "request from an unpaired client; denied"
            );
            return sign(UnsignedResponse::denied(
                &req,
                Some(Reason::Policy),
                &att,
                t,
            ));
        };
        let operable: Vec<Fingerprint> = self.key_map.keys().cloned().collect();
        let policy = ApproverPolicy {
            client_id: &req.fields.client_id,
            client_key: &client.key,
            approved_keys: &client.keys,
            operable_keys: &operable,
        };
        let verified = {
            let mut replay = self.replay.lock().expect("lock");
            verify_request(
                bytes,
                &policy,
                &self.manifest,
                &mut replay,
                t,
                self.cfg.skew_secs,
            )
        };
        let v = match verified {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    req_id = hex::encode(id),
                    error = e.kind(),
                    "request failed checks; denied"
                );
                let reason = if e == Error::RequestExpired {
                    Reason::Expired
                } else {
                    Reason::Policy
                };
                return sign(UnsignedResponse::denied(&req, Some(reason), &att, t));
            }
        };
        let view = relay_core::content::approval_view(&v, t);
        tracing::info!(
            req_id = hex::encode(id),
            client = view.client_id,
            key = view.key_label,
            op = view.op,
            mechanism = view.mechanism,
            input_sha256 = view.input_sha256,
            purpose = view.claims.purpose,
            "request verified"
        );
        if self.behavior.deny {
            return sign(UnsignedResponse::denied(
                &req,
                Some(Reason::UserDenied),
                &att,
                t,
            ));
        }
        let (slot, alg) = self.key_map[&v.key.fingerprint];
        match self.operate(slot, alg, &req) {
            Ok(result) => match UnsignedResponse::approved(&req, &result, &att, now()) {
                Ok(u) => sign(u),
                Err(e) => {
                    tracing::error!(error = %e, "sealing failed");
                    sign(UnsignedResponse::error(
                        &req,
                        Some(Reason::Internal),
                        &att,
                        now(),
                    ))
                }
            },
            Err(e) => {
                tracing::warn!(req_id = hex::encode(id), error = %e, "card operation failed");
                sign(UnsignedResponse::error(&req, Some(e.reason()), &att, now()))
            }
        }
    }

    /// PIN, then the raw operation through the core's PIV layer. The result never leaves this
    /// function except sealed.
    fn operate(
        &self,
        slot: Slot,
        alg: Algorithm,
        req: &SignedRequest,
    ) -> Result<Zeroizing<Vec<u8>>, PivError> {
        if self.pin_failed.load(Ordering::SeqCst) {
            return Err(PivError::WrongPin { retries: 0 });
        }
        let mut card = self.card.lock().expect("lock");
        // SELECT, VERIFY and the operation in one card session; the PIN state is cleared after.
        piv::in_session(card.as_mut(), |c| {
            piv::select(c)?;
            if let Err(e) = piv::verify_pin(c, &self.pin) {
                if matches!(e, PivError::WrongPin { .. } | PivError::PinBlocked) {
                    self.pin_failed.store(true, Ordering::SeqCst);
                    tracing::error!("PIN rejected; no further PIN attempts will be made");
                }
                return Err(e);
            }
            piv::perform(c, slot, alg, &req.fields.mechanism, &req.fields.input)
        })
    }
}
