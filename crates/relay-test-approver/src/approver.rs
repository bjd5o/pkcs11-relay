//! The headless approver: a thin async driver around `relay-approver`'s engine (the same code
//! the apps run), with an auto-approve policy instead of a person.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use futures_util::StreamExt;
use relay_approver::{ApproverError, Checked, Engine, EngineConfig, PairedClient};
use relay_core::piv::{CardTransport, Slot};
use relay_core::request::SignedRequest;
use relay_core::signing::{DeviceSigner, SoftwareKey};
use relay_core::{Fingerprint, ManifestSigner, PublicKey};
use serde::Deserialize;
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
    #[serde(default)]
    pub hardware_attestation: relay_core::hw_attestation::PolicyConfig,
}

fn default_window() -> u64 {
    7 * 86_400
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

/// Prefix of startup errors that must not be retried (a rejected PIN).
pub const FATAL: &str = "fatal: ";

/// The engine plus what the headless driver needs around it.
pub struct Approver {
    cfg: Config,
    behavior: Behavior,
    relay: Relay,
    engine: Engine,
    card: Mutex<Box<dyn CardTransport + Send>>,
    pin: Zeroizing<Vec<u8>>,
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

fn fatal_if_pin(e: ApproverError) -> String {
    match e {
        ApproverError::PinRejected { .. } | ApproverError::PinBlocked => {
            format!("{FATAL}PIN for attestation: {e}")
        }
        e => e.to_string(),
    }
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
            &cfg.hardware_attestation.policy()?,
            cfg.skew_secs,
            (&cfg.relay_url, ca.as_deref()),
        )
        .await?;
        let device_key = Arc::new(load_or_create_device_key(&cfg.data_dir)?);
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut clients = Vec::new();
        for c in &cfg.trusted_clients {
            let spki = b64.decode(&c.public_key).map_err(|e| e.to_string())?;
            clients.push(PairedClient {
                client_id: c.client_id.clone(),
                public_key: PublicKey::from_spki(&spki).map_err(|e| e.to_string())?,
                keys: c
                    .keys
                    .iter()
                    .map(|k| Fingerprint::parse(k).map_err(|e| e.to_string()))
                    .collect::<Result<_, _>>()?,
            });
        }
        let engine = Engine::new(
            EngineConfig {
                device_id: cfg.device_id.clone(),
                attestation_window_secs: cfg.attestation_window_secs,
                skew_secs: cfg.skew_secs,
                // The stale fixture must stay stale.
                renew_attestation: !behavior.expired_attestation,
            },
            manifest,
            device_key.clone() as Arc<dyn DeviceSigner>,
            clients,
        );
        engine.discover(card.as_mut()).map_err(|e| e.to_string())?;
        let attest_slot = Slot::parse(&cfg.attest_slot).map_err(|e| e.to_string())?;
        match engine.attest_key() {
            Some((s, _)) if s == attest_slot => {}
            _ => return Err("no manifest attest key in the attest slot".into()),
        }
        Self::attest(&cfg, &behavior, &engine, card.as_mut(), &pin)?;
        let relay = Relay::new(&cfg.relay_url, device_key, ca.as_deref())?;
        let a = Arc::new(Approver {
            cfg,
            behavior,
            relay,
            engine,
            card: Mutex::new(card),
            pin,
            handled: Mutex::new(HashSet::new()),
            approved_pairings: Mutex::new(HashSet::new()),
        });
        a.register().await?;
        Ok(a)
    }

    /// Reuse the stored attestation unless renewal is due (or `--expired-attestation` wants a
    /// stale one); otherwise the card's attest key signs a new one. A rejected PIN is fatal.
    fn attest(
        cfg: &Config,
        b: &Behavior,
        engine: &Engine,
        card: &mut dyn CardTransport,
        pin: &[u8],
    ) -> Result<(), String> {
        let path = cfg.data_dir.join("attestation.cbor");
        let t = now();
        if !b.expired_attestation {
            if let Ok(bytes) = std::fs::read(&path) {
                if engine.load_attestation(&bytes, t).is_ok() && !engine.renewal_due(t) {
                    return Ok(());
                }
            }
        }
        let (nb, na) = if b.expired_attestation {
            (t - 2 * 86_400, t - 86_400)
        } else {
            (t, t + cfg.attestation_window_secs)
        };
        let bytes = engine.attest(card, pin, nb, na).map_err(fatal_if_pin)?;
        std::fs::write(&path, &bytes).map_err(|e| e.to_string())?;
        tracing::info!(not_before = nb, not_after = na, "new attestation");
        Ok(())
    }

    async fn register(&self) -> Result<(), String> {
        let body = self
            .engine
            .registration(self.cfg.push.clone(), None)
            .map_err(|e| e.to_string())?;
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
            keys = body["keys"].as_array().map_or(0, Vec::len),
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
        let view = match self.engine.pairing_view(p) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "pending pairing failed checks; not approving");
                return;
            }
        };
        // The configured client stands in for the person comparing the code.
        let Some(tc) = self
            .cfg
            .trusted_clients
            .iter()
            .find(|c| c.client_id == view.client_id && c.approve_pairing)
        else {
            return;
        };
        let known = self
            .engine
            .clients()
            .into_iter()
            .find(|c| c.client_id == view.client_id);
        if known.is_none_or(|c| c.public_key != view.public_key) {
            return;
        }
        let fp = view.public_key.fingerprint().as_str().to_string();
        if !self.approved_pairings.lock().expect("lock").insert(fp) {
            return;
        }
        let keys: Vec<Fingerprint> = match tc.keys.iter().map(|k| Fingerprint::parse(k)).collect() {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!(error = %e, "bad key in trusted_clients");
                return;
            }
        };
        let (path, body, _client) = match self.engine.pairing_approval(&view, &keys) {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(error = %e, "pairing approval refused");
                return;
            }
        };
        match self.relay.post_json(&path, &body).await {
            Ok(r) if r.status.is_success() => {
                tracing::info!(
                    client_id = view.client_id,
                    code = view.code,
                    "pairing approved"
                )
            }
            Ok(r) => {
                tracing::warn!(client_id = view.client_id, status = %r.status, body = %String::from_utf8_lossy(&r.body), "pairing approval failed")
            }
            Err(e) => tracing::warn!(
                client_id = view.client_id,
                error = e,
                "pairing approval failed"
            ),
        }
    }

    async fn handle_request(self: Arc<Self>, bytes: Vec<u8>) {
        if !self.behavior.delay.is_zero() {
            tokio::time::sleep(self.behavior.delay).await;
        }
        let me = self.clone();
        let out = tokio::task::spawn_blocking(move || me.decide(&bytes)).await;
        let Ok(Some((req_id, resp, renewed))) = out else {
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
        if renewed {
            if let Err(e) = self.register().await {
                tracing::warn!(error = e, "re-registering the renewed attestation failed");
            }
        }
    }

    /// The engine checks the request, then approves (or denies with `--deny`). Returns the
    /// signed response and whether the attestation was renewed.
    fn decide(&self, bytes: &[u8]) -> Option<([u8; 16], Vec<u8>, bool)> {
        let t = now();
        let p = match self.engine.check_request(bytes, t) {
            Ok(Checked::Show(p)) => p,
            Ok(Checked::Rejected(r)) => {
                tracing::warn!(
                    req_id = hex::encode(r.req_id),
                    why = r.why,
                    "request failed checks; denied"
                );
                return match self.engine.sign_rejection(&r, t) {
                    Ok(response) => Some((r.req_id, response, false)),
                    Err(e) => {
                        tracing::error!(error = %e, "signing the denial failed");
                        None
                    }
                };
            }
            Err(e) => {
                tracing::warn!(error = %e, "request not handled");
                return None;
            }
        };
        let v = &p.view;
        tracing::info!(
            req_id = hex::encode(p.req_id()),
            client = v.client_id,
            key = v.key_label,
            op = v.op,
            mechanism = v.mechanism,
            input_sha256 = v.input_sha256,
            purpose = v.claims.purpose,
            "request verified"
        );
        if self.behavior.deny {
            return match self.engine.deny(&p, t) {
                Ok(r) => Some((p.req_id(), r, false)),
                Err(e) => {
                    tracing::error!(error = %e, "signing the denial failed");
                    None
                }
            };
        }
        let mut card = self.card.lock().expect("lock");
        match self.engine.approve(&p, card.as_mut(), &self.pin, now()) {
            Ok(a) => {
                if let Some(e) = &a.card_error {
                    tracing::warn!(req_id = hex::encode(a.req_id), error = %e, "card operation failed");
                    if self.engine.pin_failed() {
                        tracing::error!("PIN rejected; no further PIN attempts will be made");
                    }
                }
                if let Some(e) = &a.renewal_error {
                    tracing::warn!(
                        error = e,
                        "attestation renewal failed; keeping the current one"
                    );
                }
                if let Some(st) = &a.renewed_attestation {
                    let _ = std::fs::write(self.cfg.data_dir.join("attestation.cbor"), st);
                    tracing::info!("attestation renewed during an approval");
                }
                Some((a.req_id, a.response, a.renewed_attestation.is_some()))
            }
            Err(e) => {
                tracing::error!(error = %e, "approval failed before a response could be signed");
                None
            }
        }
    }
}
