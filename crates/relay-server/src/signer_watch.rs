//! Watching the manifest signer key (wire-format §11.4; spec: Relay, "Watch the manifest
//! signer").
//!
//! The relay re-reads its `manifest_signer` file every minute and asks keys.openpgp.org every
//! `signer_check.interval_secs`. While the key is revoked or expired it serves no client or
//! device. A keyserver that can't be reached changes nothing (fail open). A revocation, once
//! seen, is stored and stays in force until the file holds another key. Every status is
//! relay-core's `signer_status`, so only revocations and self-signatures that verify count.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use relay_core::signer::{self, SignerStatus};
use relay_core::ManifestSigner;

use crate::config::Config;
use crate::db::{self, Db};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// No `manifest_signer` configured: nothing to watch.
    Unconfigured,
    Usable,
    /// Serve nobody; the reason is for logs and error bodies.
    Unusable(String),
}

struct State {
    file: Vec<u8>,
    signer: Option<ManifestSigner>,
    keyserver_copy: Option<Vec<u8>>,
    status: Status,
}

pub struct SignerWatch {
    path: Option<PathBuf>,
    keyserver: String,
    interval: Duration,
    state: Mutex<State>,
}

impl std::fmt::Debug for SignerWatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignerWatch")
            .field("path", &self.path)
            .field("status", &self.status())
            .finish_non_exhaustive()
    }
}

/// What the keyserver said, for logs and tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    Found,
    NotFound,
    Unreachable(String),
    Rejected(String),
    Disabled,
}

/// The HTTP client for keyserver lookups: 10 s timeout, no redirects, rustls with ring.
pub fn http_client() -> Result<reqwest::Client, String> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string())
}

impl SignerWatch {
    pub fn new(cfg: &Config) -> Result<Self, String> {
        let path =
            match (&cfg.manifest_file, &cfg.manifest_signer) {
                (Some(_), None) => return Err(
                    "manifest_file needs manifest_signer: the relay checks the manifest it serves"
                        .into(),
                ),
                (_, p) => p.clone(),
            };
        let mut state = State {
            file: Vec::new(),
            signer: None,
            keyserver_copy: None,
            status: Status::Unconfigured,
        };
        if let Some(p) = &path {
            let bytes = std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?;
            let s =
                ManifestSigner::from_bytes(&bytes).map_err(|e| format!("manifest_signer: {e}"))?;
            state.file = bytes;
            state.signer = Some(s);
            state.status = Status::Usable;
        }
        Ok(SignerWatch {
            path,
            keyserver: cfg.signer_check.keyserver.trim_end_matches('/').to_string(),
            interval: Duration::from_secs(cfg.signer_check.interval_secs.max(60)),
            state: Mutex::new(state),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn interval(&self) -> Duration {
        self.interval
    }

    pub fn status(&self) -> Status {
        self.lock().status.clone()
    }

    /// `Err(reason)` while the signer is revoked or expired.
    pub fn check(&self) -> Result<(), String> {
        match self.status() {
            Status::Unusable(r) => Err(r),
            _ => Ok(()),
        }
    }

    /// The key the relay currently trusts for the manifest and for setup links.
    pub fn signer(&self) -> Option<ManifestSigner> {
        self.lock().signer.clone()
    }

    /// The armored or binary signer key as the file holds it, for `/v1/manifest-signer.asc`.
    pub fn file_bytes(&self) -> Option<Vec<u8>> {
        let s = self.lock();
        s.signer.as_ref().map(|_| s.file.clone())
    }

    /// Re-read the file. A different key there replaces the keyserver copy, which belonged to
    /// the old key.
    pub fn reload_file(&self) {
        let Some(p) = &self.path else { return };
        match std::fs::read(p) {
            Ok(bytes) => {
                let mut s = self.lock();
                if bytes == s.file {
                    return;
                }
                match ManifestSigner::from_bytes(&bytes) {
                    Ok(k) => {
                        if s.signer.as_ref().map(|o| o.fingerprint()) != Some(k.fingerprint()) {
                            s.keyserver_copy = None;
                        }
                        tracing::info!(fingerprint = %k.fingerprint(), "manifest signer key loaded");
                        s.file = bytes;
                        s.signer = Some(k);
                    }
                    Err(e) => {
                        tracing::error!(path = %p.display(), error = %e, "manifest signer unreadable; keeping the previous key")
                    }
                }
            }
            Err(e) => {
                tracing::error!(path = %p.display(), error = %e, "manifest signer unreadable; keeping the previous key")
            }
        }
    }

    /// Fetch the key from the keyserver and keep it as a second copy if it is the same key.
    pub async fn fetch_keyserver(&self, client: &reqwest::Client) -> Lookup {
        if self.keyserver.is_empty() {
            return Lookup::Disabled;
        }
        let Some(fpr) = self.signer().map(|s| s.fingerprint()) else {
            return Lookup::Disabled;
        };
        let url = format!("{}/vks/v1/by-fingerprint/{fpr}", self.keyserver);
        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => return Lookup::Unreachable(e.to_string()),
        };
        match resp.status().as_u16() {
            200 => {}
            404 => return Lookup::NotFound,
            s => return Lookup::Unreachable(format!("HTTP {s}")),
        }
        let bytes = match resp.bytes().await {
            Ok(b) if b.len() <= 1 << 20 => b.to_vec(),
            Ok(_) => return Lookup::Rejected("key too large".into()),
            Err(e) => return Lookup::Unreachable(e.to_string()),
        };
        match signer::parse_key(&bytes) {
            Ok(k) if signer::fingerprint(&k) == fpr => {
                self.lock().keyserver_copy = Some(bytes);
                Lookup::Found
            }
            Ok(k) => Lookup::Rejected(format!("returned another key, {}", signer::fingerprint(&k))),
            Err(e) => Lookup::Rejected(e.to_string()),
        }
    }

    /// Recompute the status from every copy and the stored revocations. Returns the new status
    /// when it changed.
    pub async fn recompute(&self, db: &Db, now: u64) -> Option<Status> {
        let (file, keyserver) = {
            let s = self.lock();
            s.signer.as_ref()?;
            (s.file.clone(), s.keyserver_copy.clone())
        };
        let mut copies = Vec::new();
        match signer::parse_key(&file) {
            Ok(k) => copies.push(k),
            Err(e) => tracing::error!(error = %e, "manifest signer file unparseable"),
        }
        if let Some(k) = keyserver.as_deref().and_then(|b| signer::parse_key(b).ok()) {
            copies.push(k);
        }
        let fpr = copies.first().map(signer::fingerprint).unwrap_or_default();
        let mut status = match signer::signer_status(&copies, now) {
            Ok(s) => s,
            Err(e) => SignerStatus::Revoked {
                at: now,
                reason: format!("unusable key: {e}"),
            },
        };
        match db::signer_revocation(db, &fpr).await {
            Ok(Some((at, reason))) => status = SignerStatus::Revoked { at, reason },
            Ok(None) => {
                if let SignerStatus::Revoked { at, reason } = &status {
                    if let Err(e) = db::record_signer_revocation(db, &fpr, *at, reason, now).await {
                        tracing::error!(error = %e, "could not store the signer revocation");
                    }
                }
            }
            Err(e) => tracing::error!(error = %e, "could not read stored signer revocations"),
        }
        let next = if status.is_usable() {
            Status::Usable
        } else {
            Status::Unusable(format!("manifest signer {fpr} {}", status.describe()))
        };
        let mut s = self.lock();
        if s.status == next {
            return None;
        }
        match &next {
            Status::Unusable(r) => {
                tracing::error!(reason = %r, "manifest signer unusable: serving no clients or devices")
            }
            Status::Usable => tracing::info!(fingerprint = %fpr, "manifest signer usable"),
            Status::Unconfigured => {}
        }
        s.status = next.clone();
        Some(next)
    }
}
