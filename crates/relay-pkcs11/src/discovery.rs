//! Discovery (spec: Key discovery): the verified manifest decides trust, the relay's list says
//! which manifest keys are reachable. Both are cached on disk, so a restart during an outage
//! still finds its keys.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use relay_core::{
    verify_manifest, Fingerprint, Manifest, ManifestKey, ManifestSigner, PublicKey, Role,
};
use serde::{Deserialize, Serialize};

use crate::client::{fetch, now, RelayClient};
use crate::config::Config;
use crate::log;

#[derive(Serialize, Deserialize)]
struct KeysCache {
    fetched_at: u64,
    fingerprints: Vec<String>,
}

/// One slot per manifest token; its objects are the manifest keys the relay also lists.
#[derive(Debug, Clone)]
pub struct SlotView {
    pub token: String,
    pub keys: Vec<ManifestKey>,
}

pub struct Discovery {
    manifest: Option<Manifest>,
    manifest_checked_at: u64,
    keys: Option<(Vec<Fingerprint>, u64)>,
    pairing_logged: bool,
    /// Stable object handles for the life of the process: (fingerprint, is_public) -> handle.
    handles: HashMap<(Fingerprint, bool), u64>,
}

fn sig_path(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".asc");
    PathBuf::from(s)
}

fn keys_cache_path(cfg: &Config) -> PathBuf {
    cfg.manifest_cache.with_file_name("relay-keys.json")
}

fn write_atomic(path: &Path, data: &[u8]) {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let tmp = path.with_extension("tmp");
    if std::fs::write(&tmp, data)
        .and_then(|_| std::fs::rename(&tmp, path))
        .is_err()
    {
        log::warn(&format!("could not write cache {}", path.display()));
    }
}

impl Discovery {
    /// Load the on-disk caches, re-verifying the cached manifest exactly as a fetched one.
    pub fn load(cfg: &Config, signer: &ManifestSigner) -> Self {
        let t = now();
        let manifest = match (
            std::fs::read(&cfg.manifest_cache),
            std::fs::read(sig_path(&cfg.manifest_cache)),
        ) {
            (Ok(b), Ok(s)) => match verify_manifest(&b, &s, signer, None, t, cfg.skew_secs) {
                Ok(m) => Some(m),
                Err(e) => {
                    log::warn(&format!("cached manifest rejected: {e}"));
                    None
                }
            },
            _ => None,
        };
        let keys = std::fs::read(keys_cache_path(cfg))
            .ok()
            .and_then(|b| serde_json::from_slice::<KeysCache>(&b).ok())
            .map(|c| {
                (
                    c.fingerprints
                        .iter()
                        .filter_map(|f| Fingerprint::parse(f).ok())
                        .collect(),
                    c.fetched_at,
                )
            });
        Discovery {
            manifest,
            manifest_checked_at: 0,
            keys,
            pairing_logged: false,
            handles: HashMap::new(),
        }
    }

    pub fn manifest(&self) -> Option<&Manifest> {
        self.manifest.as_ref()
    }

    /// Refetch the manifest if due. On failure keep a valid cached copy (Failure handling:
    /// "Manifest signature invalid, rolled back or expired").
    fn refresh_manifest(&mut self, cfg: &Config, signer: &ManifestSigner, t: u64) {
        if let Some(m) = &self.manifest {
            if m.check_fresh(t, cfg.skew_secs).is_err() {
                log::warn("cached manifest expired");
                self.manifest = None;
            }
        }
        let due = self.manifest.is_none()
            || t.saturating_sub(self.manifest_checked_at) >= cfg.manifest_refresh_secs;
        if !due {
            return;
        }
        self.manifest_checked_at = t;
        let fetched = fetch(&cfg.manifest_url)
            .and_then(|b| fetch(&format!("{}.asc", cfg.manifest_url)).map(|s| (b, s)));
        match fetched {
            Ok((bytes, sig)) => match verify_manifest(
                &bytes,
                &sig,
                signer,
                self.manifest.as_ref(),
                t,
                cfg.skew_secs,
            ) {
                Ok(m) => {
                    if self.manifest.as_ref().map(|c| c.bytes()) != Some(m.bytes()) {
                        write_atomic(&cfg.manifest_cache, m.bytes());
                        write_atomic(&sig_path(&cfg.manifest_cache), &sig);
                        log::info(&format!("manifest version {} verified", m.version));
                    }
                    self.manifest = Some(m);
                }
                Err(e) => log::warn(&format!("fetched manifest rejected ({}): {e}", e.kind())),
            },
            Err(e) => log::warn(&format!("manifest unreachable: {e}")),
        }
    }

    /// Refetch the relay's key list if the cached one is stale. On failure keep it until it
    /// expires (Failure handling: "Relay unreachable during discovery").
    fn refresh_keys(&mut self, cfg: &Config, relay: &RelayClient, t: u64) {
        let fresh = self
            .keys
            .as_ref()
            .is_some_and(|(_, at)| t.saturating_sub(*at) < 30);
        if fresh {
            return;
        }
        match relay.get("/v1/keys") {
            Ok(r) if r.status == 200 => {
                let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap_or_default();
                let b64 = base64::engine::general_purpose::STANDARD;
                // The provider recomputes each fingerprint from the key the relay sends.
                let fps: Vec<Fingerprint> = v["keys"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|k| b64.decode(k["public_key"].as_str()?).ok())
                    .filter_map(|spki| PublicKey::from_spki(&spki).ok())
                    .map(|pk| pk.fingerprint().clone())
                    .collect();
                let cache = KeysCache {
                    fetched_at: t,
                    fingerprints: fps.iter().map(|f| f.to_string()).collect(),
                };
                write_atomic(
                    &keys_cache_path(cfg),
                    &serde_json::to_vec(&cache).expect("json"),
                );
                self.keys = Some((fps, t));
            }
            Ok(r) if r.status == 403 && r.error_kind() == "UnpairedClient" => {
                self.keys = None;
                self.pair(cfg, relay);
            }
            Ok(r) => log::warn(&format!(
                "relay key list: HTTP {} {}",
                r.status,
                r.error_kind()
            )),
            Err(e) => log::warn(&format!("relay unreachable during discovery: {e}")),
        }
        if let Some((_, at)) = &self.keys {
            if t.saturating_sub(*at) > cfg.keys_cache_secs {
                log::warn("cached relay key list expired");
                self.keys = None;
            }
        }
    }

    /// Client pairing from the provider side: register as pending and log the code.
    fn pair(&mut self, cfg: &Config, relay: &RelayClient) {
        let spki = relay.key().public_key().spki().to_vec();
        let code = relay_core::pairing::pairing_code(&spki);
        let host = host_name(cfg);
        let body = serde_json::json!({
            "client_id": cfg.client_id,
            "public_key": base64::engine::general_purpose::STANDARD.encode(&spki),
            "host": host,
        });
        match relay.post_json("/v1/clients/pending", &body) {
            Ok(r) if r.status == 202 || r.status == 200 => {
                if !self.pairing_logged {
                    log::warn(&format!(
                        "client {} is not paired yet. Pairing code: {code}. Compare it in the approver app and approve; operations fail until then.",
                        cfg.client_id
                    ));
                    self.pairing_logged = true;
                }
            }
            Ok(r) => log::warn(&format!(
                "pairing registration refused: HTTP {} {}",
                r.status,
                r.error_kind()
            )),
            Err(e) => log::warn(&format!("pairing registration failed: {e}")),
        }
    }

    /// Refresh as needed and return the slots.
    pub fn slots(
        &mut self,
        cfg: &Config,
        signer: &ManifestSigner,
        relay: &RelayClient,
    ) -> Vec<SlotView> {
        let t = now();
        self.refresh_manifest(cfg, signer, t);
        if self.manifest.is_none() {
            return Vec::new();
        }
        self.refresh_keys(cfg, relay, t);
        let reachable: &[Fingerprint] =
            self.keys.as_ref().map(|(k, _)| k.as_slice()).unwrap_or(&[]);
        let Some(m) = self.manifest.as_ref() else {
            return Vec::new();
        };
        m.tokens()
            .into_iter()
            .map(|token| SlotView {
                keys: m
                    .keys
                    .iter()
                    .filter(|k| {
                        k.token == token
                            && k.role != Role::Attest
                            && reachable.contains(&k.fingerprint)
                    })
                    .cloned()
                    .collect(),
                token,
            })
            .collect()
    }

    /// The handle for a key's private (`false`) or public (`true`) object.
    pub fn handle(&mut self, fp: &Fingerprint, public: bool) -> u64 {
        let next = self.handles.len() as u64 + 1;
        *self.handles.entry((fp.clone(), public)).or_insert(next)
    }
}

pub fn host_name(cfg: &Config) -> String {
    if let Some(h) = &cfg.host {
        return h.clone();
    }
    for p in ["/proc/sys/kernel/hostname", "/etc/hostname"] {
        if let Ok(h) = std::fs::read_to_string(p) {
            let h = h.trim();
            if !h.is_empty() {
                return h.chars().take(255).collect();
            }
        }
    }
    std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".into())
}
