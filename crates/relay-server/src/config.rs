//! Relay configuration: a TOML file with `RELAY_*` environment-variable overrides.

use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Listener address. TLS is terminated by a reverse proxy in front of the relay.
    pub listen: String,
    /// PEM certificate chain and key. When both are set the relay serves HTTPS itself;
    /// otherwise plain HTTP for a TLS-terminating proxy in front.
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    /// Holds `relay.db` (SQLite, WAL).
    pub data_dir: PathBuf,
    pub skew_secs: u64,
    pub max_ttl_secs: u64,
    pub max_pending_per_client: usize,
    pub max_body_bytes: usize,
    /// Signed requests a client may submit per minute: what bounds approval prompts.
    pub client_requests_per_minute: u32,
    /// All other authenticated client calls (discovery, long-polls) per minute.
    pub client_calls_per_minute: u32,
    pub device_calls_per_minute: u32,
    /// Source networks allowed to start pairing (spec: tailnet only).
    pub pairing_allowed_cidrs: Vec<String>,
    pub max_pending_pairings: usize,
    pub pairing_ttl_secs: u64,
    pub long_poll_max_secs: u64,
    pub max_devices: usize,
    pub notify: NotifyConfig,
    /// A copy of the signed manifest to serve at `GET /v1/manifest`, re-read on every request
    /// so a newly signed version is served without a restart. Its detached signature is served
    /// at `/v1/manifest.asc`, from `manifest_signature_file` or else `<manifest_file>.asc`.
    pub manifest_file: Option<PathBuf>,
    pub manifest_signature_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum NotifyConfig {
    /// Log the doorbell instead of sending it.
    Log,
    /// POST to `{url}/{topic}` for devices that registered an ntfy topic.
    Ntfy {
        url: String,
        token_file: Option<PathBuf>,
    },
}

impl Default for Config {
    fn default() -> Self {
        Config {
            listen: "0.0.0.0:8080".into(),
            tls_cert: None,
            tls_key: None,
            data_dir: "/data".into(),
            skew_secs: 60,
            max_ttl_secs: 120,
            max_pending_per_client: 4,
            max_body_bytes: 64 * 1024,
            client_requests_per_minute: 30,
            client_calls_per_minute: 600,
            device_calls_per_minute: 240,
            // Tailscale's IPv4 CGNAT and IPv6 ULA ranges, plus loopback.
            pairing_allowed_cidrs: vec![
                "100.64.0.0/10".into(),
                "fd7a:115c:a1e0::/48".into(),
                "127.0.0.0/8".into(),
                "::1/128".into(),
            ],
            max_pending_pairings: 4,
            pairing_ttl_secs: 600,
            long_poll_max_secs: 30,
            max_devices: 32,
            notify: NotifyConfig::Log,
            manifest_file: None,
            manifest_signature_file: None,
        }
    }
}

impl Config {
    /// Read the file (if given), then apply environment overrides.
    pub fn load(path: Option<&Path>) -> Result<Self, String> {
        let mut cfg: Config = match path {
            Some(p) => {
                let text = std::fs::read_to_string(p)
                    .map_err(|e| format!("reading {}: {e}", p.display()))?;
                toml::from_str(&text).map_err(|e| format!("parsing {}: {e}", p.display()))?
            }
            None => Config::default(),
        };
        if let Ok(v) = std::env::var("RELAY_LISTEN") {
            cfg.listen = v;
        }
        if let Ok(v) = std::env::var("RELAY_TLS_CERT") {
            cfg.tls_cert = Some(v.into());
        }
        if let Ok(v) = std::env::var("RELAY_TLS_KEY") {
            cfg.tls_key = Some(v.into());
        }
        if cfg.tls_cert.is_some() != cfg.tls_key.is_some() {
            return Err("tls_cert and tls_key must be set together".into());
        }
        if let Ok(v) = std::env::var("RELAY_DATA_DIR") {
            cfg.data_dir = v.into();
        }
        if let Ok(v) = std::env::var("RELAY_PAIRING_ALLOWED_CIDRS") {
            cfg.pairing_allowed_cidrs = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        for c in &cfg.pairing_allowed_cidrs {
            crate::cidr::Cidr::parse(c)?;
        }
        if cfg.max_ttl_secs > relay_core::request::MAX_TTL {
            return Err(format!(
                "max_ttl_secs cannot exceed {}",
                relay_core::request::MAX_TTL
            ));
        }
        Ok(cfg)
    }
}
