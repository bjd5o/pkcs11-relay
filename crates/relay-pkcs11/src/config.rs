//! Provider configuration (spec: PKCS#11 provider, Configuration), read at `C_Initialize`
//! from the TOML file named by `RELAY_PKCS11_CONFIG`.

use std::path::{Path, PathBuf};

use serde::Deserialize;

pub const ENV_VAR: &str = "RELAY_PKCS11_CONFIG";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// `https://relay.example:8443`
    pub relay_url: String,
    /// PEM trust anchors for the relay's TLS certificate (MVP: CA file only; see
    /// docs/decisions.md). Without it the public WebPKI roots are used.
    pub relay_ca_file: Option<PathBuf>,
    /// `https://…/manifest.json` (or `file://` for offline and test setups); the detached
    /// signature is fetched from the same URL plus `.asc`.
    pub manifest_url: String,
    /// The OpenPGP public key that signs the manifest: the only root of trust.
    pub manifest_signer: PathBuf,
    /// Last verified manifest (`.asc` stored next to it), plus the relay key-list cache.
    pub manifest_cache: PathBuf,
    pub client_id: String,
    /// Ed25519 or P-256 PKCS#8 PEM; generated on first run if missing.
    pub client_key: PathBuf,
    /// Context shown on the approval screen.
    #[serde(default)]
    pub purpose: String,
    /// Host name claimed in requests; defaults to the system host name.
    pub host: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_skew")]
    pub skew_secs: u64,
    /// How long the relay's key list stays usable while the relay is unreachable.
    #[serde(default = "default_keys_cache")]
    pub keys_cache_secs: u64,
    /// How often to refetch the manifest while the cached copy is valid.
    #[serde(default = "default_manifest_refresh")]
    pub manifest_refresh_secs: u64,
    /// `error`, `warn` (default), `info` or `debug`.
    #[serde(default)]
    pub log_level: Option<String>,
    /// Log file; stderr when unset.
    pub log_path: Option<PathBuf>,
    /// Hardware attestation of the manifest's attest keys (wire-format §9.4).
    #[serde(default)]
    pub hardware_attestation: relay_core::hw_attestation::PolicyConfig,
    /// The policy built from `hardware_attestation` by [`Config::load`].
    #[serde(skip)]
    pub policy: relay_core::HardwarePolicy,
}

fn default_timeout() -> u64 {
    90
}
fn default_skew() -> u64 {
    60
}
fn default_keys_cache() -> u64 {
    300
}
fn default_manifest_refresh() -> u64 {
    300
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("reading {}: {e}", path.display()))?;
        let mut cfg: Config =
            toml::from_str(&text).map_err(|e| format!("parsing {}: {e}", path.display()))?;
        cfg.policy = cfg
            .hardware_attestation
            .policy()
            .map_err(|e| format!("hardware_attestation: {e}"))?;
        if let Some(w) = cfg.hardware_attestation.warning() {
            crate::log::warn(&w);
        }
        relay_core::check_id(&cfg.client_id).map_err(|e| format!("client_id: {e}"))?;
        if cfg.timeout_secs == 0 || cfg.timeout_secs > relay_core::request::MAX_TTL {
            return Err(format!(
                "timeout_secs must be 1-{}",
                relay_core::request::MAX_TTL
            ));
        }
        if !(cfg.relay_url.starts_with("https://") || cfg.relay_url.starts_with("http://")) {
            return Err("relay_url must be an https:// URL".into());
        }
        if cfg.relay_url.starts_with("http://") {
            crate::log::warn("relay_url uses plain http: only for tests behind a trusted network");
        }
        Ok(cfg)
    }

    pub fn from_env() -> Result<Self, String> {
        let path = std::env::var_os(ENV_VAR).ok_or_else(|| format!("{ENV_VAR} is not set"))?;
        Self::load(Path::new(&path))
    }
}
