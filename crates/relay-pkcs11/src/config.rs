//! Provider configuration (spec: PKCS#11 provider, Configuration), read at `C_Initialize`
//! from the TOML file named by `RELAY_PKCS11_CONFIG`, or else from the first default path
//! that exists (see [`locate`]).

use std::ffi::OsString;
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

    /// Finds the config file with [`locate`] in the process environment and loads it.
    pub fn from_env() -> Result<(Self, Located), String> {
        let found = locate(&Search {
            var: &|k| std::env::var_os(k),
            is_file: &|p| p.is_file(),
            apple: cfg!(target_vendor = "apple"),
        })?;
        Ok((Self::load(&found.path)?, found))
    }
}

/// Where [`locate`] looks: the environment, the file system and the platform, passed in so
/// tests don't touch the process environment.
pub struct Search<'a> {
    pub var: &'a dyn Fn(&str) -> Option<OsString>,
    pub is_file: &'a dyn Fn(&Path) -> bool,
    /// Also look in `~/Library/Application Support` (macOS and iPadOS).
    pub apple: bool,
}

/// The config file to read, and the default-path files it hides.
#[derive(Debug, PartialEq, Eq)]
pub struct Located {
    pub path: PathBuf,
    pub shadowed: Vec<PathBuf>,
}

const FILE: &str = "relay-pkcs11/provider.toml";

/// The config file, in order (docs/decisions.md, "Default provider config paths"):
/// `$RELAY_PKCS11_CONFIG`; `$XDG_CONFIG_HOME/relay-pkcs11/provider.toml`, where an unset,
/// empty or relative `XDG_CONFIG_HOME` means `~/.config`; on Apple platforms
/// `~/Library/Application Support/relay-pkcs11/provider.toml`. The first one found is the
/// whole config; files are never merged. A `RELAY_PKCS11_CONFIG` naming a missing file is
/// an error rather than a fall-through, so a typo never picks up another config.
pub fn locate(s: &Search) -> Result<Located, String> {
    let set = |k: &str| (s.var)(k).filter(|v| !v.is_empty());
    if let Some(p) = set(ENV_VAR) {
        let path = PathBuf::from(p);
        if !(s.is_file)(&path) {
            return Err(format!(
                "{ENV_VAR} names {}, which is not a file",
                path.display()
            ));
        }
        return Ok(Located {
            path,
            shadowed: Vec::new(),
        });
    }
    let home = set("HOME").map(PathBuf::from);
    let xdg = set("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| home.as_ref().map(|h| h.join(".config")));
    let app_support = home
        .as_ref()
        .filter(|_| s.apple)
        .map(|h| h.join("Library/Application Support"));
    let candidates: Vec<PathBuf> = [xdg, app_support]
        .into_iter()
        .flatten()
        .map(|d| d.join(FILE))
        .collect();
    let mut found = candidates.iter().filter(|p| (s.is_file)(p)).cloned();
    match found.next() {
        Some(path) => Ok(Located {
            path,
            shadowed: found.collect(),
        }),
        None if candidates.is_empty() => Err(format!("{ENV_VAR} and HOME are not set")),
        None => Err(format!(
            "{ENV_VAR} is not set and none of these exists: {}",
            candidates
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    fn run(vars: &[(&str, &str)], files: &[&str], apple: bool) -> Result<Located, String> {
        let vars: HashMap<String, OsString> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), OsString::from(v)))
            .collect();
        let files: HashSet<PathBuf> = files.iter().map(PathBuf::from).collect();
        locate(&Search {
            var: &|k| vars.get(k).cloned(),
            is_file: &|p| files.contains(p),
            apple,
        })
    }

    fn found(path: &str, shadowed: &[&str]) -> Result<Located, String> {
        Ok(Located {
            path: path.into(),
            shadowed: shadowed.iter().map(PathBuf::from).collect(),
        })
    }

    const XDG: &str = "/x/relay-pkcs11/provider.toml";
    const DOT: &str = "/h/.config/relay-pkcs11/provider.toml";
    const APP: &str = "/h/Library/Application Support/relay-pkcs11/provider.toml";

    #[test]
    fn the_environment_variable_wins_over_every_default_path() {
        let vars = [("RELAY_PKCS11_CONFIG", "/e.toml"), ("HOME", "/h")];
        assert_eq!(
            run(&vars, &["/e.toml", DOT, APP], true),
            found("/e.toml", &[])
        );
    }

    #[test]
    fn a_missing_file_named_by_the_variable_is_an_error_not_a_fall_through() {
        let vars = [("RELAY_PKCS11_CONFIG", "/typo.toml"), ("HOME", "/h")];
        let e = run(&vars, &[DOT], true).unwrap_err();
        assert!(e.contains("/typo.toml"), "{e}");
    }

    #[test]
    fn an_empty_variable_counts_as_unset() {
        let vars = [("RELAY_PKCS11_CONFIG", ""), ("HOME", "/h")];
        assert_eq!(run(&vars, &[DOT], false), found(DOT, &[]));
    }

    #[test]
    fn xdg_config_home_wins_over_application_support_and_hides_it() {
        let vars = [("XDG_CONFIG_HOME", "/x"), ("HOME", "/h")];
        assert_eq!(run(&vars, &[XDG, APP], true), found(XDG, &[APP]));
        assert_eq!(
            run(&vars, &[XDG, DOT], true),
            found(XDG, &[]),
            "~/.config isn't looked at"
        );
    }

    #[test]
    fn an_unset_empty_or_relative_xdg_config_home_means_dot_config() {
        for xdg in [None, Some(""), Some("rel/dir")] {
            let mut vars = vec![("HOME", "/h")];
            vars.extend(xdg.map(|x| ("XDG_CONFIG_HOME", x)));
            assert_eq!(run(&vars, &[DOT], false), found(DOT, &[]), "{xdg:?}");
        }
    }

    #[test]
    fn application_support_is_the_fallback_on_apple_platforms_only() {
        let vars = [("HOME", "/h")];
        assert_eq!(run(&vars, &[APP], true), found(APP, &[]));
        assert!(run(&vars, &[APP], false).is_err());
    }

    #[test]
    fn no_file_found_lists_every_path_tried() {
        let e = run(&[("HOME", "/h")], &[], true).unwrap_err();
        assert!(e.contains(DOT) && e.contains(APP), "{e}");
    }

    #[test]
    fn without_home_only_an_absolute_xdg_config_home_is_tried() {
        assert_eq!(
            run(&[("XDG_CONFIG_HOME", "/x")], &[XDG], true),
            found(XDG, &[])
        );
        assert!(run(&[], &[], true).unwrap_err().contains("HOME"));
    }
}
