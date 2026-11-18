//! Setting up the app from a signed link (docs/setup-link.md, "App flow"; wire-format §11).
//!
//! Blocking, like the rest of the app's networking. Nothing from the link is trusted until it
//! is checked: the time window first, then the relay CA against the link's pin, the signer key
//! against the link's fingerprint, the link's signature under that key, and finally the
//! manifest under the same key. The keys.openpgp.org lookup only shows an identity, except
//! that a revocation or expiry it reveals stops setup.

use std::sync::Arc;
use std::time::Duration;

use relay_core::setup_link::{self, SetupLink};
use relay_core::signer::{self, SignerStatus};
use relay_core::{HardwarePolicy, ManifestSigner};

use crate::relay::RelayClient;
use crate::ApproverError;

type Result<T> = std::result::Result<T, ApproverError>;

pub const KEYSERVER: &str = "https://keys.openpgp.org";

fn fail(m: impl Into<String>) -> ApproverError {
    ApproverError::Invalid(m.into())
}

/// What keys.openpgp.org says about the signer key, for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identity {
    /// The user IDs it publishes: each one's address was confirmed by its owner.
    Verified(Vec<String>),
    /// It has the key but no confirmed address.
    NoIdentity,
    /// 404: not published there.
    NotFound,
    /// Network error, timeout, TLS failure or 5xx.
    Unreachable(String),
    /// It returned a different key, or one that doesn't parse: shown as an error.
    Mismatch(String),
}

/// Everything the confirm screen shows, checked.
#[derive(Debug, Clone)]
pub struct Preview {
    pub link: String,
    pub relay_url: String,
    /// The relay CA's PEM, verified against the link's pin; `None` for a publicly trusted relay.
    pub relay_ca_pem: Option<String>,
    pub manifest_url: String,
    /// The signer's public key as the relay serves it.
    pub manifest_signer: Vec<u8>,
    pub signer_fingerprint: String,
    pub identity: Identity,
    pub device_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub max_attestation_window_secs: u64,
    pub require_hardware_attestation: bool,
}

/// Where setup reaches out to, overridable in tests only.
pub struct SetupOptions {
    pub keyserver: String,
    pub policy: HardwarePolicy,
    pub skew_secs: u64,
}

impl Default for SetupOptions {
    fn default() -> Self {
        SetupOptions {
            keyserver: KEYSERVER.into(),
            policy: HardwarePolicy::yubico(),
            skew_secs: 60,
        }
    }
}

/// Fetch `GET /v1/relay-ca.pem` with certificate verification off, and return it only if it
/// matches the pin (wire-format §11.2): the pin from the signed link decides, not the network.
fn fetch_pinned_ca(relay: &str, pin: &[u8; 32]) -> Result<String> {
    use ureq::tls::TlsConfig;
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .tls_config(TlsConfig::builder().disable_verification(true).build())
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(15)))
            .max_redirects(0)
            .build(),
    );
    let mut resp = agent
        .get(&format!("{relay}/v1/relay-ca.pem"))
        .call()
        .map_err(|e| ApproverError::Relay(format!("fetching the relay CA: {e}")))?;
    if resp.status().as_u16() != 200 {
        return Err(ApproverError::Relay(format!(
            "the relay CA: HTTP {}",
            resp.status().as_u16()
        )));
    }
    let pem = resp
        .body_mut()
        .with_config()
        .limit(64 * 1024)
        .read_to_vec()
        .map_err(|e| ApproverError::Relay(format!("the relay CA: {e}")))?;
    setup_link::check_relay_ca(&pem, pin).map_err(|e| fail(e.to_string()))
}

/// Look the signer up at the keyserver. Returns the identity and, if it served the same key, its
/// copy (for the revocation and expiry check).
pub fn lookup_identity(keyserver: &str, fingerprint: &str) -> (Identity, Option<Vec<u8>>) {
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(10)))
            .max_redirects(0)
            .build(),
    );
    let url = format!(
        "{}/vks/v1/by-fingerprint/{fingerprint}",
        keyserver.trim_end_matches('/')
    );
    let mut resp = match agent.get(&url).call() {
        Ok(r) => r,
        Err(e) => return (Identity::Unreachable(e.to_string()), None),
    };
    match resp.status().as_u16() {
        200 => {}
        404 => return (Identity::NotFound, None),
        s => return (Identity::Unreachable(format!("HTTP {s}")), None),
    }
    let bytes = match resp.body_mut().with_config().limit(1 << 20).read_to_vec() {
        Ok(b) => b,
        Err(e) => return (Identity::Unreachable(e.to_string()), None),
    };
    match signer::parse_key(&bytes) {
        Ok(k) if signer::fingerprint(&k) == fingerprint => {
            let ids = signer::user_ids(&k);
            let identity = if ids.is_empty() {
                Identity::NoIdentity
            } else {
                Identity::Verified(ids)
            };
            (identity, Some(bytes))
        }
        Ok(k) => (
            Identity::Mismatch(format!(
                "keys.openpgp.org returned a different key, {}",
                signer::fingerprint(&k)
            )),
            None,
        ),
        Err(e) => (
            Identity::Mismatch(format!("keys.openpgp.org returned an unreadable key: {e}")),
            None,
        ),
    }
}

/// Check a setup link and everything it points at (docs/setup-link.md, steps 1–7).
pub fn preview(link: &str, now: u64, opts: &SetupOptions) -> Result<Preview> {
    // 1. Form.
    let l: SetupLink = setup_link::parse(link).map_err(|e| fail(e.to_string()))?;
    // 2. Time, before anything is fetched.
    if now.saturating_add(opts.skew_secs) < l.iat {
        return Err(fail(
            "this link's issue time is in the future: the phone's clock or the link is wrong",
        ));
    }
    if now > l.exp.saturating_add(opts.skew_secs) {
        return Err(fail(format!(
            "this link expired at {}; make a new one with relayctl app-link",
            l.exp
        )));
    }
    // 3. The relay CA, pinned.
    let ca_pem = match &l.ca {
        Some(pin) => Some(fetch_pinned_ca(&l.relay, pin)?),
        None => None,
    };
    // 4. The signer key over the pinned connection.
    let throwaway = Arc::new(relay_core::signing::SoftwareKey::generate_p256());
    let rc = RelayClient::new(&l.relay, ca_pem.as_deref().map(str::as_bytes), throwaway)?;
    let r = rc.call("GET", "/v1/manifest-signer.asc", b"", "application/json")?;
    if !r.ok() {
        return Err(ApproverError::Relay(format!(
            "the relay's manifest signer: HTTP {}",
            r.status
        )));
    }
    let signer = ManifestSigner::from_bytes(&r.body).map_err(|e| fail(e.to_string()))?;
    if signer.fingerprint() != l.signer {
        return Err(fail(format!(
            "the relay's manifest signer is {}, not {} as the link says",
            signer.fingerprint(),
            l.signer
        )));
    }
    // 5. The link's signature under that key.
    setup_link::verify_setup_link(link, &signer, now, opts.skew_secs)
        .map_err(|e| fail(e.to_string()))?;
    // 7. Identity, and the keyserver's copy for the status check.
    let (identity, keyserver_copy) = lookup_identity(&opts.keyserver, &l.signer);
    let mut copies = vec![signer::parse_key(&r.body).map_err(|e| fail(e.to_string()))?];
    if let Some(k) = keyserver_copy
        .as_deref()
        .and_then(|b| signer::parse_key(b).ok())
    {
        copies.push(k);
    }
    match signer::signer_status(&copies, now).map_err(|e| fail(e.to_string()))? {
        SignerStatus::Usable { .. } => {}
        s => {
            return Err(fail(format!(
                "the manifest signer key {} {}; set up is refused",
                l.signer,
                s.describe()
            )))
        }
    }
    // 6. The manifest, under the same key.
    let manifest_url = format!("{}/v1/manifest", l.relay);
    let (m, _) = rc.fetch_manifest(
        &manifest_url,
        &signer,
        &opts.policy,
        None,
        now,
        opts.skew_secs,
    )?;
    Ok(Preview {
        link: link.to_string(),
        relay_url: l.relay.clone(),
        relay_ca_pem: ca_pem,
        manifest_url,
        manifest_signer: r.body,
        signer_fingerprint: l.signer.clone(),
        identity,
        device_id: l.device.clone(),
        issued_at: l.iat,
        expires_at: l.exp,
        max_attestation_window_secs: m.max_attestation_window_secs,
        require_hardware_attestation: m.require_hardware_attestation,
    })
}
