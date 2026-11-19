//! A blocking relay client for the apps (wire-format §8): `ureq` with rustls, trusting only the
//! relay's CA, every call signed through a [`DeviceSigner`]. No async runtime; the app calls it
//! from a background thread.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use relay_core::relay_auth::AuthHeaders;
use relay_core::signing::DeviceSigner;
use relay_core::{verify_manifest, Manifest, ManifestSigner};

use crate::ApproverError;

type Result<T> = std::result::Result<T, ApproverError>;

fn relay_err(e: impl std::fmt::Display) -> ApproverError {
    ApproverError::Relay(e.to_string())
}

/// An agent trusting `ca_pem` only (or the public roots without it).
fn agent(ca_pem: Option<&[u8]>, timeout: Duration) -> Result<ureq::Agent> {
    use ureq::tls::{PemItem, RootCerts, TlsConfig};
    let mut tls = TlsConfig::builder();
    if let Some(pem) = ca_pem {
        let mut certs = Vec::new();
        for item in ureq::tls::parse_pem(pem) {
            if let PemItem::Certificate(c) =
                item.map_err(|e| relay_err(format!("relay CA: {e}")))?
            {
                certs.push(c);
            }
        }
        if certs.is_empty() {
            return Err(relay_err("relay CA holds no certificates"));
        }
        tls = tls.root_certs(RootCerts::Specific(Arc::new(certs)));
    }
    let config = ureq::Agent::config_builder()
        .tls_config(tls.build())
        .http_status_as_error(false)
        .timeout_global(Some(timeout))
        .max_redirects(0)
        .build();
    Ok(ureq::Agent::new_with_config(config))
}

#[derive(Debug)]
pub struct Reply {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }
    fn check(self, what: &str) -> Result<Self> {
        if self.ok() {
            Ok(self)
        } else {
            Err(relay_err(format!(
                "{what}: HTTP {} {}",
                self.status,
                String::from_utf8_lossy(&self.body)
            )))
        }
    }
}

/// What `GET /v1/devices/{id}/pending` returned.
#[derive(Debug, Default)]
pub struct PendingItems {
    pub requests: Vec<Vec<u8>>,
    pub pairings: Vec<serde_json::Value>,
    /// The whole reply, for `Engine::ingest` (its `grants` and `revocations`).
    pub raw: serde_json::Value,
}

pub struct RelayClient {
    base: String,
    agent: ureq::Agent,
    ca_pem: Option<Vec<u8>>,
    auth: Arc<dyn DeviceSigner>,
}

impl RelayClient {
    /// `auth` signs every call (wire-format §8.2): the key the relay knows this device by.
    pub fn new(base: &str, ca_pem: Option<&[u8]>, auth: Arc<dyn DeviceSigner>) -> Result<Self> {
        if !base.starts_with("https://") && !base.starts_with("http://") {
            return Err(relay_err("relay URL must be https://"));
        }
        Ok(RelayClient {
            base: base.trim_end_matches('/').to_string(),
            // Long-polls wait up to 30 s at the relay.
            agent: agent(ca_pem, Duration::from_secs(45))?,
            ca_pem: ca_pem.map(<[u8]>::to_vec),
            auth,
        })
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    /// One signed call. `path` includes the query string, exactly as signed.
    pub fn call(&self, method: &str, path: &str, body: &[u8], content_type: &str) -> Result<Reply> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let h = AuthHeaders::sign_with(self.auth.as_ref(), method, path, body, now)
            .map_err(|e| ApproverError::Signer(e.to_string()))?;
        let url = format!("{}{}", self.base, path);
        let mut resp = match method {
            "GET" => {
                let mut r = self.agent.get(&url);
                for (k, v) in h.to_headers() {
                    r = r.header(k, &v);
                }
                r.call()
            }
            "POST" => {
                let mut r = self.agent.post(&url).header("content-type", content_type);
                for (k, v) in h.to_headers() {
                    r = r.header(k, &v);
                }
                r.send(body)
            }
            m => return Err(relay_err(format!("unsupported method {m}"))),
        }
        .map_err(|e| relay_err(format!("{path}: {e}")))?;
        let status = resp.status().as_u16();
        let body = resp
            .body_mut()
            .with_config()
            .limit(4 << 20)
            .read_to_vec()
            .map_err(relay_err)?;
        Ok(Reply { status, body })
    }

    /// Register or update this device (`POST /v1/devices`) with `Engine::registration`'s body.
    pub fn register(&self, body: &serde_json::Value) -> Result<()> {
        self.call(
            "POST",
            "/v1/devices",
            body.to_string().as_bytes(),
            "application/json",
        )?
        .check("device registration")
        .map(|_| ())
    }

    /// Pending requests and pairings, waiting up to `wait` seconds for something to arrive.
    pub fn pending(&self, device_id: &str, wait: u64) -> Result<PendingItems> {
        let v = self
            .call(
                "GET",
                &format!("/v1/devices/{device_id}/pending?wait={wait}"),
                b"",
                "application/octet-stream",
            )?
            .check("pending")?
            .json();
        let b64 = base64::engine::general_purpose::STANDARD;
        Ok(PendingItems {
            requests: v["requests"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|r| r.as_str().and_then(|s| b64.decode(s).ok()))
                .collect(),
            pairings: v["pairings"].as_array().cloned().unwrap_or_default(),
            raw: v,
        })
    }

    /// `GET` a JSON resource (the Clients and Approvers listings).
    pub fn get_json(&self, path: &str, what: &str) -> Result<serde_json::Value> {
        Ok(self
            .call("GET", path, b"", "application/octet-stream")?
            .check(what)?
            .json())
    }

    /// `POST` a JSON body (grants and revocations), expecting success.
    pub fn post_json(&self, path: &str, body: &serde_json::Value, what: &str) -> Result<()> {
        self.call(
            "POST",
            path,
            body.to_string().as_bytes(),
            "application/json",
        )?
        .check(what)
        .map(|_| ())
    }

    pub fn post_response(&self, req_id: [u8; 16], response: &[u8]) -> Result<()> {
        self.call(
            "POST",
            &format!("/v1/requests/{}/response", hex::encode(req_id)),
            response,
            "application/cbor",
        )?
        .check("posting the response")
        .map(|_| ())
    }

    /// `POST` a pairing approval made by `Engine::pairing_approval`.
    pub fn approve_pairing(&self, path: &str, body: &serde_json::Value) -> Result<()> {
        self.call(
            "POST",
            path,
            body.to_string().as_bytes(),
            "application/json",
        )?
        .check("pairing approval")
        .map(|_| ())
    }

    /// Fetch `url` and `url.asc` (the relay's CA when the relay serves them) and verify them
    /// exactly as clients do, against `cached` for rollback. Returns the manifest and the
    /// signature bytes that verified it (to store with it).
    pub fn fetch_manifest(
        &self,
        url: &str,
        signer: &ManifestSigner,
        policy: &relay_core::HardwarePolicy,
        cached: Option<&Manifest>,
        now: u64,
        skew: u64,
    ) -> Result<(Manifest, Vec<u8>)> {
        let bytes = self.fetch(url)?;
        let sig = self.fetch(&format!("{url}.asc"))?;
        let m = verify_manifest(&bytes, &sig, signer, policy, cached, now, skew)
            .map_err(crate::invalid)?;
        Ok((m, sig))
    }

    fn fetch(&self, url: &str) -> Result<Vec<u8>> {
        if let Some(path) = url.strip_prefix("file://") {
            return std::fs::read(path).map_err(|e| relay_err(format!("{path}: {e}")));
        }
        let ca = if relay_core::manifest::served_by_relay(url, &self.base) {
            self.ca_pem.as_deref()
        } else {
            None
        };
        let mut resp = agent(ca, Duration::from_secs(20))?
            .get(url)
            .call()
            .map_err(|e| relay_err(format!("{url}: {e}")))?;
        if resp.status().as_u16() != 200 {
            return Err(relay_err(format!("{url}: HTTP {}", resp.status())));
        }
        resp.body_mut()
            .with_config()
            .limit(relay_core::manifest::MAX_MANIFEST_LEN as u64)
            .read_to_vec()
            .map_err(relay_err)
    }
}
