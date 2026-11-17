//! Blocking HTTPS to the relay (`ureq` + rustls), signed with the client identity key. No
//! async runtime and no threads inside the host process.

use std::sync::Arc;
use std::time::Duration;

use relay_core::relay_auth::AuthHeaders;
use relay_core::signing::SoftwareKey;

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub struct Reply {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn error_kind(&self) -> String {
        serde_json::from_slice::<serde_json::Value>(&self.body)
            .ok()
            .and_then(|v| v["error"].as_str().map(String::from))
            .unwrap_or_default()
    }
}

fn agent(ca_pem: Option<&[u8]>, timeout: Duration) -> Result<ureq::Agent, String> {
    use ureq::tls::{PemItem, RootCerts, TlsConfig};
    let mut tls = TlsConfig::builder();
    if let Some(pem) = ca_pem {
        let mut certs = Vec::new();
        for item in ureq::tls::parse_pem(pem) {
            if let PemItem::Certificate(c) = item.map_err(|e| format!("relay CA: {e}"))? {
                certs.push(c);
            }
        }
        if certs.is_empty() {
            return Err("relay CA file holds no certificates".into());
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

pub struct RelayClient {
    base: String,
    agent: ureq::Agent,
    key: Arc<SoftwareKey>,
}

impl RelayClient {
    pub fn new(base: &str, ca_pem: Option<&[u8]>, key: Arc<SoftwareKey>) -> Result<Self, String> {
        Ok(RelayClient {
            base: base.trim_end_matches('/').to_string(),
            agent: agent(ca_pem, Duration::from_secs(40))?,
            key,
        })
    }

    pub fn key(&self) -> &SoftwareKey {
        &self.key
    }

    fn call(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        content_type: &str,
    ) -> Result<Reply, String> {
        let h = AuthHeaders::sign(&self.key, method, path, body, now());
        let url = format!("{}{}", self.base, path);
        let mut resp = match method {
            "GET" => {
                let mut r = self.agent.get(&url);
                for (k, v) in h.to_headers() {
                    r = r.header(k, v);
                }
                r.call()
            }
            _ => {
                let mut r = self.agent.post(&url).header("content-type", content_type);
                for (k, v) in h.to_headers() {
                    r = r.header(k, v);
                }
                r.send(body)
            }
        }
        .map_err(|e| format!("{method} {path}: {e}"))?;
        let status = resp.status().as_u16();
        let body = resp
            .body_mut()
            .with_config()
            .limit(1 << 20)
            .read_to_vec()
            .map_err(|e| e.to_string())?;
        Ok(Reply { status, body })
    }

    pub fn get(&self, path: &str) -> Result<Reply, String> {
        self.call("GET", path, b"", "")
    }

    pub fn post_json(&self, path: &str, v: &serde_json::Value) -> Result<Reply, String> {
        self.call(
            "POST",
            path,
            &serde_json::to_vec(v).expect("json"),
            "application/json",
        )
    }

    pub fn post_cbor(&self, path: &str, bytes: &[u8]) -> Result<Reply, String> {
        self.call("POST", path, bytes, "application/cbor")
    }
}

/// Fetch a manifest file over HTTPS or from `file://`. `ca_pem` replaces the public WebPKI
/// roots: callers pass the relay's CA when the manifest is served by the relay.
pub fn fetch(url: &str, ca_pem: Option<&[u8]>) -> Result<Vec<u8>, String> {
    if let Some(path) = url.strip_prefix("file://") {
        return std::fs::read(path).map_err(|e| format!("{path}: {e}"));
    }
    if !url.starts_with("https://") {
        return Err("manifest_url must be https:// or file://".into());
    }
    let a = agent(ca_pem, Duration::from_secs(20))?;
    let mut resp = a.get(url).call().map_err(|e| format!("{url}: {e}"))?;
    if resp.status().as_u16() != 200 {
        return Err(format!("{url}: HTTP {}", resp.status()));
    }
    resp.body_mut()
        .with_config()
        .limit(relay_core::manifest::MAX_MANIFEST_LEN as u64)
        .read_to_vec()
        .map_err(|e| e.to_string())
}
