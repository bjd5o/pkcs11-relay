//! An authenticated relay HTTP client (wire-format §8). Signing is done by `relay-core`.

use std::sync::Arc;

use relay_core::relay_auth::AuthHeaders;
use relay_core::signing::SoftwareKey;
use reqwest::{Method, StatusCode};

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Clone)]
pub struct Relay {
    pub base: String,
    http: reqwest::Client,
    key: Arc<SoftwareKey>,
    tls: Option<Arc<rustls::ClientConfig>>,
}

fn rustls_client_config(pem: &[u8]) -> Result<rustls::ClientConfig, String> {
    use rustls::pki_types::{pem::PemObject, CertificateDer};
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(pem) {
        roots
            .add(c.map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    }
    Ok(rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| e.to_string())?
    .with_root_certificates(roots)
    .with_no_client_auth())
}

pub struct Reply {
    pub status: StatusCode,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }
    pub fn error_kind(&self) -> String {
        self.json()["error"].as_str().unwrap_or("").to_string()
    }
}

impl Relay {
    /// `ca_pem`: the relay's trust anchors (PEM). Without it, only plain `http://` is usable.
    pub fn new(base: &str, key: Arc<SoftwareKey>, ca_pem: Option<&[u8]>) -> Result<Self, String> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut b = reqwest::Client::builder().timeout(std::time::Duration::from_secs(60));
        let mut tls = None;
        if let Some(pem) = ca_pem {
            b = b.tls_certs_only(
                reqwest::Certificate::from_pem_bundle(pem).map_err(|e| e.to_string())?,
            );
            tls = Some(Arc::new(rustls_client_config(pem)?));
        }
        Ok(Relay {
            base: base.trim_end_matches('/').to_string(),
            http: b.build().map_err(|e| e.to_string())?,
            key,
            tls,
        })
    }

    /// Open the device WebSocket, over TLS with the same trust anchors when `https`.
    pub async fn ws_connect(
        &self,
        path: &str,
    ) -> Result<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        String,
    > {
        let connector = self.tls.clone().map(tokio_tungstenite::Connector::Rustls);
        let (ws, _) = tokio_tungstenite::connect_async_tls_with_config(
            self.ws_request(path)?,
            None,
            false,
            connector,
        )
        .await
        .map_err(|e| e.to_string())?;
        Ok(ws)
    }

    pub fn with_key(&self, key: Arc<SoftwareKey>) -> Self {
        Relay {
            base: self.base.clone(),
            http: self.http.clone(),
            key,
            tls: self.tls.clone(),
        }
    }

    pub fn key(&self) -> &SoftwareKey {
        &self.key
    }

    /// Send a signed call. `path` includes the query string, exactly as signed.
    pub async fn send(
        &self,
        method: Method,
        path: &str,
        body: Vec<u8>,
        content_type: &str,
    ) -> Result<Reply, String> {
        let h = AuthHeaders::sign(&self.key, method.as_str(), path, &body, now());
        self.send_with(method, path, body, content_type, &h).await
    }

    /// Send with given headers (lets tests replay a call).
    pub async fn send_with(
        &self,
        method: Method,
        path: &str,
        body: Vec<u8>,
        content_type: &str,
        h: &AuthHeaders,
    ) -> Result<Reply, String> {
        let mut req = self
            .http
            .request(method, format!("{}{}", self.base, path))
            .body(body)
            .header("content-type", content_type);
        for (k, v) in h.to_headers() {
            req = req.header(k, v);
        }
        let resp = req.send().await.map_err(|e| format!("{path}: {e}"))?;
        let status = resp.status();
        let body = resp.bytes().await.map_err(|e| e.to_string())?.to_vec();
        Ok(Reply { status, body })
    }

    pub async fn get(&self, path: &str) -> Result<Reply, String> {
        self.send(Method::GET, path, Vec::new(), "application/octet-stream")
            .await
    }

    pub async fn post_json(&self, path: &str, v: &serde_json::Value) -> Result<Reply, String> {
        self.send(
            Method::POST,
            path,
            serde_json::to_vec(v).expect("json"),
            "application/json",
        )
        .await
    }

    pub async fn post_cbor(&self, path: &str, bytes: &[u8]) -> Result<Reply, String> {
        self.send(Method::POST, path, bytes.to_vec(), "application/cbor")
            .await
    }

    /// A WebSocket upgrade request with relay-auth headers for `path`.
    pub fn ws_request(
        &self,
        path: &str,
    ) -> Result<tokio_tungstenite::tungstenite::http::Request<()>, String> {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let url = format!("{}{}", self.base.replacen("http", "ws", 1), path);
        let mut req = url.into_client_request().map_err(|e| e.to_string())?;
        let h = AuthHeaders::sign(&self.key, "GET", path, b"", now());
        for (k, v) in h.to_headers() {
            req.headers_mut()
                .insert(k, v.parse().map_err(|_| "header value".to_string())?);
        }
        Ok(req)
    }
}

/// Fetch bytes from `file://` or `http(s)://`.
/// `ca_pem` replaces the public roots (the relay's CA, for a manifest the relay serves).
pub async fn fetch(url: &str, ca_pem: Option<&[u8]>) -> Result<Vec<u8>, String> {
    if let Some(path) = url.strip_prefix("file://") {
        return std::fs::read(path).map_err(|e| format!("{path}: {e}"));
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut b = reqwest::Client::builder();
    if let Some(pem) = ca_pem {
        b = b
            .tls_certs_only(reqwest::Certificate::from_pem_bundle(pem).map_err(|e| e.to_string())?);
    }
    let client = b.build().map_err(|e| e.to_string())?;
    let r = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("{url}: {e}"))?;
    if !r.status().is_success() {
        return Err(format!("{url}: {}", r.status()));
    }
    Ok(r.bytes().await.map_err(|e| e.to_string())?.to_vec())
}

/// Fetch and verify the manifest exactly as clients do (`relay_core::verify_manifest`).
/// `relay` is the relay URL and its CA, used when the manifest is served by the relay.
pub async fn load_manifest(
    url: &str,
    signer: &relay_core::ManifestSigner,
    skew: u64,
    relay: (&str, Option<&[u8]>),
) -> Result<relay_core::Manifest, String> {
    let ca = if relay_core::manifest::served_by_relay(url, relay.0) {
        relay.1
    } else {
        None
    };
    let bytes = fetch(url, ca).await?;
    let sig = fetch(&format!("{url}.asc"), ca).await?;
    relay_core::verify_manifest(&bytes, &sig, signer, None, now(), skew).map_err(|e| e.to_string())
}
