//! The doorbell: a content-free push ("1 pending request") to devices that advertise a key.

use std::future::Future;
use std::pin::Pin;

use crate::db::PushTarget;

/// Why a push failed.
#[derive(Debug, PartialEq, Eq)]
pub enum PushError {
    Failed(String),
    /// The push service says the device's token is no longer valid: the relay forgets it.
    Unregistered(String),
}

impl std::fmt::Display for PushError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PushError::Failed(m) => write!(f, "{m}"),
            PushError::Unregistered(m) => write!(f, "token no longer valid: {m}"),
        }
    }
}

pub type PushFuture = Pin<Box<dyn Future<Output = Result<(), PushError>> + Send>>;

pub trait Notifier: Send + Sync {
    fn ring(&self, device_id: &str, target: &PushTarget) -> PushFuture;
}

/// Logs instead of pushing. Devices holding a WebSocket or long-poll are woken regardless.
pub struct LogNotifier;

impl Notifier for LogNotifier {
    fn ring(&self, device_id: &str, target: &PushTarget) -> PushFuture {
        tracing::info!(device_id, target = ?std::mem::discriminant(target), "doorbell");
        Box::pin(async { Ok(()) })
    }
}

/// ntfy: POST `{url}/{topic}` with a fixed, content-free body. The topic comes from the device's
/// registration; the server URL only from relay config, so a device cannot point the relay at
/// arbitrary hosts.
pub struct NtfyNotifier {
    client: reqwest::Client,
    url: String,
    token: Option<String>,
}

impl NtfyNotifier {
    pub fn new(url: String, token: Option<String>) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(NtfyNotifier {
            client,
            url: url.trim_end_matches('/').to_string(),
            token,
        })
    }
}

fn valid_topic(t: &str) -> bool {
    !t.is_empty()
        && t.len() <= 64
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl Notifier for NtfyNotifier {
    fn ring(&self, device_id: &str, target: &PushTarget) -> PushFuture {
        let req = match target {
            PushTarget::Ntfy { topic } if valid_topic(topic) => {
                let mut r = self
                    .client
                    .post(format!("{}/{}", self.url, topic))
                    .body("1 pending request");
                if let Some(t) = &self.token {
                    r = r.bearer_auth(t);
                }
                r
            }
            PushTarget::Ntfy { .. } => {
                return Box::pin(async { Err(PushError::Failed("invalid ntfy topic".into())) })
            }
            PushTarget::None => return Box::pin(async { Ok(()) }),
            PushTarget::Apns { .. } | PushTarget::Fcm { .. } => {
                tracing::warn!(
                    device_id,
                    "device registered for APNs or FCM, but this relay is configured for ntfy"
                );
                return Box::pin(async { Ok(()) });
            }
        };
        Box::pin(async move {
            let resp = req
                .send()
                .await
                .map_err(|e| PushError::Failed(e.to_string()))?;
            if resp.status().is_success() {
                Ok(())
            } else {
                Err(PushError::Failed(format!(
                    "ntfy returned {}",
                    resp.status()
                )))
            }
        })
    }
}

/// Apple Push Notification service: token-based authentication (an ES256 JWT signed with the
/// `.p8` key, refreshed every 30 minutes), HTTP/2, and a content-free alert.
pub struct ApnsNotifier {
    client: reqwest::Client,
    base: String,
    key: relay_core::signing::SoftwareKey,
    key_id: String,
    team_id: String,
    topic: String,
    ttl_secs: u64,
    jwt: std::sync::Mutex<Option<(String, u64)>>,
}

/// What APNs answered, beyond success.
#[derive(Debug, PartialEq, Eq)]
pub enum ApnsError {
    /// The device token is no longer valid: forget it.
    Unregistered(String),
    Failed(String),
}

/// The alert every push carries: no client, key, host or purpose (spec: the push carries no
/// content).
pub const APNS_PAYLOAD: &str =
    r#"{"aps":{"alert":{"title":"Relay Approver","body":"1 pending request"},"sound":"default"}}"#;

fn b64url(b: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn valid_apns_token(t: &str) -> bool {
    (32..=200).contains(&t.len()) && t.bytes().all(|b| b.is_ascii_hexdigit())
}

impl ApnsNotifier {
    pub fn new(
        key_pem: &str,
        key_id: String,
        team_id: String,
        topic: String,
        environment: &str,
        url: Option<String>,
        ttl_secs: u64,
    ) -> Result<Self, String> {
        let key = relay_core::signing::SoftwareKey::from_pkcs8_pem(key_pem)
            .map_err(|e| format!("APNs key: {e}"))?;
        if key.public_key().algorithm() != relay_core::Algorithm::P256 {
            return Err("APNs key must be P-256 (the .p8 from the developer account)".into());
        }
        let base = match (url, environment) {
            (Some(u), _) => u,
            (None, "sandbox") => "https://api.sandbox.push.apple.com".into(),
            (None, "production") => "https://api.push.apple.com".into(),
            (None, e) => {
                return Err(format!(
                    "APNs environment must be sandbox or production, not {e}"
                ))
            }
        };
        let client = reqwest::Client::builder()
            .http2_prior_knowledge()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(ApnsNotifier {
            client,
            base: base.trim_end_matches('/').to_string(),
            key,
            key_id,
            team_id,
            topic,
            ttl_secs,
            jwt: std::sync::Mutex::new(None),
        })
    }

    /// The provider token, reused for 30 minutes (Apple: refresh between 20 and 60).
    pub fn token(&self, now: u64) -> String {
        let mut cached = self.jwt.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((t, iat)) = cached.as_ref() {
            if now.saturating_sub(*iat) < 30 * 60 {
                return t.clone();
            }
        }
        let header = b64url(format!(r#"{{"alg":"ES256","kid":"{}"}}"#, self.key_id).as_bytes());
        let claims = b64url(format!(r#"{{"iss":"{}","iat":{now}}}"#, self.team_id).as_bytes());
        let input = format!("{header}.{claims}");
        let sig = self.key.sign(input.as_bytes());
        let t = format!("{input}.{}", b64url(&sig));
        *cached = Some((t.clone(), now));
        t
    }

    /// Send one alert to `token`.
    pub async fn send(&self, token: &str, now: u64) -> Result<(), ApnsError> {
        if !valid_apns_token(token) {
            return Err(ApnsError::Unregistered("not a device token".into()));
        }
        let resp = self
            .client
            .post(format!("{}/3/device/{token}", self.base))
            .header("authorization", format!("bearer {}", self.token(now)))
            .header("apns-topic", &self.topic)
            .header("apns-push-type", "alert")
            .header("apns-priority", "10")
            .header("apns-expiration", (now + self.ttl_secs).to_string())
            .header("content-type", "application/json")
            .body(APNS_PAYLOAD)
            .send()
            .await
            .map_err(|e| ApnsError::Failed(e.to_string()))?;
        let status = resp.status().as_u16();
        if status == 200 {
            return Ok(());
        }
        let reason = resp
            .bytes()
            .await
            .ok()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|v| v["reason"].as_str().map(str::to_string))
            .unwrap_or_default();
        match (status, reason.as_str()) {
            (410, _) | (400, "BadDeviceToken" | "DeviceTokenNotForTopic") => {
                Err(ApnsError::Unregistered(format!("{status} {reason}")))
            }
            (403, "ExpiredProviderToken") => {
                *self.jwt.lock().unwrap_or_else(|e| e.into_inner()) = None;
                Err(ApnsError::Failed(format!("{status} {reason}")))
            }
            _ => Err(ApnsError::Failed(format!("{status} {reason}"))),
        }
    }
}

impl Notifier for std::sync::Arc<ApnsNotifier> {
    fn ring(&self, device_id: &str, target: &PushTarget) -> PushFuture {
        let PushTarget::Apns { token } = target else {
            if !matches!(target, PushTarget::None) {
                tracing::warn!(
                    device_id,
                    "device registered for another push service; this relay sends APNs"
                );
            }
            return Box::pin(async { Ok(()) });
        };
        let (me, token) = (self.clone(), token.clone());
        Box::pin(async move {
            me.send(&token, crate::state::now())
                .await
                .map_err(|e| match e {
                    ApnsError::Unregistered(m) => PushError::Unregistered(m),
                    ApnsError::Failed(m) => PushError::Failed(m),
                })
        })
    }
}
