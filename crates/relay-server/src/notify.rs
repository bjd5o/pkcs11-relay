//! The doorbell: a content-free push ("1 pending request") to devices that advertise a key.

use std::future::Future;
use std::pin::Pin;

use crate::db::PushTarget;

pub type PushFuture = Pin<Box<dyn Future<Output = Result<(), String>> + Send>>;

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
                return Box::pin(async { Err("invalid ntfy topic".to_string()) })
            }
            PushTarget::None => return Box::pin(async { Ok(()) }),
            PushTarget::Apns { .. } | PushTarget::Fcm { .. } => {
                tracing::warn!(
                    device_id,
                    "APNs/FCM push not implemented until milestones 5-6"
                );
                return Box::pin(async { Ok(()) });
            }
        };
        Box::pin(async move {
            let resp = req.send().await.map_err(|e| e.to_string())?;
            if resp.status().is_success() {
                Ok(())
            } else {
                Err(format!("ntfy returned {}", resp.status()))
            }
        })
    }
}
