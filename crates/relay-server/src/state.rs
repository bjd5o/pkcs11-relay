//! In-memory state: the pending queue, seen request ids, pending pairings, rate limits and
//! per-device wake-up channels. The std mutex is never held across an await.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use relay_core::relay_auth::NonceCache;
use relay_core::Fingerprint;
use tokio::sync::watch;

use crate::config::Config;
use crate::db::Db;
use crate::metrics::Metrics;
use crate::notify::Notifier;

pub type ReqId = [u8; 16];

pub struct Pending {
    pub bytes: Vec<u8>,
    pub client_id: String,
    pub key_fingerprint: Fingerprint,
    pub expires_at: u64,
    pub received_at: u64,
    /// Devices advertising the key when the request arrived.
    pub devices: Vec<String>,
    pub response: Option<Vec<u8>>,
    pub responded_by: Option<String>,
    /// Flips to `true` when a response arrives or the request expires.
    pub done: watch::Sender<bool>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PendingPairing {
    pub client_id: String,
    #[serde(serialize_with = "b64")]
    pub public_key: Vec<u8>,
    pub fingerprint: String,
    pub host: String,
    pub code: String,
    pub received_at: u64,
}

fn b64<S: serde::Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
    use base64::Engine as _;
    s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(v))
}

/// A token bucket allowing `per_minute` calls per minute, with that much burst.
#[derive(Debug, Clone, Copy)]
pub struct Bucket {
    tokens: f64,
    last: u64,
}

impl Bucket {
    fn take(&mut self, per_minute: u32, now: u64) -> bool {
        let cap = per_minute as f64;
        self.tokens = (self.tokens + (now.saturating_sub(self.last)) as f64 * cap / 60.0).min(cap);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[derive(Default)]
pub struct Inner {
    pub nonces: NonceCache,
    pub pending: HashMap<ReqId, Pending>,
    /// Every request id accepted, kept until its expiry plus the skew: duplicate rejection.
    pub seen: HashMap<ReqId, u64>,
    pub pairings: Vec<PendingPairing>,
    buckets: HashMap<String, Bucket>,
    device_watch: HashMap<String, watch::Sender<u64>>,
}

impl Inner {
    pub fn allow(&mut self, who: &str, per_minute: u32, now: u64) -> bool {
        self.buckets
            .entry(who.to_string())
            .or_insert(Bucket {
                tokens: per_minute as f64,
                last: now,
            })
            .take(per_minute, now)
    }

    pub fn device_channel(&mut self, device_id: &str) -> watch::Receiver<u64> {
        self.device_watch
            .entry(device_id.to_string())
            .or_insert_with(|| watch::channel(0).0)
            .subscribe()
    }

    /// Wake a device's long-poll and WebSocket.
    pub fn wake(&mut self, device_id: &str) {
        self.device_watch
            .entry(device_id.to_string())
            .or_insert_with(|| watch::channel(0).0)
            .send_modify(|v| *v += 1);
    }

    pub fn wake_all(&mut self) {
        for tx in self.device_watch.values() {
            tx.send_modify(|v| *v += 1);
        }
    }

    pub fn pending_for_client(&self, client_id: &str) -> usize {
        self.pending
            .values()
            .filter(|p| p.client_id == client_id)
            .count()
    }

    /// Drop expired requests, seen ids and pairings. Returns the expired requests' ids and
    /// client ids for the audit log.
    pub fn sweep(
        &mut self,
        now: u64,
        skew: u64,
        pairing_ttl: u64,
    ) -> Vec<(ReqId, String, Option<String>)> {
        let expired: Vec<ReqId> = self
            .pending
            .iter()
            .filter(|(_, p)| now > p.expires_at)
            .map(|(id, _)| *id)
            .collect();
        let mut out = Vec::new();
        for id in expired {
            if let Some(p) = self.pending.remove(&id) {
                p.done.send_replace(true);
                out.push((
                    id,
                    p.client_id,
                    p.response.as_ref().map(|_| "uncollected".to_string()),
                ));
            }
        }
        self.seen.retain(|_, exp| now <= exp.saturating_add(skew));
        self.pairings
            .retain(|p| now.saturating_sub(p.received_at) <= pairing_ttl);
        self.buckets
            .retain(|_, b| now.saturating_sub(b.last) < 3600);
        out
    }
}

pub struct AppState {
    pub cfg: Config,
    pub db: Db,
    pub inner: Mutex<Inner>,
    pub notifier: Arc<dyn Notifier>,
    pub metrics: Metrics,
}

impl AppState {
    pub fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_limits_and_refills() {
        let mut b = Bucket {
            tokens: 2.0,
            last: 0,
        };
        assert!(b.take(2, 0));
        assert!(b.take(2, 0));
        assert!(!b.take(2, 0));
        assert!(b.take(2, 30)); // one token back after half a minute
    }
}
