//! Prometheus text exposition, hand-written: a few counters and gauges.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

#[derive(Default)]
pub struct Metrics {
    pub requests_accepted: AtomicU64,
    pub requests_rejected: AtomicU64,
    pub requests_expired: AtomicU64,
    pub responses_approved: AtomicU64,
    pub responses_denied: AtomicU64,
    pub responses_error: AtomicU64,
    pub push_failures: AtomicU64,
    pub auth_failures: AtomicU64,
    pub approval_latency_seconds_sum: AtomicU64,
    pub approval_latency_count: AtomicU64,
}

impl Metrics {
    pub fn inc(c: &AtomicU64) {
        c.fetch_add(1, Relaxed);
    }

    pub fn render(&self, queue_depth: usize, pending_pairings: usize) -> String {
        let mut s = String::new();
        let mut counter = |name: &str, help: &str, v: u64| {
            let _ = writeln!(
                s,
                "# HELP relay_{name} {help}\n# TYPE relay_{name} counter\nrelay_{name} {v}"
            );
        };
        counter(
            "requests_accepted_total",
            "Signed requests queued.",
            self.requests_accepted.load(Relaxed),
        );
        counter(
            "requests_rejected_total",
            "Requests rejected before queuing.",
            self.requests_rejected.load(Relaxed),
        );
        counter(
            "requests_expired_total",
            "Requests that expired in the queue.",
            self.requests_expired.load(Relaxed),
        );
        counter(
            "responses_approved_total",
            "Approved responses.",
            self.responses_approved.load(Relaxed),
        );
        counter(
            "responses_denied_total",
            "Denials.",
            self.responses_denied.load(Relaxed),
        );
        counter(
            "responses_error_total",
            "Signed errors.",
            self.responses_error.load(Relaxed),
        );
        counter(
            "push_failures_total",
            "Doorbell pushes that failed.",
            self.push_failures.load(Relaxed),
        );
        counter(
            "auth_failures_total",
            "Calls with failed relay authentication.",
            self.auth_failures.load(Relaxed),
        );
        counter(
            "approval_latency_seconds_sum",
            "Sum of request-to-response times.",
            self.approval_latency_seconds_sum.load(Relaxed),
        );
        counter(
            "approval_latency_seconds_count",
            "Number of responses timed.",
            self.approval_latency_count.load(Relaxed),
        );
        let _ = writeln!(s, "# HELP relay_queue_depth Pending requests.\n# TYPE relay_queue_depth gauge\nrelay_queue_depth {queue_depth}");
        let _ = writeln!(s, "# HELP relay_pending_pairings Pending client pairings.\n# TYPE relay_pending_pairings gauge\nrelay_pending_pairings {pending_pairings}");
        s
    }
}
