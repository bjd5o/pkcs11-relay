//! Relay service: mailbox, doorbell and directory. It can deny service, but it cannot make a
//! client trust a key or a response; every message check it runs is hygiene, done by
//! `relay-core`.
#![forbid(unsafe_code)]

pub mod admin;
pub mod api;
mod cidr;
pub mod config;
pub mod db;
pub mod metrics;
pub mod notify;
pub mod state;
pub mod trust;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use config::{Config, NotifyConfig};
use state::{now, AppState};

/// Build the shared state: open the database and the notifier.
pub async fn build_state(cfg: Config) -> Result<Arc<AppState>, String> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let manifest_check = trust::ManifestCheck::new(&cfg)?;
    let db = db::open(&cfg.data_dir).await?;
    let notifier: Arc<dyn notify::Notifier> = match &cfg.notify {
        NotifyConfig::Log => Arc::new(notify::LogNotifier),
        NotifyConfig::Ntfy { url, token_file } => {
            let token = match token_file {
                Some(p) => Some(
                    std::fs::read_to_string(p)
                        .map_err(|e| format!("ntfy token: {e}"))?
                        .trim()
                        .to_string(),
                ),
                None => None,
            };
            Arc::new(notify::NtfyNotifier::new(url.clone(), token)?)
        }
    };
    Ok(Arc::new(AppState {
        cfg,
        db,
        inner: Mutex::new(Default::default()),
        notifier,
        metrics: Default::default(),
        manifest_check,
    }))
}

/// Expire pending requests, seen ids and pairings once a second.
pub fn spawn_sweeper(st: Arc<AppState>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            let expired = st
                .lock()
                .sweep(now(), st.cfg.skew_secs, st.cfg.pairing_ttl_secs);
            for (id, client_id, note) in expired {
                metrics::Metrics::inc(&st.metrics.requests_expired);
                tracing::info!(req_id = hex::encode(id), client_id, "request expired");
                let e = db::AuditEvent {
                    ts: now() as i64,
                    event: "request_expired".into(),
                    client_id: Some(client_id),
                    req_id: Some(hex::encode(id)),
                    detail: note,
                    ..Default::default()
                };
                let _ = db::audit(&st.db, &e).await;
            }
        }
    });
}

/// Serve until the listener closes or the process gets SIGTERM / Ctrl-C.
pub async fn serve_on(listener: tokio::net::TcpListener, st: Arc<AppState>) -> Result<(), String> {
    spawn_sweeper(st.clone());
    let app = api::router(st).into_make_service_with_connect_info::<SocketAddr>();
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await
        .map_err(|e| e.to_string())
}

async fn shutdown() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = term => {} }
}

/// Serve HTTPS on `listener` with the PEM chain and key (rustls, ring provider).
pub async fn serve_tls(
    listener: std::net::TcpListener,
    st: Arc<AppState>,
    cert: &std::path::Path,
    key: &std::path::Path,
) -> Result<(), String> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
        .await
        .map_err(|e| format!("loading TLS certificate and key: {e}"))?;
    spawn_sweeper(st.clone());
    let app = api::router(st).into_make_service_with_connect_info::<SocketAddr>();
    let handle = axum_server::Handle::new();
    let h = handle.clone();
    tokio::spawn(async move {
        shutdown().await;
        h.graceful_shutdown(Some(Duration::from_secs(5)));
    });
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    axum_server::from_tcp_rustls(listener, tls)
        .map_err(|e| e.to_string())?
        .handle(handle)
        .serve(app)
        .await
        .map_err(|e| e.to_string())
}
