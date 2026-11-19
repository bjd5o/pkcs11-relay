//! The relay's HTTP API (spec: Relay, API table; wire-format §8 and §10).
//!
//! The relay is untrusted: every check here is hygiene (dropping junk and spam), never the
//! basis of a client's trust. All parsing and signature checks call `relay-core`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, DefaultBodyLimit, OriginalUri, Path, Query, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use relay_core::attestation::AttestationStatement;
use relay_core::grant::{ClientGrant, ClientRevocation};
use relay_core::relay_auth::{self, AuthHeaders};
use relay_core::request::{self, SignedRequest};
use relay_core::response::{self, Status};
use relay_core::{Fingerprint, PublicKey};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::sync::watch;

use crate::cidr::Cidr;
use crate::db::{self, AdvertisedKey, AuditEvent, ClientRecord, DeviceRecord, PushTarget};
use crate::metrics::Metrics;
use crate::state::{now, AppState, Pending, PendingPairing, ReqId};

type S = State<Arc<AppState>>;

pub fn router(state: Arc<AppState>) -> Router {
    let limit = state.cfg.max_body_bytes;
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/metrics", get(metrics))
        .route("/v1/keys", get(list_keys))
        .route("/v1/manifest", get(manifest))
        .route("/v1/manifest.asc", get(manifest_signature))
        .route("/v1/manifest-signer.asc", get(manifest_signer))
        .route("/v1/relay-ca.pem", get(relay_ca))
        .route("/v1/requests", post(submit_request))
        .route("/v1/requests/{id}/result", get(get_result))
        .route("/v1/requests/{id}/response", post(post_response))
        .route("/v1/clients/pending", post(pending_client))
        .route("/v1/clients/self", get(client_self))
        .route("/v1/clients", get(list_clients))
        .route("/v1/clients/{id}/approval", post(approve_client))
        .route("/v1/clients/{id}/grant", post(post_grant))
        .route("/v1/clients/{id}/revocation", post(post_revocation))
        .route("/v1/devices", post(register_device).get(list_devices))
        .route("/v1/devices/{id}/pending", get(device_pending))
        .route("/v1/devices/{id}/ws", get(device_ws))
        .layer(DefaultBodyLimit::max(limit))
        .with_state(state)
}

// ---------- manifest copy ----------

/// Serve a configured file's bytes unchanged. Unauthenticated: the manifest is public and
/// signed; the relay is not trusted for it.
fn serve_file(
    path: Option<&std::path::Path>,
    content_type: &'static str,
) -> Result<Response, ApiError> {
    let path =
        path.ok_or_else(|| err(StatusCode::NOT_FOUND, "not_found", "no manifest configured"))?;
    let bytes = std::fs::read(path).map_err(|e| {
        tracing::warn!(path = %path.display(), error = %e, "manifest file unreadable");
        err(StatusCode::NOT_FOUND, "not_found", "manifest unavailable")
    })?;
    if bytes.len() > relay_core::manifest::MAX_MANIFEST_LEN {
        return Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "too_large",
            "manifest file too large",
        ));
    }
    Ok(([(axum::http::header::CONTENT_TYPE, content_type)], bytes).into_response())
}

async fn manifest(State(st): S) -> Result<Response, ApiError> {
    serve_file(st.cfg.manifest_file.as_deref(), "application/json")
}

async fn manifest_signature(State(st): S) -> Result<Response, ApiError> {
    let sig = st
        .cfg
        .manifest_file
        .as_ref()
        .map(|_| st.cfg.manifest_signature_path());
    serve_file(sig.as_deref(), "application/pgp-signature")
}

/// The manifest signer's public key, for app setup (it checks the fingerprint the setup link
/// pins).
async fn manifest_signer(State(st): S) -> Result<Response, ApiError> {
    let bytes = st.signer_watch.file_bytes().ok_or_else(|| {
        err(
            StatusCode::NOT_FOUND,
            "not_found",
            "no manifest signer configured",
        )
    })?;
    Ok(([(header::CONTENT_TYPE, "application/pgp-keys")], bytes).into_response())
}

/// The CA that issued the relay's certificate, for app setup (it checks the SPKI hash the
/// setup link pins).
async fn relay_ca(State(st): S) -> Result<Response, ApiError> {
    serve_file(st.cfg.tls_ca.as_deref(), "application/x-pem-file")
}

// ---------- signer gate ----------

/// 503 `ManifestSignerUnusable` while the manifest signer is revoked or expired.
fn signer_gate(st: &AppState) -> Result<(), ApiError> {
    st.signer_watch.check().map_err(|reason| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "ManifestSignerUnusable",
            reason,
        )
    })
}

// ---------- errors ----------

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    kind: &'static str,
    detail: String,
}

fn err(status: StatusCode, kind: &'static str, detail: impl Into<String>) -> ApiError {
    ApiError {
        status,
        kind,
        detail: detail.into(),
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({"error": self.kind, "detail": self.detail})),
        )
            .into_response()
    }
}

impl From<relay_core::Error> for ApiError {
    fn from(e: relay_core::Error) -> Self {
        use relay_core::Error as E;
        let status = match &e {
            E::RelayAuth(_) | E::RequestSignatureInvalid => StatusCode::UNAUTHORIZED,
            E::KeyNotApproved | E::ClientRevoked => StatusCode::FORBIDDEN,
            E::RequestExpired => StatusCode::GONE,
            _ => StatusCode::BAD_REQUEST,
        };
        err(status, e.kind(), e.to_string())
    }
}

fn internal(e: impl std::fmt::Display) -> ApiError {
    tracing::error!(error = %e, "internal error");
    err(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Internal",
        "internal error",
    )
}

type ApiResult<T> = Result<T, ApiError>;

// ---------- authentication ----------

fn header<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

fn parse_auth(h: &HeaderMap) -> ApiResult<AuthHeaders> {
    Ok(AuthHeaders::parse(
        header(h, relay_auth::HEADER_KEY),
        header(h, relay_auth::HEADER_TIME),
        header(h, relay_auth::HEADER_NONCE),
        header(h, relay_auth::HEADER_SIGNATURE),
    )?)
}

fn path_and_query(uri: &OriginalUri) -> &str {
    uri.0.path_and_query().map(|p| p.as_str()).unwrap_or("/")
}

/// Verify the relay-auth headers against `key` (wire-format §8).
fn check_auth(
    st: &AppState,
    a: &AuthHeaders,
    method: &Method,
    uri: &OriginalUri,
    body: &[u8],
    key: &PublicKey,
) -> ApiResult<()> {
    let mut inner = st.lock();
    relay_auth::verify_relay_auth(
        a,
        method.as_str(),
        path_and_query(uri),
        body,
        key,
        now(),
        st.cfg.skew_secs,
        &mut inner.nonces,
    )
    .map_err(|e| {
        Metrics::inc(&st.metrics.auth_failures);
        ApiError::from(e)
    })
}

async fn authenticate_client(
    st: &AppState,
    h: &HeaderMap,
    m: &Method,
    uri: &OriginalUri,
    body: &[u8],
) -> ApiResult<ClientRecord> {
    let a = parse_auth(h)?;
    let Some(c) = db::client_by_fingerprint(&st.db, a.key.as_str())
        .await
        .map_err(internal)?
    else {
        Metrics::inc(&st.metrics.auth_failures);
        if db::client_key_revoked(&st.db, a.key.as_str(), now())
            .await
            .map_err(internal)?
        {
            return Err(client_revoked());
        }
        return Err(err(
            StatusCode::FORBIDDEN,
            "UnpairedClient",
            "key is not a paired client",
        ));
    };
    if manifest_revokes_client(st, &a.key) {
        db::delete_client(&st.db, &c.client_id)
            .await
            .map_err(internal)?;
        tracing::warn!(
            client_id = c.client_id,
            "client revoked in the manifest; deleted"
        );
        return Err(client_revoked());
    }
    let key = PublicKey::from_spki(&c.public_key).map_err(internal)?;
    check_auth(st, &a, m, uri, body, &key)?;
    db::touch_client(&st.db, &c.client_id, now() as i64)
        .await
        .map_err(internal)?;
    if !st.lock().allow(
        &format!("client:{}", c.client_id),
        st.cfg.client_calls_per_minute,
        now(),
    ) {
        return Err(err(
            StatusCode::TOO_MANY_REQUESTS,
            "RateLimited",
            "client rate limit",
        ));
    }
    Ok(c)
}

async fn authenticate_device(
    st: &AppState,
    h: &HeaderMap,
    m: &Method,
    uri: &OriginalUri,
    body: &[u8],
    id: &str,
) -> ApiResult<DeviceRecord> {
    let a = parse_auth(h)?;
    let Some(d) = db::device_by_auth_fingerprint(&st.db, a.key.as_str())
        .await
        .map_err(internal)?
    else {
        Metrics::inc(&st.metrics.auth_failures);
        return Err(err(
            StatusCode::UNAUTHORIZED,
            "UnknownDevice",
            "key is not a registered device",
        ));
    };
    if d.device_id != id {
        return Err(err(
            StatusCode::FORBIDDEN,
            "WrongDevice",
            "authenticated as a different device",
        ));
    }
    refuse_revoked_device(st, &d).await?;
    let key = PublicKey::from_spki(&d.auth_key).map_err(internal)?;
    check_auth(st, &a, m, uri, body, &key)?;
    if !st.lock().allow(
        &format!("device:{}", d.device_id),
        st.cfg.device_calls_per_minute,
        now(),
    ) {
        return Err(err(
            StatusCode::TOO_MANY_REQUESTS,
            "RateLimited",
            "device rate limit",
        ));
    }
    db::touch_device(&st.db, &d.device_id, now() as i64)
        .await
        .map_err(internal)?;
    Ok(d)
}

fn client_revoked() -> ApiError {
    err(
        StatusCode::FORBIDDEN,
        "ClientRevoked",
        "this client has been revoked",
    )
}

fn view(st: &AppState) -> crate::trust::View {
    st.manifest_check
        .view(&st.cfg, now(), st.signer_watch.signer().as_ref())
}

/// Whether the relay's valid manifest lists this client key in `revoked_clients`.
fn manifest_revokes_client(st: &AppState, fp: &Fingerprint) -> bool {
    matches!(view(st), crate::trust::View::Valid(m) if m.client_revoked(fp))
}

/// Whether the relay's valid manifest lists this device key in `revoked_devices`.
fn manifest_revokes_device(st: &AppState, fp: &Fingerprint) -> bool {
    matches!(view(st), crate::trust::View::Valid(m) if m.device_revoked(fp))
}

/// Refuse, and forget, a device whose key the manifest lists in `revoked_devices`, whichever of
/// its keys signed the call (wire-format §10, "Manifest revocations at the relay").
async fn refuse_revoked_device(st: &AppState, d: &DeviceRecord) -> ApiResult<()> {
    let Ok(fp) = Fingerprint::parse(&d.fingerprint) else {
        return Ok(());
    };
    if !matches!(view(st), crate::trust::View::Valid(m) if m.device_revoked(&fp)) {
        return Ok(());
    }
    db::delete_device(&st.db, &d.device_id)
        .await
        .map_err(internal)?;
    tracing::warn!(
        device_id = d.device_id,
        "device revoked in the manifest; deleted"
    );
    Err(err(
        StatusCode::FORBIDDEN,
        "DeviceRevoked",
        "this device has been revoked",
    ))
}

/// Authenticate a call signed with a device's admin-auth key (wire-format §8.5): a registered,
/// unrevoked device whose attestation an `attest` key in the current manifest signed (the
/// window isn't checked, so an expired device can still sync and renew).
async fn authenticate_admin(
    st: &AppState,
    h: &HeaderMap,
    m: &Method,
    uri: &OriginalUri,
    body: &[u8],
) -> ApiResult<DeviceRecord> {
    let a = parse_auth(h)?;
    let Some(d) = db::device_by_admin_fingerprint(&st.db, a.key.as_str())
        .await
        .map_err(internal)?
    else {
        Metrics::inc(&st.metrics.auth_failures);
        let device = db::device_by_auth_fingerprint(&st.db, a.key.as_str())
            .await
            .map_err(internal)?;
        return Err(if device.is_some() {
            err(
                StatusCode::FORBIDDEN,
                "AdminKeyRequired",
                "this call must be signed with the device's admin-auth key",
            )
        } else {
            err(
                StatusCode::UNAUTHORIZED,
                "UnknownDevice",
                "key is not a registered device's admin key",
            )
        });
    };
    refuse_revoked_device(st, &d).await?;
    match view(st) {
        crate::trust::View::Valid(mf) if !crate::trust::device_attested(&d, &mf) => {
            return Err(err(
                StatusCode::FORBIDDEN,
                "DeviceNotAttested",
                "the device's attestation is not signed by an attest key in the current manifest",
            ))
        }
        crate::trust::View::Invalid(_) => {
            return Err(err(
                StatusCode::SERVICE_UNAVAILABLE,
                "ManifestInvalid",
                "the relay's manifest copy is invalid",
            ))
        }
        _ => {}
    }
    let key = PublicKey::from_spki(d.admin_key.as_deref().unwrap_or_default()).map_err(internal)?;
    check_auth(st, &a, m, uri, body, &key)?;
    if !st.lock().allow(
        &format!("device:{}", d.device_id),
        st.cfg.device_calls_per_minute,
        now(),
    ) {
        return Err(err(
            StatusCode::TOO_MANY_REQUESTS,
            "RateLimited",
            "device rate limit",
        ));
    }
    db::touch_device(&st.db, &d.device_id, now() as i64)
        .await
        .map_err(internal)?;
    Ok(d)
}

/// Check a client grant against the relay's manifest (wire-format §12.2, steps 1-3) and its
/// `revoked_clients`. Without a configured manifest only the format is checked; devices verify
/// every grant themselves either way.
fn check_grant(st: &AppState, bytes: &[u8]) -> ApiResult<ClientGrant> {
    let g = match view(st) {
        crate::trust::View::Valid(m) => {
            let g = relay_core::verify_client_grant_signer(bytes, &m)?;
            if m.client_revoked(g.client_fingerprint()) {
                return Err(client_revoked());
            }
            g
        }
        crate::trust::View::Unconfigured => ClientGrant::decode(bytes)
            .map_err(|e| relay_core::Error::GrantInvalid(e.to_string()))?,
        crate::trust::View::Invalid(_) => {
            return Err(err(
                StatusCode::SERVICE_UNAVAILABLE,
                "ManifestInvalid",
                "the relay's manifest copy is invalid; it can't check grants",
            ))
        }
    };
    Ok(g)
}

fn b64d(s: &str, what: &str) -> ApiResult<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|_| {
            err(
                StatusCode::BAD_REQUEST,
                "BadBase64",
                format!("{what} is not base64"),
            )
        })
}

fn b64e(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn parse_req_id(s: &str) -> ApiResult<ReqId> {
    let bad = || {
        err(
            StatusCode::BAD_REQUEST,
            "BadRequestId",
            "request ids are 32 lowercase hex characters",
        )
    };
    if s.len() != 32 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(bad());
    }
    let mut id = [0u8; 16];
    hex::decode_to_slice(s, &mut id).map_err(|_| bad())?;
    Ok(id)
}

async fn audit(st: &AppState, e: AuditEvent) {
    if let Err(e) = db::audit(&st.db, &e).await {
        tracing::error!(error = %e, "audit write failed");
    }
}

/// Whether an operation's content must stay out of storage: for decrypts (and key agreement)
/// the request carries ciphertext and the response a sealed plaintext, so the audit log keeps
/// only metadata and hashes. Sign requests are logged in full (spec: audit log).
fn confidential(r: &SignedRequest) -> bool {
    !matches!(r.fields.op, relay_core::Op::Sign)
}

fn request_audit(event: &str, r: &SignedRequest) -> AuditEvent {
    let f = &r.fields;
    let keep = !confidential(r);
    AuditEvent {
        ts: now() as i64,
        event: event.into(),
        client_id: Some(f.client_id.clone()),
        req_id: Some(hex::encode(f.req_id)),
        key_fingerprint: Some(f.key_fingerprint.to_string()),
        op: Some(f.op.as_str().into()),
        mechanism: Some(f.mechanism.name().into()),
        host: Some(f.context.host.clone()),
        purpose: Some(f.context.purpose.clone()),
        consumer: Some(f.context.consumer.clone()),
        input_sha256: Some(hex::encode(Sha256::digest(&f.input))),
        detail: (!keep).then(|| format!("request_sha256={}", hex::encode(r.hash()))),
        request: keep.then(|| r.bytes().to_vec()),
        ..Default::default()
    }
}

fn ring(st: &Arc<AppState>, devices: Vec<DeviceRecord>) {
    {
        let mut inner = st.lock();
        for d in &devices {
            inner.wake(&d.device_id);
        }
    }
    for d in devices {
        let fut = st.notifier.ring(&d.device_id, &d.push);
        let st = st.clone();
        tokio::spawn(async move {
            match fut.await {
                Ok(()) => {}
                Err(crate::notify::PushError::Unregistered(e)) => {
                    Metrics::inc(&st.metrics.push_failures);
                    tracing::warn!(
                        device_id = d.device_id,
                        error = e,
                        "push token no longer valid; forgetting it"
                    );
                    if let Err(e) = db::clear_push(&st.db, &d.device_id).await {
                        tracing::error!(error = %e, "could not forget the push token");
                    }
                }
                Err(e) => {
                    Metrics::inc(&st.metrics.push_failures);
                    tracing::warn!(device_id = d.device_id, error = %e, "push failed");
                }
            }
        });
    }
}

#[derive(Deserialize)]
struct Wait {
    wait: Option<u64>,
}

fn wait_secs(st: &AppState, q: &Wait) -> u64 {
    q.wait.unwrap_or(0).min(st.cfg.long_poll_max_secs)
}

// ---------- handlers ----------

async fn metrics(State(st): S) -> impl IntoResponse {
    let (depth, pairings) = {
        let i = st.lock();
        (i.pending.len(), i.pairings.len())
    };
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        st.metrics
            .render(depth, pairings, st.signer_watch.check().is_ok()),
    )
}

/// `GET /v1/keys`: keys advertised by registered devices that this client was approved for.
async fn list_keys(
    State(st): S,
    h: HeaderMap,
    m: Method,
    uri: OriginalUri,
) -> ApiResult<Json<serde_json::Value>> {
    let c = authenticate_client(&st, &h, &m, &uri, b"").await?;
    if st.signer_watch.check().is_err() {
        return Ok(Json(json!({"keys": []})));
    }
    let devices = db::list_devices(&st.db).await.map_err(internal)?;
    let t = now();
    let view = st
        .manifest_check
        .view(&st.cfg, t, st.signer_watch.signer().as_ref());
    let mut keys: Vec<serde_json::Value> = Vec::new();
    for fp in &c.approved_keys {
        let holders: Vec<&DeviceRecord> = devices.iter().filter(|d| view.counts(d, fp)).collect();
        let Some(first) = holders.first() else {
            continue;
        };
        let k = first
            .keys
            .iter()
            .find(|k| &k.fingerprint == fp)
            .expect("advertised");
        let last_seen = holders.iter().map(|d| d.last_seen).max().unwrap_or(0);
        keys.push(json!({"public_key": k.public_key, "token": k.token, "devices": holders.len(), "last_seen": last_seen}));
    }
    Ok(Json(json!({"keys": keys})))
}

/// `POST /v1/requests`: early rejection, then queue and ring.
async fn submit_request(
    State(st): S,
    h: HeaderMap,
    m: Method,
    uri: OriginalUri,
    body: Bytes,
) -> ApiResult<Response> {
    let c = authenticate_client(&st, &h, &m, &uri, &body).await?;
    signer_gate(&st)?;
    if !st.lock().allow(
        &format!("client-requests:{}", c.client_id),
        st.cfg.client_requests_per_minute,
        now(),
    ) {
        Metrics::inc(&st.metrics.requests_rejected);
        return Err(err(
            StatusCode::TOO_MANY_REQUESTS,
            "RateLimited",
            "client request rate limit",
        ));
    }
    let approved: Vec<Fingerprint> = c
        .approved_keys
        .iter()
        .filter_map(|k| Fingerprint::parse(k).ok())
        .collect();
    let key = PublicKey::from_spki(&c.public_key).map_err(internal)?;
    let t = now();
    let req = match request::verify_for_relay(
        &body,
        &c.client_id,
        &key,
        &approved,
        t,
        st.cfg.skew_secs,
    ) {
        Ok(r) => r,
        Err(e) => {
            Metrics::inc(&st.metrics.requests_rejected);
            audit(
                &st,
                AuditEvent {
                    ts: t as i64,
                    event: "request_rejected".into(),
                    client_id: Some(c.client_id.clone()),
                    // Never the body: it may be a decrypt request.
                    detail: Some(format!(
                        "{e}; body_sha256={}",
                        hex::encode(Sha256::digest(&body))
                    )),
                    ..Default::default()
                },
            )
            .await;
            return Err(e.into());
        }
    };
    let f = &req.fields;
    if f.expires_at - f.created_at > st.cfg.max_ttl_secs {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "TtlTooLong",
            "expires_at exceeds the relay's max TTL",
        ));
    }
    let fp = f.key_fingerprint.to_string();
    let view = st
        .manifest_check
        .view(&st.cfg, t, st.signer_watch.signer().as_ref());
    let devices: Vec<DeviceRecord> = db::list_devices(&st.db)
        .await
        .map_err(internal)?
        .into_iter()
        .filter(|d| view.counts(d, &fp))
        .collect();
    if devices.is_empty() {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "NoDevice",
            "no registered device operates this key",
        ));
    }
    {
        let mut inner = st.lock();
        if inner.seen.contains_key(&f.req_id) {
            Metrics::inc(&st.metrics.requests_rejected);
            return Err(err(
                StatusCode::CONFLICT,
                "DuplicateRequestId",
                "request id already used",
            ));
        }
        if inner.pending_for_client(&c.client_id) >= st.cfg.max_pending_per_client {
            return Err(err(
                StatusCode::TOO_MANY_REQUESTS,
                "TooManyPending",
                "too many pending requests for this client",
            ));
        }
        inner.seen.insert(f.req_id, f.expires_at);
        inner.pending.insert(
            f.req_id,
            Pending {
                bytes: body.to_vec(),
                client_id: c.client_id.clone(),
                key_fingerprint: f.key_fingerprint.clone(),
                expires_at: f.expires_at,
                received_at: t,
                devices: devices.iter().map(|d| d.device_id.clone()).collect(),
                response: None,
                responded_by: None,
                done: watch::channel(false).0,
            },
        );
    }
    Metrics::inc(&st.metrics.requests_accepted);
    tracing::info!(
        client_id = c.client_id,
        req_id = hex::encode(f.req_id),
        key = fp,
        mechanism = f.mechanism.name(),
        purpose = f.context.purpose,
        "request queued"
    );
    audit(&st, request_audit("request", &req)).await;
    ring(&st, devices);
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"req_id": hex::encode(f.req_id)})),
    )
        .into_response())
}

/// `GET /v1/requests/{id}/result?wait=N`: long-poll for the attested response.
async fn get_result(
    State(st): S,
    Path(id): Path<String>,
    q: Query<Wait>,
    h: HeaderMap,
    m: Method,
    uri: OriginalUri,
) -> ApiResult<Response> {
    let c = authenticate_client(&st, &h, &m, &uri, b"").await?;
    let id = parse_req_id(&id)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(wait_secs(&st, &q));
    loop {
        signer_gate(&st)?;
        let mut rx = {
            let mut inner = st.lock();
            let Some(p) = inner
                .pending
                .get(&id)
                .filter(|p| p.client_id == c.client_id)
            else {
                return Err(err(
                    StatusCode::NOT_FOUND,
                    "UnknownRequest",
                    "no such pending request (expired or never queued)",
                ));
            };
            if p.response.is_some() {
                let p = inner.pending.remove(&id).expect("present");
                return Ok((
                    [(header::CONTENT_TYPE, "application/cbor")],
                    p.response.expect("present"),
                )
                    .into_response());
            }
            p.done.subscribe()
        };
        if *rx.borrow_and_update() {
            continue;
        }
        if tokio::time::timeout_at(deadline, rx.changed())
            .await
            .is_err()
        {
            return Ok(StatusCode::NO_CONTENT.into_response());
        }
    }
}

/// `POST /v1/requests/{id}/response`: the first valid response wins.
async fn post_response(
    State(st): S,
    Path(id): Path<String>,
    h: HeaderMap,
    m: Method,
    uri: OriginalUri,
    body: Bytes,
) -> ApiResult<Response> {
    signer_gate(&st)?;
    let a = parse_auth(&h)?;
    let d = db::device_by_auth_fingerprint(&st.db, a.key.as_str())
        .await
        .map_err(internal)?
        .ok_or_else(|| {
            err(
                StatusCode::UNAUTHORIZED,
                "UnknownDevice",
                "key is not a registered device",
            )
        })?;
    let d = authenticate_device(&st, &h, &m, &uri, &body, &d.device_id).await?;
    let id = parse_req_id(&id)?;
    let (req_bytes, received_at) = {
        let inner = st.lock();
        let p = inner.pending.get(&id).ok_or_else(|| {
            err(
                StatusCode::NOT_FOUND,
                "UnknownRequest",
                "no such pending request (expired?)",
            )
        })?;
        if p.response.is_some() {
            return Err(err(
                StatusCode::CONFLICT,
                "AlreadyAnswered",
                "another response was accepted first",
            ));
        }
        if !p.devices.contains(&d.device_id) {
            return Err(err(
                StatusCode::FORBIDDEN,
                "NotAddressed",
                "this device does not operate the requested key",
            ));
        }
        if now() > p.expires_at {
            return Err(err(
                StatusCode::GONE,
                "Expired",
                "request expired before this response",
            ));
        }
        (p.bytes.clone(), p.received_at)
    };
    let req = SignedRequest::decode(&req_bytes).map_err(internal)?;
    let device_key = PublicKey::from_spki(&d.device_key).map_err(internal)?;
    let resp = response::verify_for_relay(&body, &req, &device_key)?;
    {
        let mut inner = st.lock();
        let p = inner
            .pending
            .get_mut(&id)
            .ok_or_else(|| err(StatusCode::GONE, "Expired", "request expired"))?;
        if p.response.is_some() {
            return Err(err(
                StatusCode::CONFLICT,
                "AlreadyAnswered",
                "another response was accepted first",
            ));
        }
        p.response = Some(body.to_vec());
        p.responded_by = Some(d.device_id.clone());
        p.done.send_replace(true);
        // Withdraw from the other devices: wake them so they refetch and see it gone.
        let others: Vec<String> = p
            .devices
            .iter()
            .filter(|x| **x != d.device_id)
            .cloned()
            .collect();
        for o in others {
            inner.wake(&o);
        }
    }
    let status = resp.fields.status;
    match status {
        Status::Approved => Metrics::inc(&st.metrics.responses_approved),
        Status::Denied => Metrics::inc(&st.metrics.responses_denied),
        Status::Error => Metrics::inc(&st.metrics.responses_error),
    }
    st.metrics.approval_latency_seconds_sum.fetch_add(
        now().saturating_sub(received_at),
        std::sync::atomic::Ordering::Relaxed,
    );
    Metrics::inc(&st.metrics.approval_latency_count);
    let mut e = request_audit("response", &req);
    e.device_id = Some(d.device_id.clone());
    e.status = Some(status.as_str().into());
    e.reason = resp.fields.reason.map(|r| r.as_str().into());
    if confidential(&req) {
        e.detail = Some(format!(
            "response_sha256={}",
            hex::encode(Sha256::digest(&body))
        ));
    } else {
        e.response = Some(body.to_vec());
    }
    e.request = None;
    audit(&st, e).await;
    tracing::info!(
        device_id = d.device_id,
        req_id = hex::encode(id),
        status = status.as_str(),
        "response accepted"
    );
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingClientBody {
    client_id: String,
    public_key: String,
    host: String,
}

/// `POST /v1/clients/pending`: start pairing. Tailnet only, a few at a time, 10 minutes.
async fn pending_client(
    State(st): S,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    m: Method,
    uri: OriginalUri,
    body: Bytes,
) -> ApiResult<Response> {
    signer_gate(&st)?;
    let allowed = st
        .cfg
        .pairing_allowed_cidrs
        .iter()
        .filter_map(|c| Cidr::parse(c).ok())
        .any(|c| c.contains(peer.ip()));
    if !allowed {
        return Err(err(
            StatusCode::FORBIDDEN,
            "NotTailnet",
            "pairing is only accepted from allowed networks",
        ));
    }
    if !st.lock().allow("pairing", 10, now()) {
        return Err(err(
            StatusCode::TOO_MANY_REQUESTS,
            "RateLimited",
            "pairing rate limit",
        ));
    }
    let b: PendingClientBody = serde_json::from_slice(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, "BadJson", e.to_string()))?;
    relay_core::check_id(&b.client_id)?;
    if b.host.is_empty() || b.host.len() > 255 {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "BadHost",
            "host must be 1-255 bytes",
        ));
    }
    let spki = b64d(&b.public_key, "public_key")?;
    let key = PublicKey::from_spki(&spki)?;
    // Proof of possession: the call is signed by the key being registered.
    check_auth(&st, &parse_auth(&h)?, &m, &uri, &body, &key)?;
    let fp = key.fingerprint().to_string();
    if manifest_revokes_client(&st, key.fingerprint())
        || db::client_key_revoked(&st.db, &fp, now())
            .await
            .map_err(internal)?
    {
        return Err(client_revoked());
    }
    if let Some(existing) = db::client_by_id(&st.db, &b.client_id)
        .await
        .map_err(internal)?
    {
        return if existing.fingerprint == fp {
            Ok(Json(json!({"status": "approved"})).into_response())
        } else {
            Err(err(
                StatusCode::CONFLICT,
                "ClientIdTaken",
                "client id is paired with a different key; revoke it first",
            ))
        };
    }
    let code = relay_core::pairing::pairing_code(&spki);
    {
        let mut inner = st.lock();
        inner.pairings.retain(|p| p.fingerprint != fp);
        if inner.pairings.len() >= st.cfg.max_pending_pairings {
            return Err(err(
                StatusCode::TOO_MANY_REQUESTS,
                "TooManyPairings",
                "too many pending pairings",
            ));
        }
        inner.pairings.push(PendingPairing {
            client_id: b.client_id.clone(),
            public_key: spki,
            fingerprint: fp.clone(),
            host: b.host.clone(),
            code: code.clone(),
            received_at: now(),
        });
        inner.wake_all();
    }
    audit(
        &st,
        AuditEvent {
            ts: now() as i64,
            event: "pairing_pending".into(),
            client_id: Some(b.client_id.clone()),
            host: Some(b.host),
            detail: Some(fp),
            ..Default::default()
        },
    )
    .await;
    let devices = db::list_devices(&st.db).await.map_err(internal)?;
    ring(&st, devices);
    tracing::info!(client_id = b.client_id, code, "pairing pending");
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"status": "pending", "code": code})),
    )
        .into_response())
}

/// `GET /v1/clients/self`: a client learns whether it has been approved.
async fn client_self(
    State(st): S,
    h: HeaderMap,
    m: Method,
    uri: OriginalUri,
) -> ApiResult<Json<serde_json::Value>> {
    signer_gate(&st)?;
    let a = parse_auth(&h)?;
    if let Some(c) = db::client_by_fingerprint(&st.db, a.key.as_str())
        .await
        .map_err(internal)?
    {
        let key = PublicKey::from_spki(&c.public_key).map_err(internal)?;
        check_auth(&st, &a, &m, &uri, b"", &key)?;
        return Ok(Json(
            json!({"status": "approved", "client_id": c.client_id, "approved_keys": c.approved_keys}),
        ));
    }
    let pending = st
        .lock()
        .pairings
        .iter()
        .find(|p| p.fingerprint == a.key.as_str())
        .cloned();
    let Some(p) = pending else {
        return Err(err(
            StatusCode::NOT_FOUND,
            "Unknown",
            "no pairing for this key",
        ));
    };
    let key = PublicKey::from_spki(&p.public_key).map_err(internal)?;
    check_auth(&st, &a, &m, &uri, b"", &key)?;
    Ok(Json(
        json!({"status": "pending", "client_id": p.client_id, "code": p.code}),
    ))
}

#[derive(Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum ApprovalBody {
    /// A client grant signed by an attest key (wire-format §12.1), base64 CBOR.
    Grant { grant: String },
    /// Before grants: the fingerprint of the client key whose code the approver compared, and
    /// the keys chosen. Accepted until every approver signs grants.
    Legacy {
        fingerprint: String,
        keys: Vec<String>,
    },
}

/// `POST /v1/clients/{id}/approval`: an approver device approves a pending client for keys it
/// operates.
async fn approve_client(
    State(st): S,
    Path(client_id): Path<String>,
    h: HeaderMap,
    m: Method,
    uri: OriginalUri,
    body: Bytes,
) -> ApiResult<Response> {
    signer_gate(&st)?;
    let a = parse_auth(&h)?;
    let d = db::device_by_auth_fingerprint(&st.db, a.key.as_str())
        .await
        .map_err(internal)?
        .ok_or_else(|| {
            err(
                StatusCode::UNAUTHORIZED,
                "UnknownDevice",
                "key is not a registered device",
            )
        })?;
    let d = authenticate_device(&st, &h, &m, &uri, &body, &d.device_id).await?;
    let b: ApprovalBody = serde_json::from_slice(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, "BadJson", e.to_string()))?;
    let (fingerprint, keys, grant) = match b {
        ApprovalBody::Grant { grant } => {
            let bytes = b64d(&grant, "grant")?;
            let g = check_grant(&st, &bytes)?;
            if g.fields.client_id != client_id {
                return Err(err(
                    StatusCode::BAD_REQUEST,
                    "GrantInvalid",
                    "the grant names a different client id",
                ));
            }
            if g.fields.seq != 1 {
                return Err(err(
                    StatusCode::BAD_REQUEST,
                    "GrantInvalid",
                    "a pairing's grant has seq 1",
                ));
            }
            let keys = g.fields.keys.iter().map(|k| k.to_string()).collect();
            (g.client_fingerprint().to_string(), keys, Some(bytes))
        }
        ApprovalBody::Legacy { fingerprint, keys } => {
            // The person approving chooses keys from the manifest; they need not all be on
            // this device.
            if keys.is_empty() || keys.len() > 64 {
                return Err(err(StatusCode::BAD_REQUEST, "BadKeys", "approve 1-64 keys"));
            }
            for k in &keys {
                Fingerprint::parse(k)?;
            }
            (fingerprint, keys, None)
        }
    };
    let p = {
        let mut inner = st.lock();
        let pos = inner
            .pairings
            .iter()
            .position(|p| p.client_id == client_id && p.fingerprint == fingerprint)
            .ok_or_else(|| {
                err(
                    StatusCode::NOT_FOUND,
                    "NoPendingPairing",
                    "no pending pairing for that client and key",
                )
            })?;
        inner.pairings.remove(pos)
    };
    let rec = ClientRecord {
        client_id: p.client_id.clone(),
        public_key: p.public_key,
        fingerprint: p.fingerprint.clone(),
        host: p.host,
        approved_keys: keys.clone(),
        approved_by: d.device_id.clone(),
        created_at: now() as i64,
        grant_seq: u64::from(grant.is_some()),
        grant,
        last_seen: 0,
    };
    db::insert_client(&st.db, &rec)
        .await
        .map_err(|e| err(StatusCode::CONFLICT, "ClientExists", e.to_string()))?;
    audit(
        &st,
        AuditEvent {
            ts: now() as i64,
            event: "pairing_approved".into(),
            client_id: Some(p.client_id.clone()),
            device_id: Some(d.device_id.clone()),
            detail: Some(keys.join(",")),
            ..Default::default()
        },
    )
    .await;
    tracing::info!(
        client_id = p.client_id,
        device_id = d.device_id,
        "client approved"
    );
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceKeyBody {
    public_key: String,
    token: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceBody {
    device_id: String,
    device_key: String,
    /// A separate relay-auth key (base64 SPKI, P-256) and the device key's signature over its
    /// binding (wire-format §8.4). Without them the device key authenticates.
    #[serde(default)]
    auth_key: Option<String>,
    #[serde(default)]
    auth_key_sig: Option<String>,
    /// The biometric-gated admin-auth key (base64 SPKI, P-256) and the device key's signature
    /// over its binding (wire-format §8.5).
    #[serde(default)]
    admin_key: Option<String>,
    #[serde(default)]
    admin_key_sig: Option<String>,
    attestation: String,
    keys: Vec<DeviceKeyBody>,
    #[serde(default)]
    push: PushTarget,
    /// The signed setup link the app was set up from; required for a device id the relay
    /// does not hold (wire-format §11.3).
    #[serde(default)]
    setup_link: Option<String>,
}

/// `POST /v1/devices`: register or update a device. The call is signed by the device key in
/// the body; a device id stays bound to its first key until revoked.
async fn register_device(
    State(st): S,
    h: HeaderMap,
    m: Method,
    uri: OriginalUri,
    body: Bytes,
) -> ApiResult<Response> {
    signer_gate(&st)?;
    let b: DeviceBody = serde_json::from_slice(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, "BadJson", e.to_string()))?;
    relay_core::check_id(&b.device_id)?;
    let spki = b64d(&b.device_key, "device_key")?;
    let key = PublicKey::from_spki(&spki)?;
    if key.algorithm() != relay_core::Algorithm::P256 {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "BadDeviceKey",
            "device keys are P-256",
        ));
    }
    let auth_key = match (&b.auth_key, &b.auth_key_sig) {
        (Some(a), Some(s)) => {
            let auth = PublicKey::from_spki(&b64d(a, "auth_key")?)?;
            relay_core::relay_auth::verify_auth_key_binding(
                &key,
                &b.device_id,
                &auth,
                &b64d(s, "auth_key_sig")?,
            )
            .map_err(|e| err(StatusCode::BAD_REQUEST, "BadAuthKey", e.to_string()))?;
            auth
        }
        (None, None) => key.clone(),
        _ => {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "BadAuthKey",
                "auth_key and auth_key_sig come together",
            ))
        }
    };
    let admin_key = match (&b.admin_key, &b.admin_key_sig) {
        (Some(a), Some(s)) => {
            let admin = PublicKey::from_spki(&b64d(a, "admin_key")?)?;
            relay_core::relay_auth::verify_admin_key_binding(
                &key,
                &b.device_id,
                &admin,
                &b64d(s, "admin_key_sig")?,
            )
            .map_err(|e| err(StatusCode::BAD_REQUEST, "BadAdminKey", e.to_string()))?;
            if admin == auth_key || admin == key {
                return Err(err(
                    StatusCode::BAD_REQUEST,
                    "BadAdminKey",
                    "the admin-auth key must be a key of its own",
                ));
            }
            Some(admin)
        }
        (None, None) => None,
        _ => {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "BadAdminKey",
                "admin_key and admin_key_sig come together",
            ))
        }
    };
    if manifest_revokes_device(&st, key.fingerprint()) {
        return Err(err(
            StatusCode::FORBIDDEN,
            "DeviceRevoked",
            "this device has been revoked",
        ));
    }
    // The call is signed by the key that will authenticate this device from now on.
    check_auth(&st, &parse_auth(&h)?, &m, &uri, &body, &auth_key)?;
    let attestation = b64d(&b.attestation, "attestation")?;
    let stmt = AttestationStatement::decode(&attestation)?;
    if stmt.fields.device_key != key || stmt.fields.device_id != b.device_id {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "AttestationMismatch",
            "attestation names a different device or key",
        ));
    }
    // With a valid manifest, the attestation must be signed by one of its attest keys. Its
    // window is the clients' check: an expired device re-registers when it renews.
    if let crate::trust::View::Valid(mf) =
        st.manifest_check
            .view(&st.cfg, now(), st.signer_watch.signer().as_ref())
    {
        if let Err(e) = relay_core::attestation::verify_attestation_signer(&attestation, &mf) {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "AttestationInvalid",
                e.to_string(),
            ));
        }
    }
    if b.keys.len() > 64 {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "TooManyKeys",
            "at most 64 keys per device",
        ));
    }
    let mut keys = Vec::new();
    for k in b.keys {
        let pk = PublicKey::from_spki(&b64d(&k.public_key, "keys[].public_key")?)?;
        if k.token.is_empty() || k.token.len() > 32 {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "BadToken",
                "token must be 1-32 bytes",
            ));
        }
        keys.push(AdvertisedKey {
            fingerprint: pk.fingerprint().to_string(),
            public_key: b64e(pk.spki()),
            token: k.token,
        });
    }
    let fp = key.fingerprint().to_string();
    let existing = db::device_by_id(&st.db, &b.device_id)
        .await
        .map_err(internal)?;
    match &existing {
        Some(e) if e.fingerprint != fp => {
            return Err(err(
                StatusCode::CONFLICT,
                "DeviceIdTaken",
                "device id is bound to a different key; revoke it first",
            ));
        }
        None if db::list_devices(&st.db).await.map_err(internal)?.len() >= st.cfg.max_devices => {
            return Err(err(
                StatusCode::TOO_MANY_REQUESTS,
                "TooManyDevices",
                "device limit reached",
            ));
        }
        _ => {}
    }
    // A device id the relay does not hold, including a revoked one, is admitted only with the
    // setup link that names it (wire-format §11.3).
    let admit = match (&existing, st.signer_watch.signer()) {
        (None, Some(signer)) => {
            let link = b.setup_link.as_deref().ok_or_else(|| {
                err(
                    StatusCode::BAD_REQUEST,
                    "SetupLinkRequired",
                    "a new device registers with the setup link it was set up from",
                )
            })?;
            let l =
                relay_core::setup_link::verify_setup_link(link, &signer, now(), st.cfg.skew_secs)
                    .map_err(|e| err(StatusCode::BAD_REQUEST, e.kind(), e.to_string()))?;
            if l.device != b.device_id {
                return Err(err(
                    StatusCode::BAD_REQUEST,
                    "SetupLinkWrongDevice",
                    format!("the setup link is for device {}", l.device),
                ));
            }
            Some((l.id(), l.exp))
        }
        _ => None,
    };
    let t = now() as i64;
    let rec = DeviceRecord {
        device_id: b.device_id.clone(),
        device_key: spki,
        fingerprint: fp,
        auth_key: auth_key.spki().to_vec(),
        auth_fingerprint: auth_key.fingerprint().to_string(),
        admin_key: admin_key.as_ref().map(|k| k.spki().to_vec()),
        admin_fingerprint: admin_key.as_ref().map(|k| k.fingerprint().to_string()),
        attestation,
        keys,
        push: b.push,
        last_seen: t,
        created_at: existing.as_ref().map(|e| e.created_at).unwrap_or(t),
        setup_link_id: admit
            .as_ref()
            .map(|(id, _)| id.clone())
            .or_else(|| existing.as_ref().and_then(|e| e.setup_link_id.clone())),
    };
    match &admit {
        Some((_, exp)) => match db::admit_device(&st.db, &rec, *exp)
            .await
            .map_err(internal)?
        {
            Ok(()) => {}
            Err(db::AdmitError::LinkUsed) => {
                return Err(err(
                    StatusCode::BAD_REQUEST,
                    "SetupLinkUsed",
                    "this setup link was already used; make a new one with relayctl app-link",
                ))
            }
            Err(db::AdmitError::DeviceIdTaken) => {
                return Err(err(
                    StatusCode::CONFLICT,
                    "DeviceIdTaken",
                    "device id is bound to a different key; revoke it first",
                ))
            }
        },
        None => db::upsert_device(&st.db, &rec).await.map_err(internal)?,
    }
    audit(
        &st,
        AuditEvent {
            ts: t,
            event: "device_registered".into(),
            device_id: Some(rec.device_id.clone()),
            detail: Some(match &admit {
                Some((id, _)) => format!("{} keys; admitted by setup link {id}", rec.keys.len()),
                None => format!("{} keys", rec.keys.len()),
            }),
            ..Default::default()
        },
    )
    .await;
    tracing::info!(
        device_id = rec.device_id,
        keys = rec.keys.len(),
        "device registered"
    );
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// What `/pending` returns: requests addressed to this device, with the latest grant of each
/// requesting client, every live revocation, and pending pairings (wire-format §10).
async fn pending_for_device(st: &AppState, d: &DeviceRecord) -> ApiResult<serde_json::Value> {
    let t = now();
    let (requests, clients, pairings) = {
        let inner = st.lock();
        let mut clients: Vec<String> = Vec::new();
        let requests: Vec<String> = inner
            .pending
            .values()
            .filter(|p| {
                p.response.is_none() && p.expires_at >= t && p.devices.contains(&d.device_id)
            })
            .map(|p| {
                if !clients.contains(&p.client_id) {
                    clients.push(p.client_id.clone());
                }
                b64e(&p.bytes)
            })
            .collect();
        (requests, clients, inner.pairings.clone())
    };
    let mut grants = Vec::new();
    for id in clients {
        if let Some(g) = db::client_by_id(&st.db, &id)
            .await
            .map_err(internal)?
            .and_then(|c| c.grant)
        {
            grants.push(b64e(&g));
        }
    }
    let revocations: Vec<String> = db::live_revocations(&st.db, t)
        .await
        .map_err(internal)?
        .iter()
        .map(|r| b64e(&r.revocation))
        .collect();
    Ok(json!({
        "requests": requests,
        "grants": grants,
        "revocations": revocations,
        "pairings": pairings,
    }))
}

fn has_items(v: &serde_json::Value) -> bool {
    v["requests"].as_array().is_some_and(|a| !a.is_empty())
        || v["pairings"].as_array().is_some_and(|a| !a.is_empty())
}

/// `GET /v1/devices/{id}/pending?wait=N`: pending requests addressed to this device, and
/// pending pairings.
async fn device_pending(
    State(st): S,
    Path(id): Path<String>,
    q: Query<Wait>,
    h: HeaderMap,
    m: Method,
    uri: OriginalUri,
) -> ApiResult<Json<serde_json::Value>> {
    let d = authenticate_device(&st, &h, &m, &uri, b"", &id).await?;
    let mut rx = st.lock().device_channel(&d.device_id);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(wait_secs(&st, &q));
    if st.signer_watch.check().is_err() {
        // Nothing to hand out; wait out the poll so devices don't spin.
        tokio::time::sleep_until(deadline).await;
        return Ok(Json(
            json!({"requests": [], "grants": [], "revocations": [], "pairings": []}),
        ));
    }
    loop {
        rx.borrow_and_update();
        let v = pending_for_device(&st, &d).await?;
        if has_items(&v)
            || tokio::time::timeout_at(deadline, rx.changed())
                .await
                .is_err()
        {
            return Ok(Json(v));
        }
    }
}

/// `GET /v1/devices/{id}/ws`: a connected approver is told `{"type":"pending"}` whenever
/// something may be waiting; it then fetches `/pending`.
async fn device_ws(
    State(st): S,
    Path(id): Path<String>,
    ws: WebSocketUpgrade,
    h: HeaderMap,
    m: Method,
    uri: OriginalUri,
) -> ApiResult<Response> {
    let d = authenticate_device(&st, &h, &m, &uri, b"", &id).await?;
    let rx = st.lock().device_channel(&d.device_id);
    let initial = has_items(&pending_for_device(&st, &d).await?);
    Ok(ws.on_upgrade(move |socket| ws_loop(socket, rx, initial)))
}

async fn ws_loop(mut socket: WebSocket, mut rx: watch::Receiver<u64>, initial: bool) {
    const PING: Duration = Duration::from_secs(25);
    let msg = || Message::Text(r#"{"type":"pending"}"#.into());
    if initial && socket.send(msg()).await.is_err() {
        return;
    }
    loop {
        tokio::select! {
            changed = rx.changed() => {
                if changed.is_err() || socket.send(msg()).await.is_err() { return; }
            }
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return,
                _ => {}
            },
            _ = tokio::time::sleep(PING) => {
                if socket.send(Message::Ping(Vec::new().into())).await.is_err() { return; }
            }
        }
    }
}

// ---------- clients and approvers (admin key) ----------

/// `GET /v1/clients`: every client's latest grant, host and last seen, and every live
/// revocation (wire-format §10). Signed with the admin-auth key.
async fn list_clients(
    State(st): S,
    h: HeaderMap,
    m: Method,
    uri: OriginalUri,
) -> ApiResult<Json<serde_json::Value>> {
    signer_gate(&st)?;
    authenticate_admin(&st, &h, &m, &uri, b"").await?;
    let clients: Vec<serde_json::Value> = db::list_clients(&st.db)
        .await
        .map_err(internal)?
        .iter()
        .map(|c| {
            json!({
                "client_id": c.client_id,
                "host": c.host,
                "grant": c.grant.as_deref().map(b64e),
                "last_seen": c.last_seen,
            })
        })
        .collect();
    let revocations: Vec<String> = db::live_revocations(&st.db, now())
        .await
        .map_err(internal)?
        .iter()
        .map(|r| b64e(&r.revocation))
        .collect();
    Ok(Json(
        json!({"clients": clients, "revocations": revocations}),
    ))
}

/// `GET /v1/devices`: every approver's device key, attestation, keys, push kind and last
/// seen. Never a push token. Signed with the admin-auth key.
async fn list_devices(
    State(st): S,
    h: HeaderMap,
    m: Method,
    uri: OriginalUri,
) -> ApiResult<Json<serde_json::Value>> {
    signer_gate(&st)?;
    authenticate_admin(&st, &h, &m, &uri, b"").await?;
    let devices: Vec<serde_json::Value> = db::list_devices(&st.db)
        .await
        .map_err(internal)?
        .iter()
        .map(|d| {
            let push_kind = match d.push {
                PushTarget::None => "none",
                PushTarget::Ntfy { .. } => "ntfy",
                PushTarget::Apns { .. } => "apns",
                PushTarget::Fcm { .. } => "fcm",
            };
            json!({
                "device_id": d.device_id,
                "device_key": b64e(&d.device_key),
                "attestation": b64e(&d.attestation),
                "keys": d.keys.iter().map(|k| json!({"public_key": k.public_key, "token": k.token})).collect::<Vec<_>>(),
                "push_kind": push_kind,
                "last_seen": d.last_seen,
            })
        })
        .collect();
    Ok(Json(json!({"devices": devices})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantBody {
    grant: String,
}

/// `POST /v1/clients/{id}/grant`: a changed or renewed grant. Signed with the admin-auth key,
/// or with the relay-auth key for a renewal made during an approval (same keys and window).
async fn post_grant(
    State(st): S,
    Path(client_id): Path<String>,
    h: HeaderMap,
    m: Method,
    uri: OriginalUri,
    body: Bytes,
) -> ApiResult<Response> {
    signer_gate(&st)?;
    let a = parse_auth(&h)?;
    let admin = db::device_by_admin_fingerprint(&st.db, a.key.as_str())
        .await
        .map_err(internal)?
        .is_some();
    let d = if admin {
        authenticate_admin(&st, &h, &m, &uri, &body).await?
    } else {
        let d = db::device_by_auth_fingerprint(&st.db, a.key.as_str())
            .await
            .map_err(internal)?
            .ok_or_else(|| {
                err(
                    StatusCode::UNAUTHORIZED,
                    "UnknownDevice",
                    "key is not a registered device",
                )
            })?;
        authenticate_device(&st, &h, &m, &uri, &body, &d.device_id).await?
    };
    let b: GrantBody = serde_json::from_slice(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, "BadJson", e.to_string()))?;
    let bytes = b64d(&b.grant, "grant")?;
    let g = check_grant(&st, &bytes)?;
    let c = db::client_by_id(&st.db, &client_id)
        .await
        .map_err(internal)?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "UnknownClient", "no such client"))?;
    if g.fields.client_id != client_id || g.fields.client_key.spki() != c.public_key.as_slice() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "GrantInvalid",
            "the grant names a different client or client key",
        ));
    }
    if !admin {
        // Without the admin key, only a renewal: the stored grant's keys and window, unchanged.
        let same = c
            .grant
            .as_deref()
            .and_then(|b| ClientGrant::decode(b).ok())
            .is_some_and(|old| {
                old.fields.keys == g.fields.keys && old.fields.window_secs == g.fields.window_secs
            });
        if !same {
            return Err(err(
                StatusCode::FORBIDDEN,
                "AdminKeyRequired",
                "changing a client's keys or window needs the admin-auth key",
            ));
        }
    }
    let keys: Vec<String> = g.fields.keys.iter().map(|k| k.to_string()).collect();
    if !db::replace_grant(&st.db, &client_id, &bytes, g.fields.seq, &keys)
        .await
        .map_err(internal)?
    {
        return Err(err(
            StatusCode::CONFLICT,
            "GrantStale",
            format!(
                "the stored grant has seq {}; a new grant needs a higher one",
                c.grant_seq
            ),
        ));
    }
    audit(
        &st,
        AuditEvent {
            ts: now() as i64,
            event: "grant".into(),
            client_id: Some(client_id.clone()),
            device_id: Some(d.device_id.clone()),
            detail: Some(format!("seq {}; {}", g.fields.seq, keys.join(","))),
            ..Default::default()
        },
    )
    .await;
    tracing::info!(
        client_id,
        device_id = d.device_id,
        seq = g.fields.seq,
        "grant stored"
    );
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevocationBody {
    revocation: String,
}

/// `POST /v1/clients/{id}/revocation`: store a revocation, delete the client, and serve the
/// revocation until the last grant it cancels has expired. Signed with the admin-auth key.
async fn post_revocation(
    State(st): S,
    Path(client_id): Path<String>,
    h: HeaderMap,
    m: Method,
    uri: OriginalUri,
    body: Bytes,
) -> ApiResult<Response> {
    signer_gate(&st)?;
    let d = authenticate_admin(&st, &h, &m, &uri, &body).await?;
    let b: RevocationBody = serde_json::from_slice(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, "BadJson", e.to_string()))?;
    let bytes = b64d(&b.revocation, "revocation")?;
    let (r, max_window) = match view(&st) {
        crate::trust::View::Valid(mf) => (
            relay_core::verify_client_revocation(&bytes, &mf)?,
            mf.max_client_grant_window_secs,
        ),
        crate::trust::View::Unconfigured => (
            ClientRevocation::decode(&bytes)
                .map_err(|e| relay_core::Error::RevocationInvalid(e.to_string()))?,
            relay_core::manifest::MAX_CLIENT_GRANT_WINDOW,
        ),
        crate::trust::View::Invalid(_) => {
            return Err(err(
                StatusCode::SERVICE_UNAVAILABLE,
                "ManifestInvalid",
                "the relay's manifest copy is invalid; it can't check revocations",
            ))
        }
    };
    let fp = r.client_fingerprint().to_string();
    let t = now();
    // Served until the grant it cancels expires. Without a stored grant (an unknown client, or
    // one paired before grants), as long as any grant could last.
    let mut live_until = t.saturating_add(max_window);
    if let Some(c) = db::client_by_id(&st.db, &client_id)
        .await
        .map_err(internal)?
    {
        if c.fingerprint != fp {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "RevocationInvalid",
                "the revocation names a different client key",
            ));
        }
        if r.fields.seq < c.grant_seq {
            return Err(err(
                StatusCode::CONFLICT,
                "RevocationStale",
                format!(
                    "the client's grant has seq {}; the revocation cancels only up to {}",
                    c.grant_seq, r.fields.seq
                ),
            ));
        }
        if let Some(g) = c.grant.as_deref().and_then(|b| ClientGrant::decode(b).ok()) {
            live_until = g.fields.not_after;
        }
    }
    db::revoke_client(
        &st.db,
        &db::RevocationRecord {
            client_fingerprint: fp.clone(),
            seq: r.fields.seq,
            revocation: bytes,
            live_until,
        },
        t,
    )
    .await
    .map_err(internal)?;
    st.lock().wake_all();
    audit(
        &st,
        AuditEvent {
            ts: t as i64,
            event: "client_revoked".into(),
            client_id: Some(client_id.clone()),
            device_id: Some(d.device_id.clone()),
            detail: Some(format!("{fp} up to seq {}", r.fields.seq)),
            ..Default::default()
        },
    )
    .await;
    tracing::info!(client_id, device_id = d.device_id, "client revoked");
    Ok(StatusCode::NO_CONTENT.into_response())
}
