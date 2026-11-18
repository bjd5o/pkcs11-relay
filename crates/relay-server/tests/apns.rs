//! The APNs sender against a local HTTP/2 stub (docs/milestone-5b.md, 5.7).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::Router;
use base64::Engine as _;
use relay_core::signing::SoftwareKey;
use relay_server::notify::{ApnsError, ApnsNotifier, APNS_PAYLOAD};

#[derive(Default, Clone)]
struct Seen {
    calls: Arc<Mutex<Vec<(String, HeaderMap, String)>>>,
}

async fn device(
    State(seen): State<Seen>,
    Path(token): Path<String>,
    headers: HeaderMap,
    body: String,
) -> (StatusCode, String) {
    seen.calls
        .lock()
        .unwrap()
        .push((token.clone(), headers, body));
    match &token[..2] {
        "aa" => (StatusCode::OK, String::new()),
        "bb" => (StatusCode::GONE, r#"{"reason":"Unregistered"}"#.into()),
        "cc" => (
            StatusCode::BAD_REQUEST,
            r#"{"reason":"BadDeviceToken"}"#.into(),
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            r#"{"reason":"InternalServerError"}"#.into(),
        ),
    }
}

fn b64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .unwrap()
}

#[tokio::test]
async fn apns_requests_are_authenticated_content_free_and_their_answers_handled() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let seen = Seen::default();
    let app = Router::new()
        .route("/3/device/{token}", post(device))
        .with_state(seen.clone());
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum_server::from_tcp(listener)
            .unwrap()
            .serve(app.into_make_service())
            .await
    });

    let key = SoftwareKey::generate_p256();
    let pem = key.to_pkcs8_pem().unwrap();
    let apns = ApnsNotifier::new(
        &pem,
        "KEY1234567".into(),
        "TEAM123456".into(),
        "sh.bjd.relay-approver".into(),
        "sandbox",
        Some(format!("http://{addr}")),
        120,
    )
    .unwrap();
    let now = 1_795_000_000;
    let ok = "aa".repeat(32);
    apns.send(&ok, now).await.unwrap();

    let (token, h, body) = seen.calls.lock().unwrap()[0].clone();
    assert_eq!(token, ok);
    assert_eq!(body, APNS_PAYLOAD);
    assert!(!body.contains("unseal") && body.contains("1 pending request"));
    assert_eq!(h["apns-topic"], "sh.bjd.relay-approver");
    assert_eq!(h["apns-push-type"], "alert");
    assert_eq!(h["apns-priority"], "10");
    assert_eq!(h["apns-expiration"], (now + 120).to_string().as_str());
    // The provider token: ES256 over header.claims, verifiable with the key's public half.
    let jwt = h["authorization"]
        .to_str()
        .unwrap()
        .strip_prefix("bearer ")
        .unwrap()
        .to_string();
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3);
    let header: serde_json::Value = serde_json::from_slice(&b64(parts[0])).unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&b64(parts[1])).unwrap();
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["kid"], "KEY1234567");
    assert_eq!(claims["iss"], "TEAM123456");
    assert_eq!(claims["iat"], now);
    key.public_key()
        .verify_message(
            format!("{}.{}", parts[0], parts[1]).as_bytes(),
            &b64(parts[2]),
        )
        .unwrap();

    // Reused for 30 minutes, then refreshed.
    assert_eq!(apns.token(now + 1_799), jwt);
    assert_ne!(apns.token(now + 1_800), jwt);

    // Answers: a dead token is forgotten; anything else is a plain failure.
    assert!(matches!(
        apns.send(&"bb".repeat(32), now).await,
        Err(ApnsError::Unregistered(_))
    ));
    assert!(matches!(
        apns.send(&"cc".repeat(32), now).await,
        Err(ApnsError::Unregistered(_))
    ));
    assert!(matches!(
        apns.send(&"dd".repeat(32), now).await,
        Err(ApnsError::Failed(_))
    ));
    assert!(matches!(
        apns.send("not-hex", now).await,
        Err(ApnsError::Unregistered(_))
    ));
    assert_eq!(
        seen.calls.lock().unwrap().len(),
        4,
        "an invalid token is never sent"
    );

    // Configuration errors.
    assert!(ApnsNotifier::new(
        &pem,
        "k".into(),
        "t".into(),
        "b".into(),
        "staging",
        None,
        120
    )
    .is_err());
    let ed = SoftwareKey::generate_ed25519().to_pkcs8_pem().unwrap();
    assert!(ApnsNotifier::new(
        &ed,
        "k".into(),
        "t".into(),
        "b".into(),
        "sandbox",
        None,
        120
    )
    .is_err());
}
