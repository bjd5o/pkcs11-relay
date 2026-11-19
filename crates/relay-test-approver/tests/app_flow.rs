//! The apps' path end to end against a real relay, all blocking, as the iPhone app runs it:
//! `relay-approver`'s engine and `RelayClient`, a device key that signs only responses and the
//! auth-key binding, a separate relay-auth key for every call, pairing, and one request.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use relay_approver::relay::RelayClient;
use relay_approver::{ApproverError, Checked, Engine, EngineConfig};
use relay_core::piv::Slot;
use relay_core::request::{RequestContext, UnsignedRequest};
use relay_core::response::{verify_response, Outcome};
use relay_core::seal::ReplyKey;
use relay_core::signing::{DeviceSigner, SoftwareKey};
use relay_core::{ManifestSigner, Mechanism, Op};
use relay_test_approver::fixtures::CLIENT_ID;
use relay_test_approver::relay::now;

const PIN: &[u8] = b"123456";

fn temp_dir() -> PathBuf {
    let mut b = [0u8; 8];
    relay_core::signing::random_bytes(&mut b);
    let d = std::env::temp_dir().join(format!("relay-app-flow-{}", hex::encode(b)));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn app_path_with_a_separate_auth_key() {
    let dir = temp_dir();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    relay_test_approver::fixtures::generate(
        &dir,
        dir.to_str().unwrap(),
        &url,
        &["127.0.0.0/8".into()],
        now(),
    )
    .unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let cfg = relay_server::config::Config {
        data_dir: dir.join("relay"),
        manifest_file: Some(dir.join("manifest.json")),
        manifest_signer: Some(dir.join("signer.asc")),
        tls_ca: Some(dir.join("relay-ca.pem")),
        // No keyserver in tests.
        signer_check: relay_server::config::SignerCheckConfig {
            keyserver: String::new(),
            ..Default::default()
        },
        hardware_attestation: relay_core::hw_attestation::PolicyConfig {
            roots_file: Some(dir.join("attestation-root.pem")),
        },
        ..Default::default()
    };
    let st = rt.block_on(relay_server::build_state(cfg)).unwrap();
    let (cert, key) = (dir.join("relay-cert.pem"), dir.join("relay-key.pem"));
    rt.spawn(async move { relay_server::serve_tls(listener, st, &cert, &key).await });

    let ca = std::fs::read(dir.join("relay-ca.pem")).unwrap();
    let signer =
        ManifestSigner::from_bytes(&std::fs::read(dir.join("signer.asc")).unwrap()).unwrap();
    let device: Arc<dyn DeviceSigner> = Arc::new(SoftwareKey::generate_p256()); // the Secure Enclave key
    let auth: Arc<dyn DeviceSigner> = Arc::new(SoftwareKey::generate_p256()); // the relay-auth key
    let rc = RelayClient::new(&url, Some(&ca), auth.clone()).unwrap();
    let link = relay_test_approver::fixtures::setup_link(&dir, &url, "phone", now()).unwrap();
    let policy = relay_core::hw_attestation::PolicyConfig {
        roots_file: Some(dir.join("attestation-root.pem")),
    }
    .policy()
    .unwrap();

    // The manifest, from the relay, verified as clients verify it.
    let start = Instant::now();
    let manifest = loop {
        match rc.fetch_manifest(
            &format!("{url}/v1/manifest"),
            &signer,
            &policy,
            None,
            now(),
            60,
        ) {
            Ok((m, _sig)) => break m,
            Err(e) if start.elapsed() < Duration::from_secs(10) => {
                let _ = e;
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => panic!("manifest: {e}"),
        }
    };

    // Enrollment: discover, attest, bind the auth key, register.
    let mut card = relay_softcard::SoftCard::load_dir(&dir.join("softcard-a"), PIN).unwrap();
    let engine = Engine::new(
        EngineConfig {
            device_id: "phone".into(),
            attestation_window_secs: 86_400,
            skew_secs: 60,
            renew_attestation: true,
        },
        manifest.clone(),
        device.clone(),
    );
    engine.discover(&mut card).unwrap();
    assert_eq!(engine.attest_key().unwrap().0, Slot::new(0x95).unwrap());
    engine
        .attest(&mut card, PIN, now(), now() + 86_400)
        .unwrap();
    let binding = engine.bind_auth_key(&auth.public_key()).unwrap();
    rc.register(
        &engine
            .registration(serde_json::Value::Null, Some(&binding), Some(&link))
            .unwrap(),
    )
    .unwrap();

    // Only the auth key authenticates this device now; the device key is not a relay identity.
    let by_device = RelayClient::new(&url, Some(&ca), device.clone()).unwrap();
    assert!(
        matches!(by_device.pending("phone", 0), Err(ApproverError::Relay(e)) if e.contains("401"))
    );
    // A binding for a different auth key is refused.
    let intruder: Arc<dyn DeviceSigner> = Arc::new(SoftwareKey::generate_p256());
    let r = RelayClient::new(&url, Some(&ca), intruder)
        .unwrap()
        .register(
            &engine
                .registration(serde_json::Value::Null, Some(&binding), Some(&link))
                .unwrap(),
        );
    assert!(matches!(r, Err(ApproverError::Relay(e)) if e.contains("401") || e.contains("400")));

    // Pairing: the client asks, the app shows the derived code and approves one key.
    let client_key =
        SoftwareKey::from_pkcs8_pem(&std::fs::read_to_string(dir.join("client.pem")).unwrap())
            .unwrap();
    let client_signer: Arc<dyn DeviceSigner> = Arc::new(
        SoftwareKey::from_pkcs8_pem(&std::fs::read_to_string(dir.join("client.pem")).unwrap())
            .unwrap(),
    );
    let client = RelayClient::new(&url, Some(&ca), client_signer).unwrap();
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    let body = serde_json::json!({"client_id": CLIENT_ID, "public_key": b64.encode(client_key.public_key().spki()), "host": "pi5.test"});
    assert!(client
        .call(
            "POST",
            "/v1/clients/pending",
            body.to_string().as_bytes(),
            "application/json"
        )
        .unwrap()
        .ok());
    let items = rc.pending("phone", 5).unwrap();
    assert_eq!(items.pairings.len(), 1);
    let view = engine.pairing_view(&items.pairings[0]).unwrap();
    assert_eq!(
        view.code,
        relay_core::pairing::pairing_code(client_key.public_key().spki())
    );
    let sign_ec = manifest
        .keys
        .iter()
        .find(|k| k.label == "sign-ec")
        .unwrap()
        .clone();
    // Approving signs the client's grant with the card's attest key.
    let post = engine
        .pairing_approval(
            &view,
            std::slice::from_ref(&sign_ec.fingerprint),
            3_600,
            &mut card,
            PIN,
            now(),
        )
        .unwrap();
    rc.approve_pairing(&post.path, &post.body).unwrap();

    // One request: the client submits, the app checks, approves with the PIN, posts; the client
    // verifies the response exactly as the provider does.
    let reply = ReplyKey::generate();
    let t = now();
    let u = UnsignedRequest::new(
        CLIENT_ID,
        &sign_ec,
        Op::Sign,
        Mechanism::EcdsaSha256,
        b"a release tag".to_vec(),
        RequestContext {
            host: "pi5.test".into(),
            purpose: "app flow".into(),
            consumer: "test".into(),
        },
        reply.public_bytes(),
        t,
        t + 60,
    )
    .unwrap();
    let req = u.clone().with_signature(client_key.sign(&u.to_be_signed()));
    let r = client
        .call("POST", "/v1/requests", req.bytes(), "application/cbor")
        .unwrap();
    assert_eq!(r.status, 202, "{}", String::from_utf8_lossy(&r.body));
    let items = rc.pending("phone", 5).unwrap();
    assert_eq!(items.requests.len(), 1);
    let Checked::Show(p) = engine.check_request(&items.requests[0], now()).unwrap() else {
        panic!("denied")
    };
    assert_eq!(p.view.key_label, "sign-ec");
    let a = engine.approve(&p, &mut card, PIN, now()).unwrap();
    assert!(a.approved);
    rc.post_response(a.req_id, &a.response).unwrap();
    let r = client
        .call(
            "GET",
            &format!(
                "/v1/requests/{}/result?wait=5",
                hex::encode(req.fields.req_id)
            ),
            b"",
            "application/octet-stream",
        )
        .unwrap();
    assert_eq!(r.status, 200);
    match verify_response(&r.body, req.bytes(), &manifest, now(), 60, reply).unwrap() {
        // CKM_ECDSA_SHA256 returns raw r || s over SHA-256(message).
        Outcome::Approved(sig) => sign_ec
            .public_key
            .verify_message(b"a release tag", &sig)
            .expect("the signature verifies with the manifest key"),
        o => panic!("{o:?}"),
    }
    drop(rt);
    let _ = std::fs::remove_dir_all(&dir);
}
