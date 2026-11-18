//! The UniFFI surface driven exactly as the Swift app drives it, with Rust stand-ins for the
//! two platform traits (Secure Enclave keys, an NFC card that powers down after each session),
//! against a real relay: enrollment, pairing, approval with a PIN, denial, a wrong PIN, saved
//! state across a restart.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use relay_core::piv::CardTransport;
use relay_core::request::{RequestContext, UnsignedRequest};
use relay_core::response::{verify_response, Outcome, Reason};
use relay_core::seal::ReplyKey;
use relay_core::signing::SoftwareKey;
use relay_core::{verify_manifest, ManifestSigner, Mechanism, Op};
use relay_ffi::{
    Approver, ApproverConfig, CardChannel, DeviceKey, PlatformError, RelayError, SavedState,
};
use relay_softcard::SoftCard;
use relay_test_approver::fixtures::CLIENT_ID;
use relay_test_approver::relay::now;

const PIN: &[u8] = b"123456";

struct EnclaveKey(SoftwareKey);
impl DeviceKey for EnclaveKey {
    fn public_key(&self) -> Vec<u8> {
        self.0.public_key().spki().to_vec()
    }
    fn sign(&self, message: Vec<u8>) -> Result<Vec<u8>, PlatformError> {
        Ok(self.0.sign(&message).to_vec())
    }
}

/// An NFC tap: the card is reset (powered down) when the session ends.
struct Nfc {
    card: Mutex<SoftCard>,
    sessions: Mutex<usize>,
}
impl CardChannel for Nfc {
    fn begin_session(&self) -> Result<(), PlatformError> {
        *self.sessions.lock().unwrap() += 1;
        Ok(())
    }
    fn transmit(&self, apdu: Vec<u8>) -> Result<Vec<u8>, PlatformError> {
        self.card
            .lock()
            .unwrap()
            .transmit(&apdu)
            .map_err(|e| PlatformError::Failed {
                message: e.to_string(),
            })
    }
    fn end_session(&self) {
        self.card.lock().unwrap().reset();
    }
}

fn temp_dir() -> PathBuf {
    let mut b = [0u8; 8];
    relay_core::signing::random_bytes(&mut b);
    let d = std::env::temp_dir().join(format!("relay-ffi-{}", hex::encode(b)));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn the_app_surface_end_to_end() {
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
        ..Default::default()
    };
    let st = rt.block_on(relay_server::build_state(cfg)).unwrap();
    let (cert, key) = (dir.join("relay-cert.pem"), dir.join("relay-key.pem"));
    rt.spawn(async move { relay_server::serve_tls(listener, st, &cert, &key).await });

    let config = ApproverConfig {
        relay_url: url.clone(),
        relay_ca_pem: Some(std::fs::read_to_string(dir.join("relay-ca.pem")).unwrap()),
        manifest_url: format!("{url}/v1/manifest"),
        manifest_signer: std::fs::read_to_string(dir.join("signer.asc")).unwrap(),
        device_id: "brian-iphone".into(),
        attestation_window_secs: 86_400,
        skew_secs: 60,
        require_hardware_attestation: true,
        attestation_roots_pem: Some(
            std::fs::read_to_string(dir.join("attestation-root.pem")).unwrap(),
        ),
    };
    let device: Arc<dyn DeviceKey> = Arc::new(EnclaveKey(SoftwareKey::generate_p256()));
    let auth: Arc<dyn DeviceKey> = Arc::new(EnclaveKey(SoftwareKey::generate_p256()));
    let nfc = Arc::new(Nfc {
        card: Mutex::new(SoftCard::load_dir(&dir.join("softcard-a"), PIN).unwrap()),
        sessions: Mutex::new(0),
    });

    let start = Instant::now();
    let app = loop {
        match Approver::new(
            config.clone(),
            device.clone(),
            auth.clone(),
            SavedState::default(),
        ) {
            Ok(a) => break a,
            Err(e) if start.elapsed() < Duration::from_secs(10) => {
                let _ = e;
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => panic!("{e}"),
        }
    };
    assert!(app.status().attestation.is_none());

    // Enrollment: one tap, one PIN.
    let a = app.enroll(nfc.clone(), PIN.to_vec()).unwrap();
    assert_eq!(a.not_after - a.not_before, 86_400);
    assert!(app.status().keys.iter().any(|k| k.label == "sign-ec"));

    // Pairing.
    let client_key =
        SoftwareKey::from_pkcs8_pem(&std::fs::read_to_string(dir.join("client.pem")).unwrap())
            .unwrap();
    let client = relay_approver::relay::RelayClient::new(
        &url,
        Some(&std::fs::read(dir.join("relay-ca.pem")).unwrap()),
        Arc::new(
            SoftwareKey::from_pkcs8_pem(&std::fs::read_to_string(dir.join("client.pem")).unwrap())
                .unwrap(),
        ),
    )
    .unwrap();
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
    let inbox = app.poll(5).unwrap();
    assert_eq!(inbox.pairings.len(), 1);
    assert_eq!(
        inbox.pairings[0].code,
        relay_core::pairing::pairing_code(client_key.public_key().spki())
    );
    let sign_ec = app
        .manifest_keys()
        .into_iter()
        .find(|k| k.label == "sign-ec")
        .unwrap();
    app.approve_pairing(CLIENT_ID.into(), vec![sign_ec.fingerprint.clone()])
        .unwrap();

    let signer =
        ManifestSigner::from_bytes(&std::fs::read(dir.join("signer.asc")).unwrap()).unwrap();
    let manifest = verify_manifest(
        &std::fs::read(dir.join("manifest.json")).unwrap(),
        &std::fs::read(dir.join("manifest.json.asc")).unwrap(),
        &signer,
        &relay_core::hw_attestation::PolicyConfig {
            require: true,
            roots_file: Some(dir.join("attestation-root.pem")),
        }
        .policy()
        .unwrap(),
        None,
        now(),
        60,
    )
    .unwrap();
    let key = manifest
        .keys
        .iter()
        .find(|k| k.label == "sign-ec")
        .unwrap()
        .clone();
    let submit = |msg: &[u8]| {
        let reply = ReplyKey::generate();
        let t = now();
        let u = UnsignedRequest::new(
            CLIENT_ID,
            &key,
            Op::Sign,
            Mechanism::EcdsaSha256,
            msg.to_vec(),
            RequestContext {
                host: "pi5.test".into(),
                purpose: "ffi".into(),
                consumer: "test".into(),
            },
            reply.public_bytes(),
            t,
            t + 60,
        )
        .unwrap();
        let req = u.clone().with_signature(client_key.sign(&u.to_be_signed()));
        assert_eq!(
            client
                .call("POST", "/v1/requests", req.bytes(), "application/cbor")
                .unwrap()
                .status,
            202
        );
        (req, reply)
    };
    let result = |req: &relay_core::request::SignedRequest, reply: ReplyKey| {
        let r = client
            .call(
                "GET",
                &format!(
                    "/v1/requests/{}/result?wait=5",
                    hex::encode(req.fields.req_id)
                ),
                b"",
                "x",
            )
            .unwrap();
        assert_eq!(r.status, 200);
        verify_response(&r.body, req.bytes(), &manifest, now(), 60, reply).unwrap()
    };

    // Approve with the PIN: one card session.
    let (req, reply) = submit(b"release v1");
    let inbox = app.poll(5).unwrap();
    assert_eq!(inbox.requests.len(), 1);
    let v = &inbox.requests[0];
    assert_eq!(
        (v.key_label.as_str(), v.claimed_purpose.as_str()),
        ("sign-ec", "ffi")
    );
    let sessions = *nfc.sessions.lock().unwrap();
    let o = app
        .approve(v.request_id.clone(), nfc.clone(), PIN.to_vec())
        .unwrap();
    assert!(o.approved && o.card_error.is_none());
    assert_eq!(*nfc.sessions.lock().unwrap(), sessions + 1);
    assert!(matches!(result(&req, reply), Outcome::Approved(_)));
    assert!(matches!(
        app.approve(v.request_id.clone(), nfc.clone(), PIN.to_vec()),
        Err(RelayError::Unknown)
    ));

    // Deny.
    let (req, reply) = submit(b"release v2");
    let id = app.poll(5).unwrap().requests[0].request_id.clone();
    app.deny(id).unwrap();
    assert!(matches!(
        result(&req, reply),
        Outcome::Denied(Some(Reason::UserDenied))
    ));

    // A wrong PIN: a signed error, then no card operation until the person retries.
    let (req, reply) = submit(b"release v3");
    let id = app.poll(5).unwrap().requests[0].request_id.clone();
    let retries = nfc.card.lock().unwrap().pin_retries();
    let o = app.approve(id, nfc.clone(), b"000000".to_vec()).unwrap();
    assert!(!o.approved && o.card_error.is_some());
    assert!(matches!(
        result(&req, reply),
        Outcome::Error(Some(Reason::WrongPin))
    ));
    assert!(app.status().pin_failed);
    assert_eq!(nfc.card.lock().unwrap().pin_retries(), retries - 1);
    app.clear_pin_failure();

    // Restart from saved state: still enrolled and paired, and the auth key still works.
    let saved = app.saved_state();
    assert!(
        saved.attestation.is_some()
            && saved.auth_binding.is_some()
            && saved.clients.len() == 1
            && saved.keys.iter().any(|k| k.slot == 0x95)
    );
    drop(app);
    let app = Approver::new(config, device, auth, saved).unwrap();
    assert!(app.status().attestation.is_some());
    let (req, reply) = submit(b"release v4");
    let id = app.poll(5).unwrap().requests[0].request_id.clone();
    assert!(app.approve(id, nfc.clone(), PIN.to_vec()).unwrap().approved);
    assert!(matches!(result(&req, reply), Outcome::Approved(_)));

    drop(rt);
    let _ = std::fs::remove_dir_all(&dir);
}
