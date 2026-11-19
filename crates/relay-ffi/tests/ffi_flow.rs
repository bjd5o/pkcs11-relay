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
    manifest_signer_fingerprint, setup_from_link, Approver, ApproverConfig, CardChannel, DeviceKey,
    PlatformError, RelayError, SavedState, SetupOverrides, SignerIdentity,
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
    fn resets_on_end(&self) -> bool {
        true
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

    // Setup as the app does it: scan the link, check it and everything it points at, show it,
    // then build the config from what was checked. No keyserver in tests (closed port).
    let roots = std::fs::read_to_string(dir.join("attestation-root.pem")).unwrap();
    let link =
        relay_test_approver::fixtures::setup_link(&dir, &url, "brian-iphone", now()).unwrap();
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", l.local_addr().unwrap())
    };
    let overrides = SetupOverrides {
        keyserver_url: Some(closed),
        attestation_roots_pem: Some(roots.clone()),
    };
    let start = Instant::now();
    let preview = loop {
        match setup_from_link(link.clone(), overrides.clone()) {
            Ok(p) => break p,
            Err(_) if start.elapsed() < Duration::from_secs(10) => {
                std::thread::sleep(Duration::from_millis(100))
            }
            Err(e) => panic!("setup: {e}"),
        }
    };
    assert_eq!(preview.relay_url, url);
    assert_eq!(preview.device_id, "brian-iphone");
    assert_eq!(
        preview.relay_ca_pem.as_deref().map(str::trim),
        Some(
            std::fs::read_to_string(dir.join("relay-ca.pem"))
                .unwrap()
                .trim()
        )
    );
    assert_eq!(
        preview.signer_fingerprint,
        manifest_signer_fingerprint(std::fs::read_to_string(dir.join("signer.asc")).unwrap())
            .unwrap()
    );
    assert!(matches!(
        preview.identity,
        SignerIdentity::Unreachable { .. }
    ));
    assert_eq!(preview.max_attestation_window_secs, 7 * 86_400);
    assert!(preview.require_hardware_attestation);
    // Setup checks fail before anything is trusted.
    let expired =
        relay_test_approver::fixtures::setup_link(&dir, &url, "brian-iphone", now() - 8 * 86_400)
            .unwrap();
    assert!(setup_from_link(expired, overrides.clone())
        .unwrap_err()
        .to_string()
        .contains("expired"));
    let altered = link.replacen("brian-iphone", "brian-ipad", 1);
    assert!(setup_from_link(altered, overrides.clone()).is_err());

    let config = ApproverConfig {
        relay_url: preview.relay_url.clone(),
        relay_ca_pem: preview.relay_ca_pem.clone(),
        manifest_url: preview.manifest_url.clone(),
        manifest_signer: preview.manifest_signer.clone(),
        device_id: preview.device_id.clone(),
        attestation_window_secs: 86_400,
        skew_secs: 60,
        attestation_roots_pem: Some(roots),
        setup_link: Some(preview.link.clone()),
    };
    let device: Arc<dyn DeviceKey> = Arc::new(EnclaveKey(SoftwareKey::generate_p256()));
    let auth: Arc<dyn DeviceKey> = Arc::new(EnclaveKey(SoftwareKey::generate_p256()));
    let admin: Arc<dyn DeviceKey> = Arc::new(EnclaveKey(SoftwareKey::generate_p256()));
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
            Some(admin.clone()),
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

    // Push: the APNs token from the system re-registers the enrolled device with it.
    assert!(app.set_push_token("not hex".into()).is_err());
    app.set_push_token("ab".repeat(32)).unwrap();
    let db = rt
        .block_on(relay_server::db::open(&dir.join("relay")))
        .unwrap();
    let rec = rt
        .block_on(relay_server::db::device_by_id(&db, "brian-iphone"))
        .unwrap()
        .unwrap();
    assert!(
        matches!(rec.push, relay_server::db::PushTarget::Apns { ref token } if *token == "ab".repeat(32)),
        "{:?}",
        rec.push
    );

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
    // Approving a pairing signs the client's grant on the card: one more session, one PIN.
    let sessions = *nfc.sessions.lock().unwrap();
    app.approve_pairing(
        CLIENT_ID.into(),
        vec![sign_ec.fingerprint.clone()],
        3_600,
        nfc.clone(),
        PIN.to_vec(),
    )
    .unwrap();
    assert_eq!(*nfc.sessions.lock().unwrap(), sessions + 1);
    let c = &app.clients()[0];
    assert_eq!(
        (c.client_id.as_str(), c.state.as_str(), c.accepted),
        (CLIENT_ID, "valid", true)
    );
    assert_eq!(c.key_labels, vec!["sign-ec"]);
    assert_eq!(c.approved_by.as_deref(), Some("brian-iphone"));

    let signer =
        ManifestSigner::from_bytes(&std::fs::read(dir.join("signer.asc")).unwrap()).unwrap();
    let manifest = verify_manifest(
        &std::fs::read(dir.join("manifest.json")).unwrap(),
        &std::fs::read(dir.join("manifest.json.asc")).unwrap(),
        &signer,
        &relay_core::hw_attestation::PolicyConfig {
            roots_file: Some(dir.join("attestation-root.pem")),
        }
        .policy()
        .unwrap(),
        None,
        now(),
        60,
    )
    .unwrap();
    let key_by = |label: &str| {
        manifest
            .keys
            .iter()
            .find(|k| k.label == label)
            .unwrap()
            .clone()
    };
    let submit_with = |label: &str, msg: &[u8]| {
        let key = key_by(label);
        let reply = ReplyKey::generate();
        let t = now();
        let u = UnsignedRequest::new(
            CLIENT_ID,
            &key,
            Op::Sign,
            if label == "sign-rsa" {
                Mechanism::Sha256RsaPkcs
            } else {
                Mechanism::EcdsaSha256
            },
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
        let status = client
            .call("POST", "/v1/requests", req.bytes(), "application/cbor")
            .unwrap()
            .status;
        (req, reply, status)
    };
    let key = key_by("sign-ec");
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

    // Restart from saved state: still enrolled, the client's grant kept (accepted), and the
    // auth key still works.
    let saved = app.saved_state();
    assert!(
        saved.attestation.is_some()
            && saved.auth_binding.is_some()
            && saved.admin_binding.is_some()
            && saved.clients.is_empty()
            && saved.grants.len() == 1
            && saved.grants[0].accepted
            && saved.keys.iter().any(|k| k.slot == 0x95)
    );
    drop(app);
    let app = Approver::new(config.clone(), device, auth, Some(admin), saved).unwrap();
    assert!(app.status().attestation.is_some());
    let (req, reply) = submit(b"release v4");
    let id = app.poll(5).unwrap().requests[0].request_id.clone();
    assert!(app.approve(id, nfc.clone(), PIN.to_vec()).unwrap().approved);
    assert!(matches!(result(&req, reply), Outcome::Approved(_)));

    // ---------- client grants: a second approver ----------
    // An iPad set up after the client was paired, with an interchangeable copy of the card.
    let ipad_link =
        relay_test_approver::fixtures::setup_link(&dir, &url, "brian-ipad", now()).unwrap();
    let ipad_cfg = ApproverConfig {
        device_id: "brian-ipad".into(),
        setup_link: Some(ipad_link),
        ..config.clone()
    };
    let ipad_auth = SoftwareKey::generate_p256();
    let ipad_auth_pem = ipad_auth.to_pkcs8_pem().unwrap();
    let ipad_admin = SoftwareKey::generate_p256();
    let ipad_admin_pem = ipad_admin.to_pkcs8_pem().unwrap();
    let ipad = Approver::new(
        ipad_cfg,
        Arc::new(EnclaveKey(SoftwareKey::generate_p256())),
        Arc::new(EnclaveKey(ipad_auth)),
        Some(Arc::new(EnclaveKey(ipad_admin))),
        SavedState::default(),
    )
    .unwrap();
    let ipad_card = Arc::new(Nfc {
        card: Mutex::new(SoftCard::load_dir(&dir.join("softcard-a"), PIN).unwrap()),
        sessions: Mutex::new(0),
    });
    ipad.enroll(ipad_card.clone(), PIN.to_vec()).unwrap();
    // Phone stays quiet from here on unless it is the one being tested; requests reach both.
    let ipad_request = |msg: &[u8]| {
        let (req, reply) = submit(msg);
        let inbox = ipad.poll(5).unwrap();
        assert!(inbox.rejections.is_empty(), "{:?}", inbox.rejections);
        let v = inbox
            .requests
            .into_iter()
            .find(|r| r.request_id == hex::encode(req.fields.req_id))
            .expect("shown on the iPad");
        (req, reply, v)
    };

    // The client's first request on the iPad: verified from its grant alone, shown with the
    // first-request notice. Denying leaves it unaccepted.
    let (req, reply, v) = ipad_request(b"ipad 1");
    let n = v.notice.clone().expect("first-request notice");
    assert!(n.first_on_device && n.lapsed_since.is_none());
    assert_eq!(
        (n.approved_by.as_str(), n.key_labels.clone()),
        ("brian-iphone", vec!["sign-ec".to_string()])
    );
    ipad.deny(v.request_id).unwrap();
    assert!(matches!(
        result(&req, reply),
        Outcome::Denied(Some(Reason::UserDenied))
    ));
    // Still not accepted: the next request carries the notice again; approving accepts it.
    let (req, reply, v) = ipad_request(b"ipad 2");
    assert!(v.notice.as_ref().is_some_and(|n| n.first_on_device));
    assert!(
        ipad.approve(v.request_id, ipad_card.clone(), PIN.to_vec())
            .unwrap()
            .approved
    );
    assert!(matches!(result(&req, reply), Outcome::Approved(_)));
    let (req, reply, v) = ipad_request(b"ipad 3");
    assert!(v.notice.is_none(), "accepted: no notice");
    assert!(
        ipad.approve(v.request_id, ipad_card.clone(), PIN.to_vec())
            .unwrap()
            .approved
    );
    assert!(matches!(result(&req, reply), Outcome::Approved(_)));
    let _ = app.poll(1); // drain the phone's copies

    // The Clients and Approvers screens (admin key).
    assert!(ipad.sync_clients().unwrap().is_empty());
    let c = ipad
        .clients()
        .into_iter()
        .find(|c| c.client_id == CLIENT_ID)
        .unwrap();
    assert!(c.accepted && c.state == "valid");
    assert_eq!(c.host.as_deref(), Some("pi5.test"));
    let approvers = ipad.approvers().unwrap();
    assert_eq!(
        approvers
            .iter()
            .map(|a| (
                a.device_id.as_str(),
                a.this_device,
                a.attestation_state.as_str()
            ))
            .collect::<Vec<_>>(),
        vec![
            ("brian-ipad", true, "valid"),
            ("brian-iphone", false, "valid")
        ]
    );
    // The listings refuse the relay-auth key (403 AdminKeyRequired) and clients.
    let by_auth_key = relay_approver::relay::RelayClient::new(
        &url,
        Some(&std::fs::read(dir.join("relay-ca.pem")).unwrap()),
        Arc::new(SoftwareKey::from_pkcs8_pem(&ipad_auth_pem).unwrap()),
    )
    .unwrap();
    for path in ["/v1/clients", "/v1/devices"] {
        let r = by_auth_key.call("GET", path, b"", "x").unwrap();
        assert_eq!(r.status, 403, "{path}");
        assert_eq!(r.json()["error"], "AdminKeyRequired", "{path}");
        let r = client.call("GET", path, b"", "x").unwrap();
        assert_eq!(r.status, 401, "{path}: a client key is no device's");
    }

    // The relay checks posted grants: a forged one is refused, an old one is stale, and the
    // relay-auth key may post only a plain renewal (so it gets as far as the staleness check).
    let by_admin_key = relay_approver::relay::RelayClient::new(
        &url,
        Some(&std::fs::read(dir.join("relay-ca.pem")).unwrap()),
        Arc::new(SoftwareKey::from_pkcs8_pem(&ipad_admin_pem).unwrap()),
    )
    .unwrap();
    let listed = by_admin_key
        .call("GET", "/v1/clients", b"", "x")
        .unwrap()
        .json();
    let current = listed["clients"][0]["grant"].as_str().unwrap().to_string();
    let mut forged = b64.decode(&current).unwrap();
    let n = forged.len();
    forged[n - 1] ^= 1; // inside the signature
    let path = format!("/v1/clients/{CLIENT_ID}/grant");
    let post = |c: &relay_approver::relay::RelayClient, g: &str| {
        let body = serde_json::json!({"grant": g});
        let r = c
            .call(
                "POST",
                &path,
                body.to_string().as_bytes(),
                "application/json",
            )
            .unwrap();
        (
            r.status,
            r.json()["error"].as_str().unwrap_or("").to_string(),
        )
    };
    assert_eq!(
        post(&by_admin_key, &b64.encode(&forged)),
        (400, "GrantInvalid".into())
    );
    assert_eq!(post(&by_admin_key, &current), (409, "GrantStale".into()));
    assert_eq!(post(&by_auth_key, &current), (409, "GrantStale".into()));

    // Change keys on the iPad: a grant with seq 2; the phone follows it with the next request.
    let sign_rsa = app
        .manifest_keys()
        .into_iter()
        .find(|k| k.label == "sign-rsa")
        .unwrap();
    ipad.change_client(
        CLIENT_ID.into(),
        vec![sign_ec.fingerprint.clone(), sign_rsa.fingerprint.clone()],
        3_600,
        ipad_card.clone(),
        PIN.to_vec(),
    )
    .unwrap();
    let (req, reply, status) = submit_with("sign-rsa", b"rsa after the change");
    assert_eq!(status, 202, "the relay routes the newly granted key");
    let inbox = app.poll(5).unwrap();
    let v = inbox
        .requests
        .iter()
        .find(|r| r.request_id == hex::encode(req.fields.req_id))
        .expect("the phone follows the new grant");
    assert!(
        v.notice.is_none(),
        "the phone accepted this client at pairing"
    );
    assert!(
        app.approve(v.request_id.clone(), nfc.clone(), PIN.to_vec())
            .unwrap()
            .approved
    );
    assert!(matches!(result(&req, reply), Outcome::Approved(_)));
    let phone_view = app
        .clients()
        .into_iter()
        .find(|c| c.client_id == CLIENT_ID)
        .unwrap();
    assert_eq!(phone_view.key_labels.len(), 2);
    let _ = ipad.poll(1);

    // Revoke on the iPad: the relay refuses the client at once, and the phone drops it on
    // its next poll.
    ipad.revoke_client(CLIENT_ID.into(), ipad_card.clone(), PIN.to_vec())
        .unwrap();
    assert!(ipad.clients().iter().all(|c| c.client_id != CLIENT_ID));
    let (_, _, status) = submit_with("sign-ec", b"after the revocation");
    assert_eq!(status, 403);
    let _ = app.poll(1);
    assert!(app.clients().iter().all(|c| c.client_id != CLIENT_ID));
    // Pairing the same key again is refused while the revocation is live.
    assert_eq!(
        client
            .call(
                "POST",
                "/v1/clients/pending",
                body.to_string().as_bytes(),
                "application/json"
            )
            .unwrap()
            .status,
        403
    );

    drop(rt);
    let _ = std::fs::remove_dir_all(&dir);
}
