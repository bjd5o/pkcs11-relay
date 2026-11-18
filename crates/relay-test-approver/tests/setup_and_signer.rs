//! The relay's setup-link admission and its watch on the manifest signer (wire-format §11.3,
//! §11.4), against a real relay. Failure handling row: "Manifest signer revoked or expired
//! (seen by the relay)".

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use relay_approver::relay::RelayClient;
use relay_approver::{Engine, EngineConfig};
use relay_core::setup_link::SetupLinkDraft;
use relay_core::signing::{DeviceSigner, SoftwareKey};
use relay_core::{HardwarePolicy, ManifestSigner, PgpSecretKey};
use relay_server::signer_watch::{Lookup, SignerWatch, Status};
use relay_test_approver::fixtures::setup_link;
use relay_test_approver::relay::now;

const PIN: &[u8] = b"123456";

fn temp_dir(tag: &str) -> PathBuf {
    let mut b = [0u8; 8];
    relay_core::signing::random_bytes(&mut b);
    let d = std::env::temp_dir().join(format!("relay-{tag}-{}", hex::encode(b)));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn relay_config(dir: &Path, signer_file: &Path) -> relay_server::config::Config {
    relay_server::config::Config {
        data_dir: dir.join("relay"),
        manifest_file: Some(dir.join("manifest.json")),
        manifest_signer: Some(signer_file.to_path_buf()),
        tls_ca: Some(dir.join("relay-ca.pem")),
        signer_check: relay_server::config::SignerCheckConfig {
            keyserver: String::new(),
            ..Default::default()
        },
        hardware_attestation: relay_core::hw_attestation::PolicyConfig {
            roots_file: Some(dir.join("attestation-root.pem")),
        },
        ..Default::default()
    }
}

/// `(status, error kind)` of a call.
fn call(rc: &RelayClient, method: &str, path: &str, body: &serde_json::Value) -> (u16, String) {
    let body = if body.is_null() {
        Vec::new()
    } else {
        body.to_string().into_bytes()
    };
    let r = rc.call(method, path, &body, "application/json").unwrap();
    let kind = serde_json::from_slice::<serde_json::Value>(&r.body)
        .ok()
        .and_then(|v| v["error"].as_str().map(str::to_string))
        .unwrap_or_default();
    (r.status, kind)
}

#[test]
fn setup_links_admit_devices_once_and_a_revoked_signer_stops_service() {
    let dir = temp_dir("setup");
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
    // The relay reads its signer from a copy this test can replace.
    let live = dir.join("signer-live.asc");
    std::fs::copy(dir.join("signer.asc"), &live).unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let st = rt
        .block_on(relay_server::build_state(relay_config(&dir, &live)))
        .unwrap();
    let (cert, key) = (dir.join("relay-cert.pem"), dir.join("relay-key.pem"));
    let served = st.clone();
    rt.spawn(async move { relay_server::serve_tls(listener, served, &cert, &key).await });

    let ca = std::fs::read(dir.join("relay-ca.pem")).unwrap();
    let auth: Arc<dyn DeviceSigner> = Arc::new(SoftwareKey::generate_p256());
    let rc = RelayClient::new(&url, Some(&ca), auth.clone()).unwrap();
    let signer =
        ManifestSigner::from_bytes(&std::fs::read(dir.join("signer.asc")).unwrap()).unwrap();
    let policy = relay_core::hw_attestation::PolicyConfig {
        roots_file: Some(dir.join("attestation-root.pem")),
    }
    .policy()
    .unwrap();
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
            Ok((m, _)) => break m,
            Err(_) if start.elapsed() < Duration::from_secs(10) => {
                std::thread::sleep(Duration::from_millis(100))
            }
            Err(e) => panic!("manifest: {e}"),
        }
    };

    // The two setup endpoints serve exactly the configured files.
    let get = |path: &str| rc.call("GET", path, b"", "application/json").unwrap();
    assert_eq!(
        get("/v1/manifest-signer.asc").body,
        std::fs::read(&live).unwrap()
    );
    assert_eq!(get("/v1/relay-ca.pem").body, ca);

    // An enrolled device.
    let device: Arc<dyn DeviceSigner> = Arc::new(SoftwareKey::generate_p256());
    let mut card = relay_softcard::SoftCard::load_dir(&dir.join("softcard-a"), PIN).unwrap();
    let engine = Engine::new(
        EngineConfig {
            device_id: "phone".into(),
            attestation_window_secs: 86_400,
            skew_secs: 60,
            renew_attestation: true,
        },
        manifest,
        device,
        Vec::new(),
    );
    engine.discover(&mut card).unwrap();
    engine
        .attest(&mut card, PIN, now(), now() + 86_400)
        .unwrap();
    let binding = engine.bind_auth_key(&auth.public_key()).unwrap();
    let register = |link: Option<&str>| {
        call(
            &rc,
            "POST",
            "/v1/devices",
            &engine
                .registration(serde_json::Value::Null, Some(&binding), link)
                .unwrap(),
        )
    };

    // Each rejection, one at a time.
    let good = setup_link(&dir, &url, "phone", now()).unwrap();
    assert_eq!(register(None), (400, "SetupLinkRequired".into()));
    let other_device = setup_link(&dir, &url, "tablet", now()).unwrap();
    assert_eq!(
        register(Some(&other_device)),
        (400, "SetupLinkWrongDevice".into())
    );
    let expired = setup_link(&dir, &url, "phone", now() - 8 * 86_400).unwrap();
    assert_eq!(register(Some(&expired)), (400, "SetupLinkExpired".into()));
    let tampered = good.replacen("device=phone", "device=phonf", 1);
    assert_eq!(register(Some(&tampered)).1, "SetupLinkSignatureInvalid");
    let stranger = PgpSecretKey::generate("stranger <s@test.invalid>").unwrap();
    let stranger_fpr = ManifestSigner::from_bytes(stranger.public_armored().unwrap().as_bytes())
        .unwrap()
        .fingerprint();
    let d = SetupLinkDraft {
        relay: url.clone(),
        ca: None,
        signer: stranger_fpr,
        device: "phone".into(),
        iat: now() - 60,
        exp: now() + 600,
    };
    let foreign = d
        .with_signature(
            &stranger
                .sign_detached_binary(d.signed_bytes().unwrap().as_bytes())
                .unwrap(),
        )
        .unwrap();
    assert_eq!(
        register(Some(&foreign)),
        (400, "SetupLinkWrongSigner".into())
    );
    assert_eq!(
        register(Some("poh://setup?v=1&nope")),
        (400, "SetupLinkInvalid".into())
    );

    // Admitted once; re-registration of the device it holds needs no link.
    assert_eq!(register(Some(&good)).0, 204);
    assert_eq!(register(None).0, 204);
    let rec = rt
        .block_on(relay_server::db::device_by_id(&st.db, "phone"))
        .unwrap()
        .unwrap();
    let id = relay_core::setup_link::parse(&good).unwrap().id();
    assert_eq!(rec.setup_link_id.as_deref(), Some(id.as_str()));

    // Revoked: the id counts as new again, and the old link is spent.
    rt.block_on(relay_server::admin::revoke_device(&st.db, "phone"))
        .unwrap();
    assert_eq!(register(None), (400, "SetupLinkRequired".into()));
    assert_eq!(register(Some(&good)), (400, "SetupLinkUsed".into()));
    let fresh = setup_link(&dir, &url, "phone", now() + 1).unwrap();
    assert_eq!(register(Some(&fresh)).0, 204);

    // The signer key is revoked: every client and device call is refused, setup files stay up.
    let pgp =
        PgpSecretKey::from_bytes(&std::fs::read(dir.join("signer-secret.asc")).unwrap()).unwrap();
    std::fs::write(&live, pgp.revoked_public_armored("lost the card").unwrap()).unwrap();
    st.signer_watch.reload_file();
    let change = rt.block_on(st.signer_watch.recompute(&st.db, now()));
    assert!(
        matches!(change, Some(Status::Unusable(ref r)) if r.contains("revoked") && r.contains("lost the card")),
        "{change:?}"
    );
    // A request in flight is cancelled when the signer becomes unusable.
    {
        let (done, _) = tokio::sync::watch::channel(false);
        st.lock().pending.insert(
            [7u8; 16],
            relay_server::state::Pending {
                bytes: Vec::new(),
                client_id: "c".into(),
                key_fingerprint: relay_core::Fingerprint::parse(&format!(
                    "sha256:{}",
                    "0".repeat(64)
                ))
                .unwrap(),
                expires_at: now() + 60,
                received_at: now(),
                devices: vec!["phone".into()],
                response: None,
                responded_by: None,
                done,
            },
        );
    }
    relay_server::on_signer_change(&st, change);
    assert!(st.lock().pending.is_empty(), "pending requests cancelled");
    assert_eq!(register(None), (503, "ManifestSignerUnusable".into()));
    let pairing = serde_json::json!({"client_id": "x", "public_key": "AA==", "host": "h"});
    assert_eq!(
        call(&rc, "POST", "/v1/clients/pending", &pairing),
        (503, "ManifestSignerUnusable".into())
    );
    assert_eq!(
        call(&rc, "GET", "/v1/clients/self", &serde_json::Value::Null),
        (503, "ManifestSignerUnusable".into())
    );
    assert_eq!(get("/v1/manifest-signer.asc").status, 200);
    assert!(String::from_utf8(get("/metrics").body)
        .unwrap()
        .contains("relay_signer_usable 0"));

    // The revocation persists: a relay restarted with the unrevoked file still refuses.
    std::fs::copy(dir.join("signer.asc"), &live).unwrap();
    let again = SignerWatch::new(&relay_config(&dir, &live)).unwrap();
    assert!(matches!(
        rt.block_on(again.recompute(&st.db, now())),
        Some(Status::Unusable(_))
    ));
    // A different key in the file is a fresh start.
    let new_key = PgpSecretKey::generate("new signer <n@test.invalid>").unwrap();
    std::fs::write(&live, new_key.public_armored().unwrap()).unwrap();
    let renewed = SignerWatch::new(&relay_config(&dir, &live)).unwrap();
    assert_eq!(rt.block_on(renewed.recompute(&st.db, now())), None);
    assert_eq!(renewed.status(), Status::Usable);
}

/// A one-request HTTP server: answers with `status` and `body`, then stops.
fn stub(status: u16, body: Vec<u8>) -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = l.accept() {
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let _ = write!(
                s,
                "HTTP/1.1 {status} X\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(&body);
        }
    });
    url
}

fn vector(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../relay-core/tests/vectors/signer")
        .join(name)
}

fn watch(dir: &Path, file: &Path, keyserver: String) -> SignerWatch {
    let mut cfg = relay_config(dir, file);
    cfg.manifest_file = None;
    cfg.signer_check.keyserver = keyserver;
    SignerWatch::new(&cfg).unwrap()
}

#[test]
fn the_keyserver_copy_revokes_renews_or_changes_nothing() {
    let dir = temp_dir("watch");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let db = rt
        .block_on(relay_server::db::open(&dir.join("db")))
        .unwrap();
    let client = relay_server::signer_watch::http_client().unwrap();
    let _ = HardwarePolicy::yubico();

    // Expired in the file, renewed on the keyserver: usable.
    let w = watch(
        &dir,
        &vector("expiring.asc"),
        stub(200, std::fs::read(vector("renewed.asc")).unwrap()),
    );
    assert!(
        matches!(rt.block_on(w.recompute(&db, now())), Some(Status::Unusable(ref r)) if r.contains("expired"))
    );
    assert_eq!(rt.block_on(w.fetch_keyserver(&client)), Lookup::Found);
    assert_eq!(rt.block_on(w.recompute(&db, now())), Some(Status::Usable));

    // Unreachable, not published, or another key: nothing changes (fail open).
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let u = format!("http://{}", l.local_addr().unwrap());
        drop(l);
        u
    };
    for (server, want) in [
        (closed, "unreachable"),
        (stub(404, Vec::new()), "not found"),
        (
            stub(200, std::fs::read(vector("usable.asc")).unwrap()),
            "another key",
        ),
    ] {
        let w = watch(&dir, &vector("subkey-expiring.asc"), server);
        let before = w.status();
        let r = rt.block_on(w.fetch_keyserver(&client));
        match want {
            "unreachable" => assert!(matches!(r, Lookup::Unreachable(_)), "{r:?}"),
            "not found" => assert_eq!(r, Lookup::NotFound),
            _ => assert!(
                matches!(r, Lookup::Rejected(ref m) if m.contains("another key")),
                "{r:?}"
            ),
        }
        assert_eq!(w.status(), before);
    }

    // Disabled: no lookup at all.
    let w = watch(&dir, &vector("usable.asc"), String::new());
    assert_eq!(rt.block_on(w.fetch_keyserver(&client)), Lookup::Disabled);
}

#[test]
fn app_setup_checks_the_link_pins_and_the_keyserver() {
    use relay_approver::setup::{preview, Identity, SetupOptions};
    let dir = temp_dir("app-setup");
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
    let st = rt
        .block_on(relay_server::build_state(relay_config(
            &dir,
            &dir.join("signer.asc"),
        )))
        .unwrap();
    let (cert, key) = (dir.join("relay-cert.pem"), dir.join("relay-key.pem"));
    rt.spawn(async move { relay_server::serve_tls(listener, st, &cert, &key).await });
    let policy = relay_core::hw_attestation::PolicyConfig {
        roots_file: Some(dir.join("attestation-root.pem")),
    }
    .policy()
    .unwrap();
    let opts = |keyserver: String| SetupOptions {
        keyserver,
        policy: policy.clone(),
        skew_secs: 60,
    };
    let link = setup_link(&dir, &url, "phone", now()).unwrap();
    let signer_pub = std::fs::read(dir.join("signer.asc")).unwrap();

    // Published with a confirmed address: shown.
    let start = Instant::now();
    let p = loop {
        match preview(&link, now(), &opts(stub(200, signer_pub.clone()))) {
            Ok(p) => break p,
            Err(_) if start.elapsed() < Duration::from_secs(10) => {
                std::thread::sleep(Duration::from_millis(100))
            }
            Err(e) => panic!("{e}"),
        }
    };
    assert!(
        matches!(&p.identity, Identity::Verified(ids) if ids.iter().any(|i| i.contains("fixtures@test.invalid"))),
        "{:?}",
        p.identity
    );
    assert_eq!(p.device_id, "phone");
    // Not published, or another key: setup goes on, with the state shown.
    let p = preview(&link, now(), &opts(stub(404, Vec::new()))).unwrap();
    assert_eq!(p.identity, Identity::NotFound);
    let other = PgpSecretKey::generate("other <o@test.invalid>").unwrap();
    let p = preview(
        &link,
        now(),
        &opts(stub(200, other.public_armored().unwrap().into_bytes())),
    )
    .unwrap();
    assert!(
        matches!(p.identity, Identity::Mismatch(_)),
        "{:?}",
        p.identity
    );
    // Revoked on the keyserver: setup stops.
    let pgp =
        PgpSecretKey::from_bytes(&std::fs::read(dir.join("signer-secret.asc")).unwrap()).unwrap();
    let revoked = pgp.revoked_public_armored("gone").unwrap().into_bytes();
    let e = preview(&link, now(), &opts(stub(200, revoked))).unwrap_err();
    assert!(e.to_string().contains("revoked"), "{e}");

    // A link pinning another CA: the fetched CA is refused before anything else.
    let d = SetupLinkDraft {
        relay: url.clone(),
        ca: Some([9u8; 32]),
        signer: ManifestSigner::from_bytes(&signer_pub)
            .unwrap()
            .fingerprint(),
        device: "phone".into(),
        iat: now() - 60,
        exp: now() + 600,
    };
    let wrong_ca = d
        .with_signature(
            &pgp.sign_detached_binary(d.signed_bytes().unwrap().as_bytes())
                .unwrap(),
        )
        .unwrap();
    let e = preview(&wrong_ca, now(), &opts(stub(404, Vec::new()))).unwrap_err();
    assert!(e.to_string().contains("ca pin"), "{e}");
    // No pin at all: the private relay's certificate isn't trusted by the public roots.
    let no_ca = SetupLinkDraft { ca: None, ..d };
    let no_ca = no_ca
        .with_signature(
            &pgp.sign_detached_binary(no_ca.signed_bytes().unwrap().as_bytes())
                .unwrap(),
        )
        .unwrap();
    assert!(preview(&no_ca, now(), &opts(stub(404, Vec::new()))).is_err());
}
