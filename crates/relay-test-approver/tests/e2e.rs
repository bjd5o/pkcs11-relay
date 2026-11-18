//! The milestone 2 gate in-process: a real relay on a local port, three approvers over
//! WebSocket and long-poll, and the gate client. The Docker run (deploy/compose.test.yml)
//! repeats this with each component in its own container.

use std::path::PathBuf;
use std::time::Duration;

use relay_test_approver::approver::{Approver, Behavior, Config, FATAL};

fn temp_dir() -> PathBuf {
    let mut b = [0u8; 8];
    relay_core::signing::random_bytes(&mut b);
    let d = std::env::temp_dir().join(format!("relay-e2e-{}", hex::encode(b)));
    std::fs::create_dir_all(&d).unwrap();
    d
}

async fn approver(dir: &std::path::Path, name: &str, b: Behavior) {
    let cfg: Config = toml::from_str(
        &std::fs::read_to_string(dir.join(format!("approver-{name}.toml"))).unwrap(),
    )
    .unwrap();
    let card =
        relay_softcard::SoftCard::load_dir(cfg.softcard_dir.as_ref().unwrap(), b"123456").unwrap();
    let a = Approver::start(cfg, b, Box::new(card))
        .await
        .unwrap_or_else(|e| panic!("approver {name}: {e}"));
    tokio::spawn(a.run());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gate_in_process() {
    let dir = temp_dir();
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
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let now = relay_test_approver::relay::now();
    relay_test_approver::fixtures::generate(
        &dir,
        dir.to_str().unwrap(),
        &url,
        &["127.0.0.0/8".into()],
        now,
    )
    .unwrap();
    let st = relay_server::build_state(cfg).await.unwrap();
    let (cert, key) = (dir.join("relay-cert.pem"), dir.join("relay-key.pem"));
    tokio::spawn(async move { relay_server::serve_tls(listener, st, &cert, &key).await });
    approver(&dir, "a", Behavior::default()).await;
    approver(
        &dir,
        "b",
        Behavior {
            deny: true,
            delay: Duration::from_secs(3),
            long_poll: true,
            ..Default::default()
        },
    )
    .await;
    approver(
        &dir,
        "c",
        Behavior {
            expired_attestation: true,
            ..Default::default()
        },
    )
    .await;

    let gate: relay_test_approver::gate::Config =
        toml::from_str(&std::fs::read_to_string(dir.join("gate.toml")).unwrap()).unwrap();
    let r = tokio::time::timeout(
        Duration::from_secs(120),
        relay_test_approver::gate::run(gate),
    )
    .await
    .expect("gate timed out");
    r.unwrap();

    // A rejected PIN at startup is fatal (the binary does not retry it), and costs one attempt.
    let mut cfg: Config =
        toml::from_str(&std::fs::read_to_string(dir.join("approver-a.toml")).unwrap()).unwrap();
    cfg.data_dir = dir.join("fresh-device"); // no stored attestation: the card must sign one
    cfg.pin_file = Some(dir.join("wrong-pin"));
    std::fs::write(cfg.pin_file.as_ref().unwrap(), "000000").unwrap();
    let card =
        relay_softcard::SoftCard::load_dir(cfg.softcard_dir.as_ref().unwrap(), b"123456").unwrap();
    let e = match Approver::start(cfg, Behavior::default(), Box::new(card)).await {
        Ok(_) => panic!("started with a wrong PIN"),
        Err(e) => e,
    };
    assert!(e.starts_with(FATAL), "{e}");
    let _ = std::fs::remove_dir_all(&dir);
}
