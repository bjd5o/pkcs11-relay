//! Runs every golden vector under `tests/vectors/` against the core's verifiers.

mod common;

use common::*;
use relay_core::request::{ApproverPolicy, ReplayCache};
use relay_core::seal::ReplyKey;
use relay_core::{verify_attestation, verify_request, verify_response, Fingerprint, Outcome};
use serde_json::Value;

fn cases(kind: &str) -> Vec<(String, Value)> {
    let mut out: Vec<(String, Value)> = std::fs::read_dir(dir().join(kind))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .map(|p| {
            let v = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
            (p.file_name().unwrap().to_string_lossy().into_owned(), v)
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    assert!(!out.is_empty(), "no vectors in {kind}");
    out
}

fn hx(v: &Value, k: &str) -> Vec<u8> {
    hex::decode(v[k].as_str().unwrap()).unwrap()
}

fn u(v: &Value, k: &str) -> u64 {
    v[k].as_u64().unwrap()
}

fn kind_of<T>(r: relay_core::Result<T>) -> String {
    match r {
        Ok(_) => "ok".into(),
        Err(e) => e.kind().into(),
    }
}

#[test]
fn attestation_vectors() {
    let fx = load();
    for (name, v) in cases("attestation") {
        let got = kind_of(verify_attestation(
            &hx(&v, "attestation"),
            &fx.manifest,
            u(&v, "now"),
            u(&v, "skew"),
        ));
        assert_eq!(got, v["expect"].as_str().unwrap(), "{name}");
    }
}

#[test]
fn request_vectors() {
    let fx = load();
    let all: Vec<Fingerprint> = fx
        .manifest
        .keys
        .iter()
        .map(|k| k.fingerprint.clone())
        .collect();
    let client = fx.client.public_key();
    let policy = ApproverPolicy {
        client_id: CLIENT_ID,
        client_key: &client,
        approved_keys: &all,
        operable_keys: &all,
    };
    for (name, v) in cases("request") {
        let mut replay = ReplayCache::new(86_400);
        let got = kind_of(verify_request(
            &hx(&v, "request"),
            &policy,
            &fx.manifest,
            &mut replay,
            u(&v, "now"),
            u(&v, "skew"),
        ));
        assert_eq!(got, v["expect"].as_str().unwrap(), "{name}");
    }
}

#[test]
fn response_vectors() {
    let fx = load();
    for (name, v) in cases("response") {
        let reply = ReplyKey::from_private_bytes(&hx(&v, "reply_key")).unwrap();
        let r = verify_response(
            &hx(&v, "response"),
            &hx(&v, "request"),
            &fx.manifest,
            u(&v, "now"),
            u(&v, "skew"),
            reply,
        );
        let expect = v["expect"].as_str().unwrap();
        match (r, expect) {
            (Ok(Outcome::Approved(res)), "approved") => {
                assert_eq!(*res, hx(&v, "result"), "{name}")
            }
            (Ok(Outcome::Denied(reason)), "denied") | (Ok(Outcome::Error(reason)), "error") => {
                assert_eq!(reason.map(|r| r.as_str()), v["reason"].as_str(), "{name}")
            }
            (Err(e), want) => assert_eq!(e.kind(), want, "{name}"),
            (got, want) => panic!("{name}: expected {want}, got {got:?}"),
        }
    }
}

#[test]
fn hw_attestation_vectors() {
    use relay_core::hw_attestation::verify_piv_attestation;
    for (name, v) in cases("hw-attestation") {
        let chain: Vec<Vec<u8>> = v["chain"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| hex::decode(c.as_str().unwrap()).unwrap())
            .collect();
        let pk = relay_core::PublicKey::from_spki(&hx(&v, "public_key")).unwrap();
        let r = verify_piv_attestation(&chain, &pk, &[hx(&v, "root")], u(&v, "now"));
        match &v["expect"] {
            Value::String(kind) => assert_eq!(&kind_of(r), kind, "{name}"),
            want => {
                let a = r.unwrap_or_else(|e| panic!("{name}: {e}"));
                assert_eq!(a.serial as u64, want["serial"].as_u64().unwrap(), "{name}");
                assert_eq!(
                    a.firmware_string(),
                    want["firmware"].as_str().unwrap(),
                    "{name}"
                );
                assert_eq!(
                    a.pin_policy.as_str(),
                    want["pin_policy"].as_str().unwrap(),
                    "{name}"
                );
                assert_eq!(
                    a.touch_policy.as_str(),
                    want["touch_policy"].as_str().unwrap(),
                    "{name}"
                );
                assert_eq!(
                    a.form_factor.map(u64::from),
                    want["form_factor"].as_u64(),
                    "{name}"
                );
            }
        }
    }
}

#[test]
fn setup_link_vectors() {
    use relay_core::setup_link::verify_setup_link;
    for (name, v) in cases("setup-link") {
        let signer =
            relay_core::ManifestSigner::from_bytes(v["signer"].as_str().unwrap().as_bytes())
                .unwrap();
        let r = verify_setup_link(
            v["link"].as_str().unwrap(),
            &signer,
            u(&v, "now"),
            u(&v, "skew"),
        );
        let expect = v["expect"].as_str().unwrap();
        if expect == "ok" {
            assert_eq!(r.unwrap().id(), v["id"].as_str().unwrap(), "{name}");
        } else {
            assert_eq!(kind_of(r), expect, "{name}");
        }
    }
}
