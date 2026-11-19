//! The approver engine against the software card: every response it produces is checked with
//! `relay_core::verify_response`, exactly as the provider checks it.

use std::sync::Arc;

use base64::Engine as _;
use relay_approver::{ApproverError, Checked, Engine, EngineConfig, PairedClient, PendingRequest};
use relay_core::manifest::{DraftKey, ManifestDraft};
use relay_core::piv::{PivError, Slot};
use relay_core::request::{RequestContext, UnsignedRequest};
use relay_core::response::{verify_response, Outcome, Reason};
use relay_core::seal::ReplyKey;
use relay_core::signing::{DeviceSigner, SoftwareKey};
use relay_core::{Algorithm, Manifest, Mechanism, Op, PublicKey, Role};
use relay_softcard::SoftCard;

const NOW: u64 = 1_800_000_000;
const PIN: &[u8] = b"123456";

fn slot(s: u8) -> Slot {
    Slot::new(s).unwrap()
}

struct Fx {
    card: SoftCard,
    manifest: Manifest,
    client: SoftwareKey,
    engine: Engine,
}

fn fixture(window: u64) -> Fx {
    let mut card = SoftCard::new(PIN);
    let attest = card.generate(slot(0x95), Algorithm::P256);
    let sign = card.generate(slot(0x9c), Algorithm::P256);
    let sign2 = card.generate(slot(0x9d), Algorithm::P256); // on the card, not granted to pi5
    let other = SoftCard::new(PIN).generate(slot(0x9c), Algorithm::P256); // not on this card
    let key = |role, label: &str, id: u8, pk: PublicKey| DraftKey {
        role,
        label: label.into(),
        id: vec![id],
        token: "yk".into(),
        public_key: pk,
        hardware_attestation: None,
    };
    let draft = ManifestDraft {
        version: 2,
        issued_at: NOW - 100,
        valid_until: NOW + 86_400 * 30,
        keys: vec![
            key(Role::Attest, "attest", 0x10, attest),
            key(Role::Sign, "sign", 0x11, sign.clone()),
            key(Role::Sign, "elsewhere", 0x12, other),
            key(Role::Sign, "sign2", 0x13, sign2),
        ],
        ..Default::default()
    };
    let manifest = Manifest::from_json_unverified(&draft.to_json().unwrap()).unwrap();
    let client = SoftwareKey::generate_ed25519();
    let engine = Engine::new(
        EngineConfig {
            device_id: "phone".into(),
            attestation_window_secs: window,
            skew_secs: 60,
            renew_attestation: true,
        },
        manifest.clone(),
        Arc::new(SoftwareKey::generate_p256()),
        vec![PairedClient {
            client_id: "pi5".into(),
            public_key: client.public_key(),
            keys: vec![sign.fingerprint().clone()],
        }],
    );
    let found = engine.discover(&mut card).unwrap();
    assert_eq!(
        found.len(),
        3,
        "attest, sign and sign2 are on the card; `elsewhere` is not"
    );
    engine.attest(&mut card, PIN, NOW, NOW + window).unwrap();
    Fx {
        card,
        manifest,
        client,
        engine,
    }
}

impl Fx {
    fn request(&self, label: &str, at: u64) -> (Vec<u8>, ReplyKey) {
        let reply = ReplyKey::generate();
        let key = self
            .manifest
            .keys
            .iter()
            .find(|k| k.label == label)
            .unwrap();
        let r = UnsignedRequest::new(
            "pi5",
            key,
            Op::Sign,
            Mechanism::EcdsaSha256,
            b"a release tag".to_vec(),
            RequestContext {
                host: "pi5".into(),
                purpose: "release".into(),
                consumer: "git".into(),
            },
            reply.public_bytes(),
            at,
            at + 90,
        )
        .unwrap();
        let sig = self.client.sign(&r.to_be_signed());
        (r.with_signature(sig).bytes().to_vec(), reply)
    }

    fn show(&self, bytes: &[u8], at: u64) -> PendingRequest {
        match self.engine.check_request(bytes, at).unwrap() {
            Checked::Show(p) => *p,
            Checked::Rejected(r) => panic!("rejected: {}", r.why),
        }
    }

    fn outcome(&self, resp: &[u8], req: &[u8], at: u64, reply: ReplyKey) -> Outcome {
        verify_response(resp, req, &self.manifest, at, 60, reply).unwrap()
    }
}

#[test]
fn approve_seals_a_result_the_provider_accepts() {
    let mut f = fixture(86_400);
    let (req, reply) = f.request("sign", NOW + 5);
    let p = f.show(&req, NOW + 5);
    assert_eq!(p.view.key_label, "sign");
    assert_eq!(p.view.claims.purpose, "release");
    let sessions = f.card.sessions;
    let a = f.engine.approve(&p, &mut f.card, PIN, NOW + 5).unwrap();
    assert!(a.approved && a.card_error.is_none() && a.renewed_attestation.is_none());
    assert_eq!(
        f.card.sessions,
        sessions + 1,
        "PIN and operation share one card session"
    );
    match f.outcome(&a.response, &req, NOW + 5, reply) {
        Outcome::Approved(sig) => assert_eq!(sig.len(), 64),
        o => panic!("{o:?}"),
    }
}

#[test]
fn denial_and_failed_checks_are_signed_denials() {
    let f = fixture(86_400);
    let (req, reply) = f.request("sign", NOW + 5);
    let p = f.show(&req, NOW + 5);
    let d = f.engine.deny(&p, NOW + 5).unwrap();
    assert!(matches!(
        f.outcome(&d, &req, NOW + 5, reply),
        Outcome::Denied(Some(Reason::UserDenied))
    ));

    // The same request id again: replay.
    let Checked::Rejected(r) = f.engine.check_request(&req, NOW + 6).unwrap() else {
        panic!()
    };
    assert!(
        r.why.contains("Replay") || r.why.contains("replay"),
        "{}",
        r.why
    );

    // A key that is not on this card.
    let (req, reply) = f.request("elsewhere", NOW + 5);
    let Checked::Rejected(r) = f.engine.check_request(&req, NOW + 5).unwrap() else {
        panic!()
    };
    let response = f.engine.sign_rejection(&r, NOW + 5).unwrap();
    assert!(matches!(
        f.outcome(&response, &req, NOW + 5, reply),
        Outcome::Denied(Some(Reason::Policy))
    ));

    // Expired by the time it arrives.
    let (req, reply) = f.request("sign", NOW);
    let Checked::Rejected(r) = f.engine.check_request(&req, NOW + 200).unwrap() else {
        panic!()
    };
    let response = f.engine.sign_rejection(&r, NOW + 200).unwrap();
    assert!(matches!(
        f.outcome(&response, &req, NOW + 100, reply),
        Outcome::Denied(Some(Reason::Expired))
    ));

    // An unpaired client.
    assert!(f.engine.remove_client("pi5"));
    let (req, _) = f.request("sign", NOW + 5);
    assert!(matches!(
        f.engine.check_request(&req, NOW + 5).unwrap(),
        Checked::Rejected(_)
    ));
}

#[test]
fn wrong_pin_stops_card_operations_until_cleared() {
    let mut f = fixture(86_400);
    let (req, reply) = f.request("sign", NOW + 5);
    let p = f.show(&req, NOW + 5);
    let retries = f.card.pin_retries();
    let a = f
        .engine
        .approve(&p, &mut f.card, b"000000", NOW + 5)
        .unwrap();
    assert!(!a.approved);
    assert!(matches!(a.card_error, Some(PivError::WrongPin { .. })));
    assert!(matches!(
        f.outcome(&a.response, &req, NOW + 5, reply),
        Outcome::Error(Some(Reason::WrongPin))
    ));
    assert_eq!(f.card.pin_retries(), retries - 1);
    assert!(f.engine.pin_failed());

    // No further attempt, even with the right PIN, until the person retries.
    let (req, _) = f.request("sign", NOW + 6);
    let p = f.show(&req, NOW + 6);
    let sessions = f.card.sessions;
    let a = f.engine.approve(&p, &mut f.card, PIN, NOW + 6).unwrap();
    assert!(!a.approved);
    assert_eq!(f.card.sessions, sessions, "the card was not touched");
    assert_eq!(f.card.pin_retries(), retries - 1);
    assert!(matches!(
        f.engine.attest(&mut f.card, PIN, NOW, NOW + 10),
        Err(ApproverError::PinRejected { .. })
    ));

    f.engine.clear_pin_failure();
    let (req, _) = f.request("sign", NOW + 7);
    let p = f.show(&req, NOW + 7);
    assert!(
        f.engine
            .approve(&p, &mut f.card, PIN, NOW + 7)
            .unwrap()
            .approved
    );
}

#[test]
fn renewal_rides_along_with_an_approval() {
    let mut f = fixture(100);
    let before = f.engine.attestation_info().unwrap();
    assert_eq!(before.renew_at, NOW + 75);
    assert!(!f.engine.renewal_due(NOW + 74));
    let (req, reply) = f.request("sign", NOW + 80);
    let p = f.show(&req, NOW + 80);
    let sessions = f.card.sessions;
    let a = f.engine.approve(&p, &mut f.card, PIN, NOW + 80).unwrap();
    assert!(a.approved, "{:?}", a.renewal_error);
    assert_eq!(
        f.card.sessions,
        sessions + 1,
        "renewal shares the approval's card session"
    );
    let renewed = a.renewed_attestation.expect("renewed");
    let info = f.engine.attestation_info().unwrap();
    assert_eq!((info.not_before, info.not_after), (NOW + 80, NOW + 180));
    assert_eq!(f.engine.attestation().unwrap(), renewed);
    // The response carries the new statement, and the provider accepts it after the old
    // window has ended.
    assert!(matches!(
        f.outcome(&a.response, &req, NOW + 110, reply),
        Outcome::Approved(_)
    ));
    // A restart restores it; a statement for another device key is refused.
    f.engine.load_attestation(&renewed).unwrap();
    let mut g = fixture(100);
    assert!(g.engine.load_attestation(&renewed).is_err());
    let _ = &mut g.card;
}

#[test]
fn an_expired_attestation_is_kept_and_renewed_by_the_next_approval() {
    let mut f = fixture(100);
    let old = f.engine.attestation().unwrap();
    // Long past its window (NOW..NOW+100): a restart still restores it.
    let info = f.engine.load_attestation(&old).unwrap();
    assert_eq!(info.not_after, NOW + 100);
    assert!(f.engine.renewal_due(NOW + 1_000));
    let (req, reply) = f.request("sign", NOW + 1_000);
    let p = f.show(&req, NOW + 1_000);
    let a = f.engine.approve(&p, &mut f.card, PIN, NOW + 1_000).unwrap();
    assert!(a.approved, "{:?}", a.renewal_error);
    assert!(
        a.renewed_attestation.is_some(),
        "renewed in the same session"
    );
    let info = f.engine.attestation_info().unwrap();
    assert_eq!(
        (info.not_before, info.not_after),
        (NOW + 1_000, NOW + 1_100)
    );
    assert!(matches!(
        f.outcome(&a.response, &req, NOW + 1_010, reply),
        Outcome::Approved(_)
    ));
}

#[test]
fn pairing_code_is_derived_not_trusted() {
    let mut f = fixture(86_400);
    let b64 = base64::engine::general_purpose::STANDARD;
    let newcomer = SoftwareKey::generate_ed25519().public_key();
    let code = relay_core::pairing::pairing_code(newcomer.spki());
    let p = serde_json::json!({
        "client_id": "laptop",
        "public_key": b64.encode(newcomer.spki()),
        "fingerprint": newcomer.fingerprint().as_str(),
        "host": "laptop.tailnet",
        "code": code,
    });
    let v = f.engine.pairing_view(&p).unwrap();
    assert_eq!(v.code, code);
    let sign = f.manifest.keys.iter().find(|k| k.label == "sign").unwrap();
    let attest = f
        .manifest
        .keys
        .iter()
        .find(|k| k.label == "attest")
        .unwrap();
    // Approving signs a grant (seq 1) on the card for the chosen keys and window.
    let post = f
        .engine
        .pairing_approval(
            &v,
            std::slice::from_ref(&sign.fingerprint),
            3_600,
            &mut f.card,
            PIN,
            NOW,
        )
        .unwrap();
    assert_eq!(post.path, "/v1/clients/laptop/approval");
    let grant = b64.decode(post.body["grant"].as_str().unwrap()).unwrap();
    let g = relay_core::verify_client_grant(&grant, &f.manifest, NOW, 60).unwrap();
    assert!(!g.lapsed);
    let g = g.grant.fields;
    assert_eq!(
        (
            g.client_id.as_str(),
            g.seq,
            g.window_secs,
            g.approved_by.as_str()
        ),
        ("laptop", 1, 3_600, "phone")
    );
    assert_eq!(&g.client_key, &newcomer);
    assert_eq!(g.keys, vec![sign.fingerprint.clone()]);
    assert!(
        f.engine
            .pairing_approval(
                &v,
                std::slice::from_ref(&attest.fingerprint),
                3_600,
                &mut f.card,
                PIN,
                NOW
            )
            .is_err(),
        "never the attest key"
    );
    assert!(
        f.engine
            .pairing_approval(
                &v,
                std::slice::from_ref(&sign.fingerprint),
                31 * 86_400,
                &mut f.card,
                PIN,
                NOW
            )
            .is_err(),
        "no longer than the manifest's max_client_grant_window_secs"
    );
    let laptop = f
        .engine
        .client_list(NOW)
        .into_iter()
        .find(|c| c.client_id == "laptop")
        .unwrap();
    assert!(laptop.accepted, "pairing it here accepts it here");

    let mut wrong = p.clone();
    wrong["code"] = "some-other-four-words".into();
    assert!(f.engine.pairing_view(&wrong).is_err());
    let mut swapped = p;
    swapped["fingerprint"] = sign.fingerprint.as_str().into();
    assert!(f.engine.pairing_view(&swapped).is_err());
}

#[test]
fn registration_lists_operable_keys_without_the_attest_key() {
    let f = fixture(86_400);
    let r = f
        .engine
        .registration(serde_json::Value::Null, None, None)
        .unwrap();
    assert_eq!(r["device_id"], "phone");
    assert_eq!(r["keys"].as_array().unwrap().len(), 2);
    assert_eq!(r["push"]["kind"], "none");
    assert!(r.get("auth_key").is_none());

    // A separate relay-auth key, vouched for once by the device key.
    let auth = SoftwareKey::generate_p256().public_key();
    let b = f.engine.bind_auth_key(&auth).unwrap();
    relay_core::relay_auth::verify_auth_key_binding(
        &f.engine.device_key(),
        "phone",
        &auth,
        &b.signature,
    )
    .unwrap();
    let r = f
        .engine
        .registration(serde_json::Value::Null, Some(&b), None)
        .unwrap();
    let b64 = base64::engine::general_purpose::STANDARD;
    assert_eq!(r["auth_key"], b64.encode(auth.spki()));
    assert_eq!(r["auth_key_sig"], b64.encode(&b.signature));
}

/// A platform signer that signs the wrong bytes is caught before anything is posted.
struct Broken(SoftwareKey);
impl DeviceSigner for Broken {
    fn public_key(&self) -> PublicKey {
        self.0.public_key()
    }
    fn sign_message(&self, _msg: &[u8]) -> Result<[u8; 64], String> {
        Ok(self.0.sign(b"something else"))
    }
}

#[test]
fn a_bad_device_signature_is_caught() {
    let mut f = fixture(86_400);
    let broken = Engine::new(
        f.engine.config().clone(),
        f.manifest.clone(),
        Arc::new(Broken(SoftwareKey::generate_p256())),
        f.engine.clients(),
    );
    broken.discover(&mut f.card).unwrap();
    let (req, _) = f.request("sign", NOW + 5);
    let Checked::Show(p) = broken.check_request(&req, NOW + 5).unwrap() else {
        panic!()
    };
    assert!(
        matches!(broken.deny(&p, NOW + 5), Err(ApproverError::NotEnrolled)),
        "nothing to sign with before enrollment"
    );
    broken.attest(&mut f.card, PIN, NOW, NOW + 1000).unwrap();
    assert!(matches!(
        broken.deny(&p, NOW + 5),
        Err(ApproverError::Signer(_))
    ));
    assert!(matches!(
        broken.approve(&p, &mut f.card, PIN, NOW + 5),
        Err(ApproverError::Signer(_))
    ));
}

#[test]
fn discovery_reports_an_attest_key_attested_on_another_card() {
    use relay_core::hw_attestation::testing::{LeafOptions, TestHierarchy};
    use relay_core::hw_attestation::HardwareAttestation;
    let h = TestHierarchy::new();
    let mut card = SoftCard::new(PIN).with_attestation(h.device(111, (5, 7, 4)));
    let attest = card.generate(slot(0x95), Algorithm::P256);
    let elsewhere = h.device(222, (5, 7, 4));
    let chain = elsewhere.chain(
        0x95,
        attest.spki(),
        &LeafOptions::for_device(&elsewhere, 2, 2),
    );
    let draft = ManifestDraft {
        version: 2,
        issued_at: NOW - 100,
        valid_until: NOW + 86_400,
        keys: vec![DraftKey {
            role: Role::Attest,
            label: "attest".into(),
            id: vec![0x10],
            token: "yk".into(),
            public_key: attest,
            hardware_attestation: Some(HardwareAttestation { chain }),
        }],
        ..Default::default()
    };
    let policy = relay_core::HardwarePolicy::with_roots(vec![h.root_der()]).unwrap();
    let manifest = Manifest::from_json_unverified(&draft.to_json().unwrap())
        .unwrap()
        .check_hardware_unverified(&policy, NOW)
        .unwrap();
    let engine = Engine::new(
        EngineConfig {
            device_id: "phone".into(),
            attestation_window_secs: 86_400,
            skew_secs: 60,
            renew_attestation: true,
        },
        manifest,
        Arc::new(SoftwareKey::generate_p256()),
        Vec::new(),
    );
    assert_eq!(engine.discover(&mut card).unwrap().len(), 1);
    let report = engine.last_discovery();
    assert!(
        report.contains("attest's hardware attestation names YubiKey 222, but this card is 111"),
        "{report}"
    );
}

#[test]
fn attestation_windows_respect_the_manifest_maximum() {
    let mut f = fixture(86_400);
    let max = f.manifest.max_attestation_window_secs;
    // Longer than the manifest allows: refused before the card is asked for anything.
    let sessions = f.card.sessions;
    let e = f
        .engine
        .attest(&mut f.card, PIN, NOW, NOW + max + 1)
        .unwrap_err();
    assert!(
        e.to_string().contains("longer than the manifest allows"),
        "{e}"
    );
    assert_eq!(
        f.card.sessions, sessions,
        "no card session for a refused window"
    );
    f.engine.attest(&mut f.card, PIN, NOW, NOW + max).unwrap();
    assert!(!f.engine.renewal_due(NOW + 1));

    // The manifest lowers the maximum: the current attestation is due for renewal at once.
    let mut lower = f.manifest.clone();
    lower.max_attestation_window_secs = 3_600;
    f.engine.set_manifest(lower);
    assert!(f.engine.renewal_due(NOW + 1));
}

// ---------- client grants (docs/client-grants.md) ----------

fn fp(f: &Fx, label: &str) -> relay_core::Fingerprint {
    f.manifest
        .keys
        .iter()
        .find(|k| k.label == label)
        .unwrap()
        .fingerprint
        .clone()
}

fn grant_bytes(post: &relay_approver::Post) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(post.body["grant"].as_str().unwrap())
        .unwrap()
}

fn rejected(f: &Fx, bytes: &[u8], at: u64) -> (Reason, String) {
    match f.engine.check_request(bytes, at).unwrap() {
        Checked::Rejected(r) => (r.reason(), r.why.clone()),
        Checked::Show(_) => panic!("shown"),
    }
}

/// Give pi5 (paired before grants) its first grant: the migration path.
fn granted(window: u64) -> (Fx, Vec<u8>) {
    let mut f = fixture(86_400);
    let sign = fp(&f, "sign");
    let post = f
        .engine
        .change_client("pi5", &[sign], window, &mut f.card, PIN, NOW)
        .unwrap();
    (f, grant_bytes(&post))
}

#[test]
fn a_local_pairing_migrates_to_a_grant() {
    let f = fixture(86_400);
    let before = f.engine.client_list(NOW);
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].state, relay_approver::ClientState::NoGrant);
    let (f, _) = granted(3_600);
    assert!(f.engine.clients().is_empty(), "the local record is dropped");
    let c = &f.engine.client_list(NOW)[0];
    assert_eq!(c.state, relay_approver::ClientState::Valid);
    assert!(c.accepted);
    assert_eq!(c.grant.as_ref().unwrap().seq, 1);
    let (req, _) = f.request("sign", NOW + 1);
    assert!(f.show(&req, NOW + 1).notice.is_none());
}

#[test]
fn a_grant_renews_during_an_approval_at_75_percent() {
    let (mut f, _) = granted(400);
    // Before 75%: no renewal.
    let (req, _) = f.request("sign", NOW + 200);
    let p = f.show(&req, NOW + 200);
    let a = f.engine.approve(&p, &mut f.card, PIN, NOW + 200).unwrap();
    assert!(a.approved && a.renewed_grant.is_none());
    // At 75%: renewed in the same card session, seq 2, same keys and window.
    let (req, reply) = f.request("sign", NOW + 300);
    let p = f.show(&req, NOW + 300);
    assert!(p.notice.is_none(), "renewing soon is not a notice");
    let sessions = f.card.sessions;
    let a = f.engine.approve(&p, &mut f.card, PIN, NOW + 300).unwrap();
    assert!(a.approved, "{:?}", a.grant_renewal_error);
    assert_eq!(f.card.sessions, sessions + 1, "one card session");
    let g = relay_core::grant::ClientGrant::decode(&a.renewed_grant.unwrap()).unwrap();
    assert_eq!(
        (g.fields.seq, g.fields.issued_at, g.fields.not_after),
        (2, NOW + 300, NOW + 700)
    );
    assert_eq!(g.fields.keys, vec![fp(&f, "sign")]);
    assert!(matches!(
        f.outcome(&a.response, &req, NOW + 310, reply),
        Outcome::Approved(_)
    ));
    assert_eq!(
        f.engine.client_list(NOW + 310)[0]
            .grant
            .as_ref()
            .unwrap()
            .seq,
        2
    );
}

#[test]
fn a_lapsed_client_is_shown_with_a_notice_and_renewed_by_approving() {
    let (mut f, _) = granted(400);
    let at = NOW + 400 + 61; // past not_after + skew
    assert_eq!(
        f.engine.client_list(at)[0].state,
        relay_approver::ClientState::Lapsed
    );
    let (req, reply) = f.request("sign", at);
    let p = f.show(&req, at);
    let n = p.notice.clone().expect("lapse notice");
    assert_eq!(n.lapsed_since, Some(NOW + 400));
    assert!(!n.first_on_device);
    // Denying leaves it lapsed.
    let d = f.engine.deny(&p, at).unwrap();
    assert!(matches!(
        f.outcome(&d, &req, at, reply),
        Outcome::Denied(Some(Reason::UserDenied))
    ));
    let (req, _) = f.request("sign", at + 1);
    assert!(f.show(&req, at + 1).notice.is_some());
    // Approving renews it in the same session.
    let (req, reply) = f.request("sign", at + 2);
    let p = f.show(&req, at + 2);
    let a = f.engine.approve(&p, &mut f.card, PIN, at + 2).unwrap();
    assert!(a.approved && a.renewed_grant.is_some());
    assert!(matches!(
        f.outcome(&a.response, &req, at + 2, reply),
        Outcome::Approved(_)
    ));
    let (req, _) = f.request("sign", at + 3);
    assert!(f.show(&req, at + 3).notice.is_none());
}

#[test]
fn a_new_device_accepts_an_existing_client_with_its_first_approval() {
    let (mut f, grant) = granted(3_600);
    // A second device: same manifest and card, no local pairing for pi5.
    let other = Engine::new(
        EngineConfig {
            device_id: "ipad".into(),
            attestation_window_secs: 86_400,
            skew_secs: 60,
            renew_attestation: true,
        },
        f.manifest.clone(),
        Arc::new(SoftwareKey::generate_p256()),
        vec![],
    );
    other.discover(&mut f.card).unwrap();
    other.attest(&mut f.card, PIN, NOW, NOW + 86_400).unwrap();
    let (req, _) = f.request("sign", NOW + 1);
    assert!(matches!(
        other.check_request(&req, NOW + 1).unwrap(),
        Checked::Rejected(r) if r.reason() == Reason::ClientNotGranted
    ));
    let b64 = base64::engine::general_purpose::STANDARD;
    assert!(other
        .ingest(
            &serde_json::json!({"grants": [b64.encode(&grant)]}),
            NOW + 1
        )
        .is_empty());
    fn first(f: &Fx, other: &Engine, at: u64) -> (PendingRequest, Vec<u8>, ReplyKey) {
        let (req, reply) = f.request("sign", at);
        match other.check_request(&req, at).unwrap() {
            Checked::Show(p) => (*p, req, reply),
            Checked::Rejected(r) => panic!("{}", r.why),
        }
    }
    let (p, req, reply) = first(&f, &other, NOW + 2);
    let n = p.notice.clone().expect("first-request notice");
    assert!(n.first_on_device && n.lapsed_since.is_none());
    assert_eq!(n.approved_by, "phone");
    let d = other.deny(&p, NOW + 2).unwrap();
    assert!(matches!(
        verify_response(&d, &req, &f.manifest, NOW + 2, 60, reply).unwrap(),
        Outcome::Denied(Some(Reason::UserDenied))
    ));
    let (p, req, reply) = first(&f, &other, NOW + 3);
    assert!(p.notice.as_ref().is_some_and(|n| n.first_on_device));
    let a = other.approve(&p, &mut f.card, PIN, NOW + 3).unwrap();
    assert!(matches!(
        verify_response(&a.response, &req, &f.manifest, NOW + 3, 60, reply).unwrap(),
        Outcome::Approved(_)
    ));
    let (p, _, _) = first(&f, &other, NOW + 4);
    assert!(p.notice.is_none(), "accepted");
    // A later grant for an accepted client needs no new notice.
    let sign = fp(&f, "sign");
    let sign2 = fp(&f, "sign2");
    let post = f
        .engine
        .change_client("pi5", &[sign, sign2], 3_600, &mut f.card, PIN, NOW + 5)
        .unwrap();
    assert!(other
        .ingest(
            &serde_json::json!({"grants": [b64.encode(grant_bytes(&post))]}),
            NOW + 5
        )
        .is_empty());
    let (req, _) = f.request("sign2", NOW + 6);
    match other.check_request(&req, NOW + 6).unwrap() {
        Checked::Show(p) => assert!(p.notice.is_none()),
        Checked::Rejected(r) => panic!("{}", r.why),
    }
    // Restored from saved state, acceptance survives.
    let (grants, revs) = other.grant_state();
    assert!(grants.iter().all(|(_, accepted)| *accepted));
    let again = Engine::new(
        other.config().clone(),
        f.manifest.clone(),
        Arc::new(SoftwareKey::generate_p256()),
        vec![],
    );
    again.restore_grants(&grants, &revs, NOW + 7);
    assert!(again.client_list(NOW + 7)[0].accepted);
}

#[test]
fn sequence_numbers_never_go_back() {
    let (mut f, first) = granted(3_600);
    let sign = fp(&f, "sign");
    let sign2 = fp(&f, "sign2");
    f.engine
        .change_client(
            "pi5",
            &[sign.clone(), sign2],
            3_600,
            &mut f.card,
            PIN,
            NOW + 1,
        )
        .unwrap();
    // The relay replays the older, narrower grant: kept as is.
    let b64 = base64::engine::general_purpose::STANDARD;
    assert!(f
        .engine
        .ingest(
            &serde_json::json!({"grants": [b64.encode(&first)]}),
            NOW + 2
        )
        .is_empty());
    let c = &f.engine.client_list(NOW + 2)[0];
    assert_eq!((c.grant.as_ref().unwrap().seq, c.keys.len()), (2, 2));
    // A different grant with the same seq is refused.
    let other = Engine::new(
        f.engine.config().clone(),
        f.manifest.clone(),
        Arc::new(SoftwareKey::generate_p256()),
        vec![PairedClient {
            client_id: "pi5".into(),
            public_key: f.client.public_key(),
            keys: vec![sign.clone()],
        }],
    );
    other.discover(&mut f.card).unwrap();
    let twin = other
        .change_client("pi5", &[sign], 7_200, &mut f.card, PIN, NOW + 3)
        .unwrap();
    let problems = f.engine.ingest(
        &serde_json::json!({"grants": [b64.encode(grant_bytes(&twin))]}),
        NOW + 3,
    );
    assert_eq!(problems.len(), 0, "seq 1 < 2: ignored, not a conflict");
}

#[test]
fn rejection_reasons_for_grants() {
    let (mut f, grant) = granted(3_600);
    // A key this device operates that the grant doesn't list.
    let (req, _) = f.request("sign2", NOW + 1);
    assert_eq!(rejected(&f, &req, NOW + 1).0, Reason::KeyNotGranted);
    // A client with no grant.
    let stranger = SoftwareKey::generate_ed25519();
    let key = f.manifest.keys.iter().find(|k| k.label == "sign").unwrap();
    let u = UnsignedRequest::new(
        "laptop",
        key,
        Op::Sign,
        Mechanism::EcdsaSha256,
        b"x".to_vec(),
        RequestContext {
            host: "laptop".into(),
            purpose: "x".into(),
            consumer: "x".into(),
        },
        ReplyKey::generate().public_bytes(),
        NOW + 1,
        NOW + 90,
    )
    .unwrap();
    let sig = stranger.sign(&u.to_be_signed());
    let req = u.with_signature(sig).bytes().to_vec();
    assert_eq!(rejected(&f, &req, NOW + 1).0, Reason::ClientNotGranted);
    // The client is in the manifest's revoked_clients.
    let mut json: serde_json::Value = serde_json::from_slice(f.manifest.bytes()).unwrap();
    json["revoked_clients"] = serde_json::json!([f.client.public_key().fingerprint().as_str()]);
    let revoked = Manifest::from_json_unverified(&serde_json::to_vec(&json).unwrap()).unwrap();
    f.engine.set_manifest(revoked);
    let (req, _) = f.request("sign", NOW + 2);
    assert_eq!(rejected(&f, &req, NOW + 2).0, Reason::ClientRevoked);
    assert_eq!(
        f.engine.client_list(NOW + 2)[0].state,
        relay_approver::ClientState::RevokedInManifest
    );
    // The attest key that signed the grant left the manifest: the grant no longer counts.
    let mut json: serde_json::Value = serde_json::from_slice(f.manifest.bytes()).unwrap();
    let new_attest = SoftCard::new(PIN).generate(slot(0x95), Algorithm::P256);
    let attest = json["keys"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|k| k["role"] == "attest")
        .unwrap();
    attest["public_key"] = base64::engine::general_purpose::STANDARD
        .encode(new_attest.spki())
        .into();
    attest["fingerprint"] = new_attest.fingerprint().as_str().into();
    let rekeyed = Manifest::from_json_unverified(&serde_json::to_vec(&json).unwrap()).unwrap();
    f.engine.set_manifest(rekeyed);
    let (req, _) = f.request("sign", NOW + 3);
    assert_eq!(rejected(&f, &req, NOW + 3).0, Reason::ClientNotGranted);
    assert_eq!(
        f.engine.client_list(NOW + 3)[0].state,
        relay_approver::ClientState::CannotVerify
    );
    f.engine.set_manifest(f.manifest.clone());
    // Revoked with a signed revocation: denied, and the old grant is refused if replayed.
    let post = f
        .engine
        .revoke_client("pi5", &mut f.card, PIN, NOW + 4)
        .unwrap();
    assert_eq!(post.path, "/v1/clients/pi5/revocation");
    let (req, _) = f.request("sign", NOW + 5);
    assert_eq!(rejected(&f, &req, NOW + 5).0, Reason::ClientNotGranted);
    let b64 = base64::engine::general_purpose::STANDARD;
    let problems = f.engine.ingest(
        &serde_json::json!({"grants": [b64.encode(&grant)]}),
        NOW + 6,
    );
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(f.engine.client_list(NOW + 6).is_empty());
    // The denial a rejected request gets carries the reason.
    let (req, reply) = f.request("sign", NOW + 7);
    let r = match f.engine.check_request(&req, NOW + 7).unwrap() {
        Checked::Rejected(r) => r,
        Checked::Show(_) => panic!("shown"),
    };
    let d = f.engine.sign_rejection(&r, NOW + 7).unwrap();
    assert!(matches!(
        f.outcome(&d, &req, NOW + 7, reply),
        Outcome::Denied(Some(Reason::ClientNotGranted))
    ));
}
