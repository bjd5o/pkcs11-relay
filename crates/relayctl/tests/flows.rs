//! relayctl's manifest and attestation flows, end to end: the files it writes are checked with
//! relay-core exactly as clients and approvers check them.

use std::path::{Path, PathBuf};
use std::process::Command;

use relay_core::hw_attestation::testing::TestHierarchy;
use relay_core::manifest::PgpSecretKey;
use relay_core::piv::Slot;
use relay_core::HardwarePolicy;
use relay_core::{verify_attestation, Algorithm, Role};
use relay_softcard::SoftCard;
use relayctl::{card, hw, manifest, util};

const SERIAL: u32 = 31_415_926;

/// A synthetic attestation hierarchy and the PEM file `--attestation-roots` reads.
fn anchors(dir: &Path, h: &TestHierarchy) -> hw::Anchors {
    use x509_cert::der::{Decode, EncodePem};
    let mut pem = String::new();
    for der in std::iter::once(h.root_der()).chain(h.intermediates()) {
        pem.push_str(
            &x509_cert::Certificate::from_der(&der)
                .unwrap()
                .to_pem(x509_cert::der::pem::LineEnding::LF)
                .unwrap(),
        );
    }
    let p = dir.join("roots.pem");
    std::fs::write(&p, pem).unwrap();
    hw::Anchors::load(Some(&p)).unwrap()
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("relayctl-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A software OpenPGP signer: (secret key file, public key file).
fn pgp(dir: &Path) -> (PathBuf, PathBuf) {
    let k = PgpSecretKey::generate("relayctl test <test@test.invalid>").unwrap();
    let (s, p) = (dir.join("signer.sec.asc"), dir.join("signer.pub.asc"));
    std::fs::write(&s, k.to_armored().unwrap().as_bytes()).unwrap();
    std::fs::write(&p, k.public_armored().unwrap()).unwrap();
    (s, p)
}

fn slot(s: u8) -> Slot {
    Slot::new(s).unwrap()
}

#[test]
fn imported_keys_cannot_be_attested() {
    let dir = tmp("imported");
    let h = TestHierarchy::new();
    let anchors = anchors(&dir, &h);
    let mut yk = SoftCard::new(b"123456").with_attestation(h.device(SERIAL, (5, 7, 4)));
    let key = relay_softcard::SlotKey::generate(Algorithm::P256);
    let cert = key.self_signed_certificate("imported");
    yk.insert(slot(0x86), key, cert);
    let e = hw::from_card(&mut yk, slot(0x86), &anchors, util::now()).unwrap_err();
    assert!(e.contains("only keys generated on the card"), "{e}");
}

#[test]
fn manifest_round_trip_and_attestation() {
    let dir = tmp("flow");
    let (sec, public) = pgp(&dir);
    let m = dir.join("manifest.json");

    let h = TestHierarchy::new();
    let anchors = anchors(&dir, &h);
    let policy = anchors.policy().unwrap();
    let mut yk = SoftCard::new(b"123456").with_attestation(h.device(SERIAL, (5, 7, 4)));
    yk.generate(slot(0x95), Algorithm::P256);
    yk.generate(slot(0x9c), Algorithm::Ed25519);
    yk.generate(slot(0x9d), Algorithm::Rsa2048);
    let keys = card::list(&mut yk).unwrap();
    assert_eq!(keys.len(), 3, "list finds every populated slot");
    assert_eq!(yk.sessions, 1, "list uses one card session");

    manifest::init(&m).unwrap();
    assert!(manifest::init(&m).is_err(), "init never overwrites");
    let (attest, chain, facts) = hw::from_card(&mut yk, slot(0x95), &anchors, util::now()).unwrap();
    assert_eq!(attest, card::export(&mut yk, slot(0x95)).unwrap());
    assert_eq!(facts.serial, SERIAL);
    assert!(hw::describe(&facts).contains("touch always"));
    manifest::add(
        &m,
        attest.clone(),
        Some(chain),
        Role::Attest,
        "attest",
        "10",
        "yk",
    )
    .unwrap();
    manifest::add(
        &m,
        card::export(&mut yk, slot(0x9c)).unwrap(),
        None,
        Role::Sign,
        "release",
        "01",
        "yk",
    )
    .unwrap();
    manifest::add(
        &m,
        card::export(&mut yk, slot(0x9d)).unwrap(),
        None,
        Role::Encrypt,
        "unseal",
        "02",
        "yk",
    )
    .unwrap();
    // relay-core's validation runs on every edit.
    assert!(manifest::add(
        &m,
        card::export(&mut yk, slot(0x9c)).unwrap(),
        None,
        Role::Encrypt,
        "x",
        "03",
        "yk"
    )
    .is_err());
    let shown = manifest::show(&m, &anchors).unwrap();
    assert!(shown.contains("release"));
    assert!(
        shown.contains(&format!("attested: YubiKey serial {SERIAL}")),
        "{shown}"
    );
    // Yubico's real anchors do not accept the synthetic chain.
    let yubico = hw::Anchors::load(None).unwrap();
    assert!(manifest::show(&m, &yubico)
        .unwrap()
        .contains("attestation INVALID"));

    // Export through the PEM path, as `key export` / `manifest add --public-key` do.
    let pem = dir.join("unseal.pem");
    std::fs::write(
        &pem,
        util::public_key_pem(&card::export(&mut yk, slot(0x9d)).unwrap()),
    )
    .unwrap();
    assert_eq!(
        util::read_public_key(&pem).unwrap(),
        card::export(&mut yk, slot(0x9d)).unwrap()
    );

    let v = manifest::sign(
        &m,
        30,
        manifest::Signer::Software(&sec),
        Some((&public, &policy)),
    )
    .unwrap();
    assert_eq!(v, 2);
    let accepted = dir.join("accepted.json");
    std::fs::copy(&m, &accepted).unwrap();
    std::fs::copy(manifest::sig_path(&m), manifest::sig_path(&accepted)).unwrap();

    assert_eq!(
        manifest::remove(&m, None, Some("release"), Some("yk")).unwrap(),
        1
    );
    manifest::sign(&m, 30, manifest::Signer::Software(&sec), None).unwrap();
    let mf = manifest::verify(
        &m,
        &manifest::sig_path(&m),
        &public,
        &policy,
        Some(&accepted),
        60,
    )
    .unwrap();
    assert_eq!(
        mf.keys
            .iter()
            .find(|k| k.role == Role::Attest)
            .unwrap()
            .attested
            .unwrap()
            .serial,
        SERIAL
    );
    assert!(
        manifest::verify(
            &m,
            &manifest::sig_path(&m),
            &public,
            &HardwarePolicy::default(),
            None,
            60
        )
        .is_err(),
        "Yubico's root does not accept the synthetic chain"
    );
    assert_eq!(mf.version, 3);
    // Rollback to the older copy is refused against the newer cached one.
    let e = manifest::verify(
        &accepted,
        &manifest::sig_path(&accepted),
        &public,
        &policy,
        Some(&m),
        60,
    )
    .unwrap_err();
    assert!(e.contains("ManifestRolledBack"), "{e}");
    // Tampering after signing is caught.
    let mut json = std::fs::read(&m).unwrap();
    let i = json.iter().position(|&b| b == b'u').unwrap();
    json[i] = b'v';
    std::fs::write(dir.join("t.json"), &json).unwrap();
    assert!(manifest::verify(
        &dir.join("t.json"),
        &manifest::sig_path(&m),
        &public,
        &policy,
        None,
        60
    )
    .is_err());

    // Attest a device key with the card's attest key; the approver-side check accepts it.
    let device = SoftCard::new(b"000000").generate(slot(0x82), Algorithm::P256);
    let now = util::now();
    let before = yk.sessions;
    let st = card::attest(
        &mut yk,
        slot(0x95),
        b"123456",
        "approver-1",
        device.clone(),
        now - 10,
        now + 86_400,
    )
    .unwrap();
    assert_eq!(
        yk.sessions,
        before + 1,
        "PIN and signature share one session"
    );
    let ok = verify_attestation(st.bytes(), &mf, now, 60).unwrap();
    assert_eq!(ok.device_key, device);
    assert_eq!(&ok.attest_key_fingerprint, attest.fingerprint());
}

#[test]
fn attest_stops_after_one_wrong_pin() {
    let mut yk = SoftCard::new(b"123456");
    yk.generate(slot(0x95), Algorithm::P256);
    let device = SoftCard::new(b"0").generate(slot(0x82), Algorithm::P256);
    let before = yk.pin_retries();
    let e = card::attest(&mut yk, slot(0x95), b"654321", "d", device, 0, 10).unwrap_err();
    assert!(e.contains("stopping without retrying"), "{e}");
    assert_eq!(yk.pin_retries(), before - 1, "exactly one attempt");
}

/// `Signer::Gpg` with a throwaway GNUPGHOME; skipped when gpg is not installed.
#[test]
fn gpg_signing() {
    if Command::new("gpg").arg("--version").output().is_err() {
        eprintln!("gpg not installed; skipping");
        return;
    }
    let dir = tmp("gpg");
    let home = dir.join("gnupg");
    std::fs::create_dir_all(&home).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let gpg = |args: &[&str]| {
        let o = Command::new("gpg")
            .env("GNUPGHOME", &home)
            .args(["--batch", "--pinentry-mode", "loopback", "--passphrase", ""])
            .args(args)
            .output()
            .unwrap();
        assert!(
            o.status.success(),
            "gpg {args:?}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        o.stdout
    };
    gpg(&[
        "--quick-generate-key",
        "relayctl gpg test <gpg@test.invalid>",
        "ed25519",
        "sign",
        "1d",
    ]);
    let public = dir.join("signer.asc");
    std::fs::write(&public, gpg(&["--armor", "--export", "gpg@test.invalid"])).unwrap();

    let m = dir.join("manifest.json");
    manifest::init(&m).unwrap();
    // This attest key has no hardware attestation; the manifest says it needn't.
    manifest::set(&m, Some(false), None, Some(14 * 86_400)).unwrap();
    assert!(manifest::show(&m, &hw::Anchors::load(None).unwrap())
        .unwrap()
        .contains("hardware attestation not required; attestation window at most 7d"));
    // The emergency lists: sorted, no duplicates, and removable.
    let a = format!("sha256:{}", "a".repeat(64));
    let b = format!("sha256:{}", "b".repeat(64));
    assert!(manifest::revoke(&m, manifest::Revoked::Clients, &b, false).unwrap());
    assert!(manifest::revoke(&m, manifest::Revoked::Clients, &a, false).unwrap());
    assert!(!manifest::revoke(&m, manifest::Revoked::Clients, &a, false).unwrap());
    assert!(manifest::revoke(&m, manifest::Revoked::Devices, &a, false).unwrap());
    assert!(manifest::revoke(&m, manifest::Revoked::Clients, "sha256:nope", false).is_err());
    let d = relay_core::ManifestDraft::from_json(&std::fs::read(&m).unwrap()).unwrap();
    assert_eq!(d.max_client_grant_window_secs, 14 * 86_400);
    assert_eq!(
        d.revoked_clients
            .iter()
            .map(|f| f.as_str())
            .collect::<Vec<_>>(),
        vec![a.as_str(), b.as_str()]
    );
    assert!(manifest::revoke(&m, manifest::Revoked::Clients, &a, true).unwrap());
    assert!(manifest::revoke(&m, manifest::Revoked::Clients, &b, true).unwrap());
    assert!(manifest::revoke(&m, manifest::Revoked::Devices, &a, true).unwrap());
    let mut yk = SoftCard::new(b"123456");
    manifest::add(
        &m,
        yk.generate(slot(0x95), Algorithm::P256),
        None,
        Role::Attest,
        "attest",
        "10",
        "yk",
    )
    .unwrap();
    // The signer program is a wrapper that pins GNUPGHOME and the batch flags.
    let wrapper = dir.join("gpg-wrap.sh");
    std::fs::write(
        &wrapper,
        format!("#!/bin/sh\nexec gpg --homedir '{}' --batch --pinentry-mode loopback --passphrase '' \"$@\"\n", home.display()),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let program = wrapper.to_str().unwrap();
    manifest::sign(
        &m,
        7,
        manifest::Signer::Gpg {
            key: "gpg@test.invalid",
            program,
        },
        Some((&public, &HardwarePolicy::yubico())),
    )
    .unwrap();
    let _ = Command::new("gpgconf")
        .env("GNUPGHOME", &home)
        .args(["--kill", "all"])
        .status();
}

/// A transport that runs sessions but never resets the card, standing in for a PC/SC layer
/// that ignores `SCARD_RESET_CARD`.
struct NoReset(SoftCard);

impl relay_core::piv::CardTransport for NoReset {
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, relay_core::piv::PivError> {
        self.0.transmit(apdu)
    }
    fn session(
        &mut self,
        f: &mut dyn FnMut(&mut dyn relay_core::piv::CardTransport),
    ) -> Result<(), relay_core::piv::PivError> {
        f(self);
        Ok(())
    }
}

#[test]
fn pin_reset_check() {
    for alg in [
        Algorithm::P256,
        Algorithm::P384,
        Algorithm::Ed25519,
        Algorithm::Rsa2048,
    ] {
        let mut yk = SoftCard::new(b"123456");
        yk.generate(slot(0x86), alg);
        let before = yk.pin_retries();
        assert_eq!(
            card::check_pin_reset(&mut yk, slot(0x86), b"123456").unwrap(),
            card::PinReset::Cleared,
            "{alg:?}"
        );
        assert_eq!(
            yk.pin_retries(),
            before,
            "the refused step costs no PIN attempt"
        );

        let mut leaky = SoftCard::new(b"123456");
        leaky.generate(slot(0x86), alg);
        let mut leaky = NoReset(leaky);
        assert_eq!(
            card::check_pin_reset(&mut leaky, slot(0x86), b"123456").unwrap(),
            card::PinReset::StillVerified,
            "{alg:?}"
        );
    }
    // A wrong PIN stops after one attempt; X25519 cannot sign.
    let mut yk = SoftCard::new(b"123456");
    yk.generate(slot(0x86), Algorithm::P256);
    let e = card::check_pin_reset(&mut yk, slot(0x86), b"000000").unwrap_err();
    assert!(e.contains("stopping without retrying"), "{e}");
    yk.generate(slot(0x87), Algorithm::X25519);
    assert!(card::check_pin_reset(&mut yk, slot(0x87), b"123456")
        .unwrap_err()
        .contains("cannot sign"));
}

#[test]
fn app_link_signs_a_verifiable_link_and_draws_it() {
    use relayctl::link;
    let dir = tmp("link");
    let (sec, public) = pgp(&dir);
    // Any CA certificate will do for the pin; the relay check is skipped here (the simulator
    // end-to-end test runs it against a real relay).
    relay_test_ca(&dir);
    let svg = dir.join("link.svg");
    let l = link::make(link::Options {
        relay_url: Some("https://10.0.0.170:8443".into()),
        relay_ca: Some(dir.join("ca.pem")),
        public_relay: false,
        signer: Some(link::LinkSigner::Software(&sec)),
        device_id: Some("iphone".into()),
        valid_for: Some(900),
        no_input: true,
        skip_relay_check: true,
        svg: Some(svg.clone()),
        relay_admin: None,
        replace: false,
    })
    .unwrap();
    let signer = relay_core::ManifestSigner::from_bytes(&std::fs::read(&public).unwrap()).unwrap();
    let v = relay_core::setup_link::verify_setup_link(&l.url, &signer, util::now(), 60).unwrap();
    assert_eq!(v.device, "iphone");
    assert_eq!(
        v.ca,
        Some(link::ca_pin(&std::fs::read(dir.join("ca.pem")).unwrap()).unwrap())
    );
    assert_eq!(l.exp - v.iat, 900);
    assert!(std::fs::read_to_string(&svg).unwrap().contains("<svg"));
    let shown = link::show(&l).unwrap();
    assert!(shown.starts_with(&l.url));
    assert!(shown.contains('▀') || shown.contains('▄') || shown.contains('█'));

    // Missing values fail with --no-input; bad values fail before signing.
    let base = || link::Options {
        relay_url: Some("https://10.0.0.170:8443".into()),
        relay_ca: None,
        public_relay: true,
        signer: Some(link::LinkSigner::Software(&sec)),
        device_id: Some("iphone".into()),
        valid_for: None,
        no_input: true,
        skip_relay_check: true,
        svg: None,
        relay_admin: None,
        replace: false,
    };
    assert!(link::make(link::Options {
        device_id: None,
        ..base()
    })
    .err()
    .unwrap()
    .contains("--device-id"));
    assert!(link::make(link::Options {
        device_id: Some("Bad Id".into()),
        ..base()
    })
    .is_err());
    assert!(link::make(link::Options {
        valid_for: Some(8 * 86_400),
        ..base()
    })
    .err()
    .unwrap()
    .contains("7d"));
    assert!(link::make(link::Options {
        relay_url: Some("http://x".into()),
        ..base()
    })
    .is_err());
    assert!(link::make(link::Options {
        replace: true,
        ..base()
    })
    .err()
    .unwrap()
    .contains("--relay-config"));
    // A publicly trusted relay has no CA pin.
    let l = link::make(base()).unwrap();
    assert!(!l.url.contains("&ca="));
}

/// Writes `ca.pem`: a self-signed P-256 certificate, as a relay CA would be.
fn relay_test_ca(dir: &Path) {
    let k = relay_softcard::SlotKey::generate(Algorithm::P256);
    let der = k.self_signed_certificate("test relay CA");
    std::fs::write(
        dir.join("ca.pem"),
        relay_core::hw_attestation::testing::to_pem(&[der]),
    )
    .unwrap();
}

#[test]
fn verify_ff_clears_the_pin_within_a_session() {
    // The softcard implements VERIFY P1=FF; a card that ignores it would sign twice.
    let mut card = NoReset(SoftCard::new(b"123456"));
    card.0.generate(slot(0x86), Algorithm::P256);
    assert_eq!(
        card::check_security_reset(&mut card, slot(0x86), b"123456").unwrap(),
        card::PinReset::Cleared
    );
    let e = card::check_security_reset(&mut card, slot(0x86), b"000000").unwrap_err();
    assert!(e.contains("wrong PIN"), "{e}");
}
