//! wire-format §9.4: YubiKey PIV attestation chains, against a synthetic hierarchy with the
//! same shape as Yubico's.

use relay_core::hw_attestation::testing::{
    der_integer, extension, HierarchyOptions, LeafOptions, TestDevice, TestHierarchy,
};
use relay_core::hw_attestation::{verify_piv_attestation, PinPolicy, TouchPolicy};
use relay_core::{Error, PublicKey};

const NOW: u64 = 1_795_000_000; // 2026-11
const SERIAL: u32 = 12_345_678;

fn attest_key() -> PublicKey {
    let k = <p256::ecdsa::SigningKey as p256::elliptic_curve::Generate>::generate_from_rng(
        &mut rand_core::UnwrapErr(getrandom::SysRng),
    );
    let der = p256::pkcs8::EncodePublicKey::to_public_key_der(k.verifying_key()).unwrap();
    PublicKey::from_spki(der.as_bytes()).unwrap()
}

struct Setup {
    h: TestHierarchy,
    d: TestDevice,
    key: PublicKey,
}

fn setup_with(options: HierarchyOptions, firmware: (u8, u8, u8)) -> Setup {
    let h = TestHierarchy::with_options(options);
    let d = h.device(SERIAL, firmware);
    Setup {
        h,
        d,
        key: attest_key(),
    }
}

fn setup() -> Setup {
    setup_with(HierarchyOptions::default(), (5, 7, 4))
}

impl Setup {
    fn opts(&self) -> LeafOptions {
        LeafOptions::for_device(&self.d, 2, 2)
    }
    fn chain(&self, o: &LeafOptions) -> Vec<Vec<u8>> {
        self.d.chain(0x85, self.key.spki(), o)
    }
    fn verify(&self, chain: &[Vec<u8>]) -> relay_core::Result<relay_core::PivAttestation> {
        verify_piv_attestation(chain, &self.key, &[self.h.root_der()], NOW)
    }
}

fn assert_invalid(r: relay_core::Result<relay_core::PivAttestation>, needle: &str) {
    match r {
        Err(Error::HardwareAttestationInvalid(m)) => {
            assert!(m.contains(needle), "expected '{needle}' in '{m}'")
        }
        other => panic!("expected HardwareAttestationInvalid({needle}), got {other:?}"),
    }
}

#[test]
fn valid_chain_yields_the_card_facts() {
    let s = setup();
    let a = s.verify(&s.chain(&s.opts())).unwrap();
    assert_eq!(a.serial, SERIAL);
    assert_eq!(a.firmware, (5, 7, 4));
    assert_eq!(a.firmware_string(), "5.7.4");
    assert_eq!(a.pin_policy, PinPolicy::Once);
    assert_eq!(a.touch_policy, TouchPolicy::Always);
    assert_eq!(a.form_factor, Some(3));
    let e = Error::HardwareAttestationInvalid("x".into());
    assert_eq!(e.failure_row(), relay_core::FailureRow::ManifestRejected);
    assert_eq!(e.ckr(), None);
}

#[test]
fn every_policy_byte_is_decoded() {
    let s = setup();
    for (p, t, pin, touch) in [
        (1, 1, PinPolicy::Never, TouchPolicy::Never),
        (3, 3, PinPolicy::Always, TouchPolicy::Cached),
    ] {
        let mut o = s.opts();
        o.policy = Some(vec![p, t]);
        let a = s.verify(&s.chain(&o)).unwrap();
        assert_eq!((a.pin_policy, a.touch_policy), (pin, touch));
    }
    let mut o = s.opts();
    o.policy = Some(vec![4, 2]);
    assert_invalid(s.verify(&s.chain(&o)), "unknown PIN policy");
    o.policy = Some(vec![2, 0]);
    assert_invalid(s.verify(&s.chain(&o)), "unknown touch policy");
    o.policy = Some(vec![2]);
    assert_invalid(s.verify(&s.chain(&o)), "policy extension");
}

#[test]
fn leaf_must_attest_the_listed_key() {
    let s = setup();
    let chain = s.chain(&s.opts());
    assert_invalid(
        verify_piv_attestation(&chain, &attest_key(), &[s.h.root_der()], NOW),
        "different public key",
    );
}

#[test]
fn broken_signature_fails() {
    let s = setup();
    let mut chain = s.chain(&s.opts());
    let n = chain[0].len();
    chain[0][n - 1] ^= 1;
    assert!(s.verify(&chain).is_err());
}

#[test]
fn other_roots_and_missing_links_fail() {
    let s = setup();
    let chain = s.chain(&s.opts());
    let other = TestHierarchy::new();
    assert_invalid(
        verify_piv_attestation(&chain, &s.key, &[other.root_der()], NOW),
        "does not verify",
    );
    assert_invalid(
        verify_piv_attestation(
            &chain,
            &s.key,
            &[relay_core::hw_attestation::YUBICO_ATTESTATION_ROOT_1.to_vec()],
            NOW,
        ),
        "does not verify",
    );
    // Without the PIV CA the path cannot be built.
    let gap = vec![chain[0].clone(), chain[1].clone(), chain[3].clone()];
    assert_invalid(s.verify(&gap), "does not verify");
}

#[test]
fn only_the_piv_branch_is_accepted() {
    let s = setup_with(
        HierarchyOptions {
            branch_cn: "Yubico OPGP Attestation Test 1".into(),
            ..Default::default()
        },
        (5, 7, 4),
    );
    assert_invalid(s.verify(&s.chain(&s.opts())), "PIV Attestation CA");
}

#[test]
fn f9_certificate_must_be_a_ca() {
    let s = setup_with(
        HierarchyOptions {
            f9_is_ca: false,
            ..Default::default()
        },
        (5, 7, 4),
    );
    assert_invalid(s.verify(&s.chain(&s.opts())), "does not verify");
}

#[test]
fn expired_chain_fails() {
    let s = setup_with(
        HierarchyOptions {
            f9_not_after: NOW - 1,
            ..Default::default()
        },
        (5, 7, 4),
    );
    assert_invalid(s.verify(&s.chain(&s.opts())), "does not verify");
}

#[test]
fn unknown_critical_extension_fails_and_eku_is_ignored() {
    let s = setup();
    let mut o = s.opts();
    o.extra = vec![extension("1.2.3.4.5", true, vec![0x05, 0x00])];
    assert_invalid(s.verify(&s.chain(&o)), "UnsupportedCriticalExtension");
    // id-kp-clientAuth, not critical.
    let mut o = s.opts();
    o.extra = vec![extension(
        "2.5.29.37",
        false,
        vec![
            0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02,
        ],
    )];
    s.verify(&s.chain(&o)).unwrap();
}

#[test]
fn yubico_extensions_must_be_present_and_well_formed() {
    let s = setup();
    type Edit = fn(&mut LeafOptions);
    let cases: [(Edit, &str); 6] = [
        (|o| o.firmware = None, "no firmware"),
        (|o| o.serial = None, "no serial"),
        (|o| o.policy = None, "no policy"),
        (|o| o.firmware = Some(vec![5, 7]), "3 bytes"),
        (|o| o.serial = Some(vec![0x04, 1, 1]), "DER INTEGER"),
        (|o| o.form_factor = Some(vec![1, 2]), "form factor"),
    ];
    for (edit, needle) in cases {
        let mut o = s.opts();
        edit(&mut o);
        assert_invalid(s.verify(&s.chain(&o)), needle);
    }
    let mut o = s.opts();
    o.form_factor = None;
    assert_eq!(s.verify(&s.chain(&o)).unwrap().form_factor, None);
    o.serial = Some(der_integer(u32::MAX));
    assert_eq!(s.verify(&s.chain(&o)).unwrap().serial, u32::MAX);
}

#[test]
fn firmware_before_5_7_4_fails() {
    for (fw, ok) in [
        ((5, 7, 3), false),
        ((5, 4, 3), false),
        ((5, 7, 4), true),
        ((5, 8, 0), true),
    ] {
        let s = setup_with(HierarchyOptions::default(), fw);
        let r = s.verify(&s.chain(&s.opts()));
        if ok {
            r.unwrap();
        } else {
            assert_invalid(r, "older than 5.7.4");
        }
    }
}

#[test]
fn chain_size_limits() {
    let s = setup();
    let chain = s.chain(&s.opts());
    assert_invalid(s.verify(&chain[..1]), "2-4 certificates");
    let mut long = chain.clone();
    long.push(chain[3].clone());
    assert_invalid(s.verify(&long), "2-4 certificates");
    let mut big = chain.clone();
    big[1] = vec![0x30; 2049];
    assert_invalid(s.verify(&big), "exceeds 2048");
    assert_invalid(
        s.verify(&[vec![1, 2, 3], chain[1].clone()]),
        "leaf certificate",
    );
}

#[test]
fn assemble_chain_picks_the_intermediates_by_issuer() {
    use relay_core::hw_attestation::assemble_chain;
    let s = setup();
    let chain = s.chain(&s.opts());
    let mut pool = s.h.intermediates();
    pool.reverse();
    pool.push(s.h.root_der());
    pool.extend(TestHierarchy::new().intermediates());
    let built = assemble_chain(chain[0].clone(), chain[1].clone(), &pool).unwrap();
    assert_eq!(built, chain);
    s.verify(&built).unwrap();
    // With nothing to add, the chain stays leaf + F9 and does not verify.
    let short = assemble_chain(chain[0].clone(), chain[1].clone(), &[]).unwrap();
    assert_eq!(short.len(), 2);
    assert!(s.verify(&short).is_err());
}
