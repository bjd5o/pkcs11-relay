//! The softcard's `GET ATTESTATION`, `F9` certificate and `GET SERIAL`, read through relay-core
//! and verified with the same function clients use.

use relay_core::hw_attestation::testing::TestHierarchy;
use relay_core::hw_attestation::{verify_piv_attestation, PinPolicy, TouchPolicy};
use relay_core::piv::{self, PivError, Slot};
use relay_core::Algorithm;
use relay_softcard::{SlotKey, SoftCard};

const NOW: u64 = 1_795_000_000;

fn slot(id: u8) -> Slot {
    Slot::new(id).unwrap()
}

#[test]
fn generated_key_is_attested_and_verifies() {
    let h = TestHierarchy::new();
    let mut card = SoftCard::new(b"123456").with_attestation(h.device(23_456_789, (5, 7, 4)));
    let pk = card.generate(slot(0x85), Algorithm::P256);
    card.set_policy(slot(0x85), 0x03, 0x02);

    piv::select(&mut card).unwrap();
    assert_eq!(piv::get_serial(&mut card).unwrap(), 23_456_789);
    let leaf = piv::get_attestation(&mut card, slot(0x85)).unwrap();
    let f9 = piv::read_f9_certificate(&mut card).unwrap();
    let mut chain = vec![leaf, f9];
    chain.extend(h.intermediates());

    let a = verify_piv_attestation(&chain, &pk, &[h.root_der()], NOW).unwrap();
    assert_eq!(a.serial, 23_456_789);
    assert_eq!(a.pin_policy, PinPolicy::Always);
    assert_eq!(a.touch_policy, TouchPolicy::Always);
}

#[test]
fn imported_keys_and_cards_without_attestation_refuse() {
    let h = TestHierarchy::new();
    let mut card = SoftCard::new(b"123456").with_attestation(h.device(1, (5, 7, 4)));
    let key = SlotKey::generate(Algorithm::P256);
    let cert = key.self_signed_certificate("imported");
    card.insert(slot(0x86), key, cert);
    piv::select(&mut card).unwrap();
    assert!(matches!(
        piv::get_attestation(&mut card, slot(0x86)),
        Err(PivError::Status(0x6a80))
    ));
    assert!(matches!(
        piv::get_attestation(&mut card, slot(0x87)),
        Err(PivError::NotFound)
    ));

    let mut plain = SoftCard::new(b"123456");
    plain.generate(slot(0x85), Algorithm::P256);
    piv::select(&mut plain).unwrap();
    assert!(matches!(
        piv::get_attestation(&mut plain, slot(0x85)),
        Err(PivError::Status(0x6d00))
    ));
    assert!(matches!(
        piv::read_f9_certificate(&mut plain),
        Err(PivError::NotFound)
    ));
    assert_eq!(
        piv::get_serial(&mut plain).unwrap(),
        relay_softcard::DEFAULT_SERIAL
    );
}
