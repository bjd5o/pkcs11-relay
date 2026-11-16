//! Reading keys from a card and signing attestations with its attest key. These go through
//! `relay-core`'s PIV layer over any `CardTransport` (PC/SC in production, the softcard in
//! tests), so the CLI exercises the same code the approvers use.

use relay_core::attestation::{AttestationStatement, UnsignedAttestation};
use relay_core::piv::{self, CardTransport, PivError, Slot};
use relay_core::PublicKey;

/// Every PIV key slot, in display order.
pub fn all_slots() -> Vec<Slot> {
    [0x9a, 0x9c, 0x9d, 0x9e]
        .into_iter()
        .chain(0x82..=0x95)
        .map(|s| Slot::new(s).expect("slot"))
        .collect()
}

/// The public key in every slot that has a certificate.
pub fn list(card: &mut dyn CardTransport) -> Result<Vec<(Slot, PublicKey)>, String> {
    piv::select(card).map_err(|e| e.to_string())?;
    Ok(all_slots()
        .into_iter()
        .filter_map(|s| piv::read_public_key(card, s).ok().map(|k| (s, k)))
        .collect())
}

pub fn export(card: &mut dyn CardTransport, slot: Slot) -> Result<PublicKey, String> {
    piv::select(card).map_err(|e| e.to_string())?;
    piv::read_public_key(card, slot).map_err(|e| format!("slot {:02x}: {e}", slot.id()))
}

/// Sign a device attestation with the attest key in `slot`: one PIN attempt, never retried
/// (CLAUDE.md hardware safety). Touch happens on the card if its policy requires it.
pub fn attest(
    card: &mut dyn CardTransport,
    slot: Slot,
    pin: &[u8],
    device_id: &str,
    device_key: PublicKey,
    not_before: u64,
    not_after: u64,
) -> Result<AttestationStatement, String> {
    piv::select(card).map_err(|e| e.to_string())?;
    let attest_key = piv::read_public_key(card, slot)
        .map_err(|e| format!("attest slot {:02x}: {e}", slot.id()))?;
    let st = UnsignedAttestation::new(
        device_id,
        device_key,
        not_before,
        not_after,
        attest_key.fingerprint().clone(),
    )
    .map_err(|e| e.to_string())?;
    match piv::verify_pin(card, pin) {
        Ok(()) => {}
        Err(PivError::WrongPin { retries }) => {
            return Err(format!(
                "wrong PIN ({retries} tries left); stopping without retrying"
            ))
        }
        Err(e) => return Err(e.to_string()),
    }
    piv::sign_attestation(card, slot, st).map_err(|e| e.to_string())
}

pub fn fingerprint_line(slot: Slot, k: &PublicKey) -> String {
    format!(
        "{:02x}  {:<9} {}",
        slot.id(),
        k.algorithm().as_str(),
        k.fingerprint()
    )
}
