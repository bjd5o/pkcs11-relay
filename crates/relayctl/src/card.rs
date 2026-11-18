//! Reading keys from a card and signing attestations with its attest key. These go through
//! `relay-core`'s PIV layer over any `CardTransport` (PC/SC in production, the softcard in
//! tests), so the CLI exercises the same code the approvers use.

use relay_core::attestation::{AttestationStatement, UnsignedAttestation};
use relay_core::piv::{self, CardTransport, PivError, Slot};
use relay_core::{Algorithm, Mechanism, PublicKey};

/// Every PIV key slot, in display order.
pub fn all_slots() -> Vec<Slot> {
    [0x9a, 0x9c, 0x9d, 0x9e]
        .into_iter()
        .chain(0x82..=0x95)
        .map(|s| Slot::new(s).expect("slot"))
        .collect()
}

/// The public key in every slot that has a certificate (one card session).
pub fn list(card: &mut dyn CardTransport) -> Result<Vec<(Slot, PublicKey)>, String> {
    piv::in_session(card, |c| {
        piv::select(c)?;
        Ok(all_slots()
            .into_iter()
            .filter_map(|s| piv::read_public_key(c, s).ok().map(|k| (s, k)))
            .collect())
    })
    .map_err(|e| e.to_string())
}

pub fn export(card: &mut dyn CardTransport, slot: Slot) -> Result<PublicKey, String> {
    piv::in_session(card, |c| {
        piv::select(c)?;
        piv::read_public_key(c, slot)
    })
    .map_err(|e| format!("slot {:02x}: {e}", slot.id()))
}

/// Sign a device attestation with the attest key in `slot`: one PIN attempt, never retried
/// (CLAUDE.md hardware safety). Touch happens on the card if its policy requires it. The PIN
/// verification and the signature share one card session, which clears the PIN state at the end.
pub fn attest(
    card: &mut dyn CardTransport,
    slot: Slot,
    pin: &[u8],
    device_id: &str,
    device_key: PublicKey,
    not_before: u64,
    not_after: u64,
) -> Result<AttestationStatement, String> {
    piv::in_session(card, |c| {
        piv::select(c)?;
        let attest_key = match piv::read_public_key(c, slot) {
            Ok(k) => k,
            Err(e) => return Ok(Err(format!("attest slot {:02x}: {e}", slot.id()))),
        };
        let st = match UnsignedAttestation::new(
            device_id,
            device_key,
            not_before,
            not_after,
            attest_key.fingerprint().clone(),
        ) {
            Ok(st) => st,
            Err(e) => return Ok(Err(e.to_string())),
        };
        match piv::verify_pin(c, pin) {
            Ok(()) => {}
            Err(PivError::WrongPin { retries }) => {
                return Ok(Err(format!(
                    "wrong PIN ({retries} tries left); stopping without retrying"
                )))
            }
            Err(e) => return Err(e),
        }
        Ok(piv::sign_attestation(c, slot, st).map_err(|e| e.to_string()))
    })
    .map_err(|e| e.to_string())?
}

/// A fixed signature input for `alg`, for the PIN-state checks (thrown away afterwards).
fn test_signature(slot: Slot, alg: Algorithm) -> Result<(Mechanism, Vec<u8>), String> {
    Ok(match alg {
        Algorithm::P256 => (Mechanism::Ecdsa, vec![0x5a; 32]),
        Algorithm::P384 => (Mechanism::Ecdsa, vec![0x5a; 48]),
        Algorithm::Ed25519 => (Mechanism::Eddsa, b"relayctl pin-reset check".to_vec()),
        Algorithm::Rsa2048 | Algorithm::Rsa4096 => {
            // DigestInfo for SHA-256 over a fixed digest.
            let mut di = vec![
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ];
            di.extend_from_slice(&[0x5a; 32]);
            (Mechanism::RsaPkcs, di)
        }
        other => {
            return Err(format!(
                "slot {:02x} holds a {} key, which cannot sign; pick a signing key",
                slot.id(),
                other.as_str()
            ))
        }
    })
}

/// Outcome of [`check_pin_reset`].
#[derive(Debug, PartialEq, Eq)]
pub enum PinReset {
    /// The second session was refused without a PIN: sessions clear the PIN state.
    Cleared,
    /// The second session signed without a PIN: the PIN stayed verified across sessions.
    StillVerified,
}

/// Check on a real card that a session leaves no PIN verified. Two sessions on `slot`:
///
/// 1. `SELECT`, `VERIFY` (one attempt, never retried), sign a fixed test digest;
/// 2. `SELECT`, the same signature with no `VERIFY`.
///
/// The second must fail with "security status not satisfied", which costs no PIN attempt.
/// Neither session writes to the card, and both signatures are thrown away. Use a slot whose
/// key has PIN policy `once` and touch `never`: with policy `always` the second step fails
/// whatever the session does, so the check proves nothing.
pub fn check_pin_reset(
    card: &mut dyn CardTransport,
    slot: Slot,
    pin: &[u8],
) -> Result<PinReset, String> {
    let alg = export(card, slot)?.algorithm();
    let (mech, input) = test_signature(slot, alg)?;
    let first = piv::in_session(card, |c| {
        piv::select(c)?;
        match piv::verify_pin(c, pin) {
            Ok(()) => {}
            Err(PivError::WrongPin { retries }) => {
                return Ok(Err(format!(
                    "wrong PIN ({retries} tries left); stopping without retrying"
                )))
            }
            Err(e) => return Err(e),
        }
        Ok(piv::perform(c, slot, alg, &mech, &input)
            .map(|_| ())
            .map_err(|e| format!("signing with the PIN failed: {e}")))
    })
    .map_err(|e| e.to_string())?;
    first?;
    let second = piv::in_session(card, |c| {
        piv::select(c)?;
        Ok(piv::perform(c, slot, alg, &mech, &input).map(|_| ()))
    })
    .map_err(|e| e.to_string())?;
    match second {
        Err(PivError::SecurityStatusNotSatisfied) => Ok(PinReset::Cleared),
        Ok(()) => Ok(PinReset::StillVerified),
        Err(e) => Err(format!("unexpected card answer in the second session: {e}")),
    }
}

/// Check on a real card that `VERIFY` P1=`FF` clears the PIN, inside one session (the way the
/// apps' CryptoTokenKit transport ends a session, since it can't reset the card):
///
/// `SELECT`, `VERIFY` (one attempt, never retried), sign a fixed test digest, `VERIFY` P1=`FF`,
/// the same signature without a PIN, which must fail with "security status not satisfied".
///
/// Use a slot whose key has PIN policy `once` and touch `never`. Nothing is written; the
/// signatures are thrown away.
pub fn check_security_reset(
    card: &mut dyn CardTransport,
    slot: Slot,
    pin: &[u8],
) -> Result<PinReset, String> {
    let alg = export(card, slot)?.algorithm();
    let (mech, input) = test_signature(slot, alg)?;
    piv::in_session(card, |c| {
        piv::select(c)?;
        match piv::verify_pin(c, pin) {
            Ok(()) => {}
            Err(PivError::WrongPin { retries }) => {
                return Ok(Err(format!(
                    "wrong PIN ({retries} tries left); stopping without retrying"
                )))
            }
            Err(e) => return Err(e),
        }
        if let Err(e) = piv::perform(c, slot, alg, &mech, &input) {
            return Ok(Err(format!("signing with the PIN failed: {e}")));
        }
        if let Err(e) = piv::reset_security_status(c) {
            return Ok(Err(format!("the card refused VERIFY P1=FF: {e}")));
        }
        Ok(match piv::perform(c, slot, alg, &mech, &input) {
            Err(PivError::SecurityStatusNotSatisfied) => Ok(PinReset::Cleared),
            Ok(_) => Ok(PinReset::StillVerified),
            Err(e) => Err(format!("unexpected card answer after the reset: {e}")),
        })
    })
    .map_err(|e| e.to_string())?
}

pub fn fingerprint_line(slot: Slot, k: &PublicKey) -> String {
    format!(
        "{:02x}  {:<9} {}",
        slot.id(),
        k.algorithm().as_str(),
        k.fingerprint()
    )
}
