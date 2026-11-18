//! Hardware attestation for `relayctl manifest`: read a key's YubiKey attestation from the
//! card (read-only), assemble the chain with Yubico's published intermediates and verify it with
//! relay-core before it goes into the manifest.

use std::path::Path;

use relay_core::hw_attestation::{
    assemble_chain, certificates_from_pem, verify_piv_attestation, HardwareAttestation,
    HardwarePolicy, PivAttestation,
};
use relay_core::piv::{self, CardTransport, Slot};
use relay_core::PublicKey;

/// Yubico's intermediate bundle (developers.yubico.com/PKI/yubico-intermediate.pem), used to
/// complete chains for firmware 5.7.4 and later. Public data; trust comes from the root.
pub const YUBICO_INTERMEDIATES: &[u8] = include_bytes!("../data/yubico-intermediate.pem");

/// Where chains are anchored and completed: Yubico's, or a test hierarchy's.
pub struct Anchors {
    pub roots: Vec<Vec<u8>>,
    pub pool: Vec<Vec<u8>>,
}

impl Anchors {
    /// Yubico's root and intermediates, or (`--attestation-roots`, testing only) a PEM file
    /// with a test root first, then the intermediates that complete chains.
    pub fn load(test_roots: Option<&Path>) -> Result<Self, String> {
        let yubico = certificates_from_pem(YUBICO_INTERMEDIATES).map_err(|e| e.to_string())?;
        match test_roots {
            None => Ok(Anchors {
                roots: HardwarePolicy::default().roots,
                pool: yubico,
            }),
            Some(p) => {
                eprintln!(
                    "warning: using attestation roots from {} instead of Yubico's (testing only)",
                    p.display()
                );
                let pem = std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?;
                let certs = certificates_from_pem(&pem).map_err(|e| e.to_string())?;
                Ok(Anchors {
                    roots: certs[..1].to_vec(),
                    pool: certs[1..].to_vec(),
                })
            }
        }
    }

    pub fn policy(&self, require: bool) -> Result<HardwarePolicy, String> {
        HardwarePolicy::with_roots(require, self.roots.clone()).map_err(|e| e.to_string())
    }
}

/// Read the key in `slot` and its attestation from the card, in one session. Read-only: no
/// PIN, and slot `F9` is only read, never written.
pub fn from_card(
    card: &mut dyn CardTransport,
    slot: Slot,
    anchors: &Anchors,
    now: u64,
) -> Result<(PublicKey, HardwareAttestation, PivAttestation), String> {
    let (key, leaf, f9, serial) = piv::in_session(card, |c| {
        piv::select(c)?;
        Ok((
            piv::read_public_key(c, slot)?,
            piv::get_attestation(c, slot)?,
            piv::read_f9_certificate(c)?,
            piv::get_serial(c)?,
        ))
    })
    .map_err(|e| {
        format!(
            "slot {:02x}: {e} (only keys generated on the card can be attested)",
            slot.id()
        )
    })?;
    let chain = assemble_chain(leaf, f9, &anchors.pool).map_err(|e| e.to_string())?;
    let a = verify_piv_attestation(&chain, &key, &anchors.roots, now).map_err(|e| e.to_string())?;
    if a.serial != serial {
        return Err(format!(
            "attestation names serial {}, but the card reports {serial}",
            a.serial
        ));
    }
    Ok((key, HardwareAttestation { chain }, a))
}

/// A chain gathered elsewhere (PEM: the attestation certificate first, then `F9`, then any
/// intermediates), for a key given by file.
pub fn from_pem(
    path: &Path,
    key: &PublicKey,
    anchors: &Anchors,
    now: u64,
) -> Result<(HardwareAttestation, PivAttestation), String> {
    let pem = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut certs = certificates_from_pem(&pem).map_err(|e| format!("{}: {e}", path.display()))?;
    if certs.len() < 2 {
        return Err(format!(
            "{}: needs the attestation certificate and the F9 certificate",
            path.display()
        ));
    }
    let leaf = certs.remove(0);
    let f9 = certs.remove(0);
    let mut pool = certs;
    pool.extend(anchors.pool.iter().cloned());
    let chain = assemble_chain(leaf, f9, &pool).map_err(|e| e.to_string())?;
    let a = verify_piv_attestation(&chain, key, &anchors.roots, now).map_err(|e| e.to_string())?;
    Ok((HardwareAttestation { chain }, a))
}

pub fn describe(a: &PivAttestation) -> String {
    format!(
        "YubiKey serial {}, firmware {}, PIN {}, touch {}",
        a.serial,
        a.firmware_string(),
        a.pin_policy.as_str(),
        a.touch_policy.as_str()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yubico_bundle_has_the_piv_attestation_cas() {
        let a = Anchors::load(None).unwrap();
        assert!(HardwarePolicy::default().is_builtin());
        assert_eq!(a.roots, HardwarePolicy::default().roots);
        let names: Vec<String> = a
            .pool
            .iter()
            .map(|c| {
                use x509_cert::der::Decode;
                let c = x509_cert::Certificate::from_der(c).unwrap();
                c.tbs_certificate()
                    .subject()
                    .common_name()
                    .unwrap()
                    .unwrap()
                    .value()
                    .to_string()
            })
            .collect();
        for want in [
            "Yubico Attestation Intermediate A 1",
            "Yubico Attestation Intermediate B 1",
            "Yubico PIV Attestation A 1",
            "Yubico PIV Attestation B 1",
            "Yubico PIV Attestation B2 1",
        ] {
            assert!(names.iter().any(|n| n == want), "{want} missing");
        }
    }
}
