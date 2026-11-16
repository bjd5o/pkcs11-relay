//! `relayctl key generate` on a real YubiKey, through the `yubikey` crate 0.8 (management-key
//! authentication, key generation, writing a self-signed certificate).
//!
//! What 0.8 supports: RSA-2048, P-256 and P-384 keys, and 3DES management keys. Generate
//! RSA-4096, Ed25519 and X25519 keys with `ykman` and import them with
//! `relayctl manifest add --serial S --slot XX` (docs/decisions.md).
//!
//! Hardware safety: the serial interlock; no overwrite without `--force` and a typed
//! confirmation; PIN policy `never` is not offered; touch `always` on the attest key; one PIN
//! attempt; the management key is typed in or PIN-protected, never assumed to be the default.

use std::str::FromStr;
use std::time::Duration;

use relay_core::piv::Slot;
use relay_core::{Algorithm, PublicKey, Role};
use yubikey::certificate::{yubikey_signer, Certificate};
use yubikey::piv::{self as ypiv, AlgorithmId, SlotId};
use yubikey::{MgmKey, PinPolicy, Serial, TouchPolicy, YubiKey};
use zeroize::Zeroizing;

use crate::util::{confirm_phrase, prompt_secret};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pin {
    Once,
    Always,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Touch {
    Never,
    Always,
    Cached,
}

pub struct Generate {
    pub serial: u32,
    pub slot: Slot,
    pub role: Role,
    pub alg: Algorithm,
    pub pin: Pin,
    pub touch: Touch,
    pub force: bool,
    pub common_name: String,
}

/// The `ykman` command for keys this tool cannot generate.
pub fn ykman_hint(g: &Generate) -> String {
    let alg = match g.alg {
        Algorithm::Rsa4096 => "RSA4096",
        Algorithm::Ed25519 => "ED25519",
        Algorithm::X25519 => "X25519",
        other => other.as_str(),
    };
    let touch = match g.touch {
        Touch::Never => "NEVER",
        Touch::Always => "ALWAYS",
        Touch::Cached => "CACHED",
    };
    let pin = if g.pin == Pin::Always {
        "ALWAYS"
    } else {
        "ONCE"
    };
    format!(
        "ykman --device {s} piv keys generate --algorithm {alg} --pin-policy {pin} --touch-policy {touch} {slot:02x} key.pem\n\
         ykman --device {s} piv certificates generate --subject 'CN={cn}' {slot:02x} key.pem   (not possible for X25519; then import with ykman piv certificates import)\n\
         relayctl manifest add --manifest manifest.json --serial {s} --slot {slot:02x} --role {role} --label <label> --id <hex> --token <token>",
        s = g.serial,
        slot = g.slot.id(),
        cn = g.common_name,
        role = g.role.as_str()
    )
}

/// The policy rules, checked before the card is opened.
pub fn check_policy(role: Role, alg: Algorithm, touch: Touch) -> Result<(), String> {
    if !role.allows(alg) {
        return Err(format!(
            "a {} key cannot hold the {} role",
            alg.as_str(),
            role.as_str()
        ));
    }
    if role == Role::Attest && touch != Touch::Always {
        return Err("the attest key requires --touch-policy always".into());
    }
    Ok(())
}

fn algorithm_id(alg: Algorithm) -> Option<AlgorithmId> {
    match alg {
        Algorithm::Rsa2048 => Some(AlgorithmId::Rsa2048),
        Algorithm::P256 => Some(AlgorithmId::EccP256),
        Algorithm::P384 => Some(AlgorithmId::EccP384),
        _ => None,
    }
}

fn yk_err(what: &str) -> impl Fn(yubikey::Error) -> String + '_ {
    move |e| format!("{what}: {e}")
}

/// Verify the PIN once; a wrong PIN stops the command (never retried).
fn verify_pin(yk: &mut YubiKey, pin: &[u8]) -> Result<(), String> {
    yk.verify_pin(pin).map_err(|e| match e {
        yubikey::Error::WrongPin { tries } => {
            format!("wrong PIN ({tries} tries left); stopping without retrying")
        }
        e => format!("PIN verification: {e}"),
    })
}

/// Authenticate with the 3DES management key: typed in hex, or the PIN-protected one when the
/// answer is empty. The default key is never tried.
fn authenticate(yk: &mut YubiKey) -> Result<(), String> {
    let hex_key =
        prompt_secret("Management key (3DES, hex; empty to use the PIN-protected key): ")?;
    let mgm = if hex_key.trim().is_empty() {
        MgmKey::get_protected(yk).map_err(yk_err("reading the PIN-protected management key"))?
    } else {
        let bytes = Zeroizing::new(
            hex::decode(hex_key.trim()).map_err(|_| "management key must be hex".to_string())?,
        );
        MgmKey::from_bytes(&*bytes).map_err(yk_err(
            "management key (yubikey 0.8 supports 3DES keys only)",
        ))?
    };
    yk.authenticate(mgm).map_err(yk_err(
        "management key authentication (an AES management key needs ykman)",
    ))
}

/// Generate a key in a slot and write its self-signed certificate. Returns the public key, read
/// back through relay-core's PIV layer so it is checked like any other.
pub fn generate(g: &Generate) -> Result<PublicKey, String> {
    relay_pcsc::check_interlock(g.serial)?;
    check_policy(g.role, g.alg, g.touch)?;
    let Some(alg) = algorithm_id(g.alg) else {
        return Err(format!(
            "this relayctl generates RSA-2048, P-256 and P-384 keys only; use:\n{}",
            ykman_hint(g)
        ));
    };
    let mut yk =
        YubiKey::open_by_serial(Serial(g.serial)).map_err(yk_err("opening the YubiKey"))?;
    let slot = SlotId::try_from(g.slot.id()).map_err(yk_err("slot"))?;
    let occupied =
        ypiv::metadata(&mut yk, slot).is_ok() || Certificate::read(&mut yk, slot).is_ok();
    if occupied {
        if !g.force {
            return Err(format!(
                "slot {:02x} already holds a key or certificate; pass --force to replace it",
                g.slot.id()
            ));
        }
        let phrase = format!("overwrite {:02x} on {}", g.slot.id(), g.serial);
        if !confirm_phrase(
            &format!(
                "Slot {:02x} on YubiKey {} is in use. Its key will be destroyed.",
                g.slot.id(),
                g.serial
            ),
            &phrase,
        )? {
            return Err("not confirmed; nothing changed".into());
        }
    }
    let pin = prompt_secret("PIV PIN: ")?;
    verify_pin(&mut yk, pin.as_bytes())?;
    authenticate(&mut yk)?;
    let pin_policy = match g.pin {
        Pin::Once => PinPolicy::Once,
        Pin::Always => PinPolicy::Always,
    };
    let touch_policy = match g.touch {
        Touch::Never => TouchPolicy::Never,
        Touch::Always => TouchPolicy::Always,
        Touch::Cached => TouchPolicy::Cached,
    };
    let spki = ypiv::generate(&mut yk, slot, alg, pin_policy, touch_policy)
        .map_err(yk_err("key generation"))?;
    let name = x509_cert_02::name::Name::from_str(&format!("CN={}", g.common_name))
        .map_err(|e| e.to_string())?;
    let validity = x509_cert_02::time::Validity::from_now(Duration::from_secs(20 * 365 * 86_400))
        .map_err(|e| e.to_string())?;
    let serial = x509_cert_02::serial_number::SerialNumber::from(1u32);
    if g.pin == Pin::Always {
        verify_pin(&mut yk, pin.as_bytes())?; // policy `always`: the same, already-verified PIN
    }
    if g.touch != Touch::Never {
        eprintln!("Touch the YubiKey to sign its certificate...");
    }
    let r = match g.alg {
        Algorithm::Rsa2048 => Certificate::generate_self_signed::<
            _,
            yubikey_signer::YubiRsa<yubikey_signer::Rsa2048>,
        >(&mut yk, slot, serial, validity, name, spki, |_| Ok(())),
        Algorithm::P256 => Certificate::generate_self_signed::<_, p256_013::NistP256>(
            &mut yk,
            slot,
            serial,
            validity,
            name,
            spki,
            |_| Ok(()),
        ),
        Algorithm::P384 => Certificate::generate_self_signed::<_, p384_013::NistP384>(
            &mut yk,
            slot,
            serial,
            validity,
            name,
            spki,
            |_| Ok(()),
        ),
        _ => unreachable!("checked above"),
    };
    r.map_err(yk_err("self-signed certificate"))?;
    drop(yk);
    let mut card = relay_pcsc::open(g.serial)?;
    let pk = crate::card::export(&mut card, g.slot)?;
    if pk.algorithm() != g.alg {
        return Err(format!(
            "card holds a {} key instead of {}",
            pk.algorithm().as_str(),
            g.alg.as_str()
        ));
    }
    Ok(pk)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(alg: Algorithm) -> Generate {
        Generate {
            serial: 1,
            slot: Slot::new(0x95).unwrap(),
            role: Role::Encrypt,
            alg,
            pin: Pin::Once,
            touch: Touch::Never,
            force: false,
            common_name: "t".into(),
        }
    }

    #[test]
    fn policy() {
        assert!(check_policy(Role::Encrypt, Algorithm::Rsa4096, Touch::Never).is_ok());
        assert!(check_policy(Role::Encrypt, Algorithm::Ed25519, Touch::Never).is_err());
        assert!(check_policy(Role::Sign, Algorithm::X25519, Touch::Never).is_err());
        assert!(
            check_policy(Role::Attest, Algorithm::P256, Touch::Cached).is_err(),
            "attest needs touch always"
        );
        assert!(check_policy(Role::Attest, Algorithm::P256, Touch::Always).is_ok());
    }

    #[test]
    fn refuses_without_interlock_and_points_to_ykman() {
        std::env::remove_var(relay_pcsc::SERIAL_ENV);
        assert!(generate(&g(Algorithm::P256))
            .unwrap_err()
            .contains("not set"));
        let hint = ykman_hint(&g(Algorithm::X25519));
        assert!(hint.contains("--algorithm X25519") && hint.contains("relayctl manifest add"));
    }
}
