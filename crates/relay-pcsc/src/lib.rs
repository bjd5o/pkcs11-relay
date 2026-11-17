//! A real card behind `relay_core::piv::CardTransport`, over PC/SC, for `relayctl` and the
//! test approver's `--pcsc` mode. Platforms move APDU bytes; all PIV logic stays in the core.
//!
//! Hardware safety (CLAUDE.md): nothing here touches a card unless `RELAY_TEST_YUBIKEY_SERIAL`
//! is set and equals the serial the caller asks for, and only the reader whose card reports
//! that serial is opened.
#![forbid(unsafe_code)]

use std::ffi::CString;

use relay_core::piv::{self, CardTransport, PivError};

/// The interlock variable.
pub const SERIAL_ENV: &str = "RELAY_TEST_YUBIKEY_SERIAL";

/// Refuse unless `RELAY_TEST_YUBIKEY_SERIAL` names exactly this serial.
pub fn check_interlock(serial: u32) -> Result<(), String> {
    match std::env::var(SERIAL_ENV) {
        Ok(v) if v.trim().parse::<u32>().ok() == Some(serial) => Ok(()),
        Ok(v) => Err(format!("{SERIAL_ENV}={v} does not match the requested serial {serial}; refusing to touch the card")),
        Err(_) => Err(format!("{SERIAL_ENV} is not set; refusing to touch any YubiKey (set it to the serial you mean)")),
    }
}

/// A connected card.
pub struct PcscCard {
    card: pcsc::Card,
    pub reader: String,
    pub serial: u32,
}

fn transmit_on(card: &pcsc::Card, apdu: &[u8]) -> Result<Vec<u8>, PivError> {
    let mut buf = vec![0u8; pcsc::MAX_BUFFER_SIZE_EXTENDED];
    let r = card
        .transmit(apdu, &mut buf)
        .map_err(|e| PivError::Transport(e.to_string()))?;
    Ok(r.to_vec())
}

/// The card inside a running PC/SC transaction.
struct InTransaction<'a>(&'a pcsc::Card);

impl CardTransport for InTransaction<'_> {
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, PivError> {
        transmit_on(self.0, apdu)
    }
    /// Already inside one: nested sessions share it.
    fn session(&mut self, f: &mut dyn FnMut(&mut dyn CardTransport)) -> Result<(), PivError> {
        f(self);
        Ok(())
    }
}

impl CardTransport for PcscCard {
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, PivError> {
        transmit_on(&self.card, apdu)
    }

    /// One PC/SC transaction (`SCardBeginTransaction`): other programs' commands wait until it
    /// ends. It first checks that the card in the reader still reports the expected serial, and
    /// it ends with `SCARD_RESET_CARD`, which clears the PIV PIN verification for everyone.
    fn session(&mut self, f: &mut dyn FnMut(&mut dyn CardTransport)) -> Result<(), PivError> {
        let err = |e: pcsc::Error| match e {
            pcsc::Error::SharingViolation => PivError::Transport(
                "card busy: another program holds it exclusively (for gpg, set pcsc-shared in \
                 scdaemon.conf or run gpgconf --kill scdaemon)"
                    .into(),
            ),
            e => PivError::Transport(e.to_string()),
        };
        // The reset that ended the previous session invalidates this handle until it reconnects.
        self.card
            .reconnect(
                pcsc::ShareMode::Shared,
                pcsc::Protocols::ANY,
                pcsc::Disposition::LeaveCard,
            )
            .map_err(err)?;
        let expected = self.serial;
        let tx = self.card.transaction().map_err(err)?;
        let mut card = InTransaction(&tx);
        piv::select(&mut card)?;
        let serial = piv::get_serial(&mut card)?;
        let checked = serial == expected;
        if checked {
            f(&mut card);
        }
        tx.end(pcsc::Disposition::ResetCard)
            .map_err(|(_, e)| err(e))?;
        if !checked {
            return Err(PivError::Transport(format!(
                "the card in the reader is now serial {serial}, not {expected}; nothing was sent"
            )));
        }
        Ok(())
    }
}

/// Open the card whose PIV serial is `serial`, after the interlock check. Readers whose card
/// reports another serial are disconnected without any further command.
pub fn open(serial: u32) -> Result<PcscCard, String> {
    check_interlock(serial)?;
    let ctx = pcsc::Context::establish(pcsc::Scope::User).map_err(|e| format!("PC/SC: {e}"))?;
    let readers: Vec<CString> = ctx
        .list_readers_owned()
        .map_err(|e| format!("PC/SC readers: {e}"))?;
    for r in readers {
        let Ok(card) = ctx.connect(&r, pcsc::ShareMode::Shared, pcsc::Protocols::ANY) else {
            continue;
        };
        let mut c = PcscCard {
            card,
            reader: r.to_string_lossy().into_owned(),
            serial: 0,
        };
        // SELECT and GET SERIAL only: neither changes any card state.
        if piv::select(&mut c).is_err() {
            continue;
        }
        match piv::get_serial(&mut c) {
            Ok(s) if s == serial => {
                c.serial = s;
                return Ok(c);
            }
            _ => continue,
        }
    }
    Err(format!("no YubiKey with serial {serial} found"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interlock() {
        // Single test touching the variable, so parallel tests do not race on it.
        std::env::remove_var(SERIAL_ENV);
        assert!(check_interlock(123).is_err());
        std::env::set_var(SERIAL_ENV, "456");
        assert!(check_interlock(123).is_err());
        std::env::set_var(SERIAL_ENV, "123");
        assert!(check_interlock(123).is_ok());
        std::env::remove_var(SERIAL_ENV);
        // open() refuses before any PC/SC call.
        assert!(open(123).err().is_some_and(|e| e.contains("not set")));
    }
}
