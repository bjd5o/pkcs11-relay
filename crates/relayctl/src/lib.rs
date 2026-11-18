//! `relayctl`: the admin CLI for keys on YubiKeys, the trust manifest, offline attestation and
//! the relay's admin commands. Every format and check is `relay-core`'s.
#![forbid(unsafe_code)]

pub mod card;
pub mod hw;
pub mod keygen;
pub mod manifest;
pub mod util;
