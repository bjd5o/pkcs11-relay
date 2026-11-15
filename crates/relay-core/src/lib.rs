//! Shared core for pkcs11-relay: wire format, verification, crypto and PIV over APDUs.
//!
//! Every security check lives here. Other crates call the `verify_*` functions and never
//! re-implement parsing, signing or verification.
#![forbid(unsafe_code)]
