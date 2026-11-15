//! PKCS#11 provider that forwards sign and decrypt operations through the relay.
//!
//! The module holds no private keys. Slots come from the relay's advertisement filtered
//! through the signed manifest; each `C_Sign` / `C_Decrypt` becomes a signed request whose
//! response is accepted only after `relay_core::verify_response`.
//!
//! This is the only crate allowed `unsafe`, and only inside `ffi` (and its generated
//! `ffi_stubs`). Every exported function catches panics and maps them to `CKR_GENERAL_ERROR`.
#![deny(unsafe_op_in_unsafe_fn)]
// CK_ULONG is u64 here but u32 on some targets: the casts are needed for portability.
#![allow(clippy::unnecessary_cast)]

pub mod client;
pub mod config;
pub mod discovery;
#[allow(unsafe_code)]
pub mod ffi;
#[allow(unsafe_code)]
mod ffi_stubs;
pub mod log;
pub mod provider;
