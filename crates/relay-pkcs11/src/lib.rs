//! PKCS#11 provider that forwards sign and decrypt operations through the relay.
//!
//! This is the only crate allowed `unsafe`, and only inside the C ABI module. Every exported
//! function catches panics and maps them to `CKR_GENERAL_ERROR`.
#![deny(unsafe_op_in_unsafe_fn)]
