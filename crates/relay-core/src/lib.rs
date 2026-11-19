//! Shared core for pkcs11-relay: wire format, verification, crypto and PIV over APDUs.
//!
//! Every security check lives here. Other crates call the `verify_*` functions and never
//! re-implement parsing, signing or verification. The format is specified in
//! `docs/wire-format.md`.
#![forbid(unsafe_code)]

pub mod attestation;
pub mod cbor;
pub mod content;
pub mod error;
pub mod grant;
pub mod hw_attestation;
pub mod keys;
pub mod manifest;
pub mod mechanism;
pub mod padding;
pub mod pairing;
pub mod piv;
pub mod relay_auth;
pub mod request;
pub mod response;
pub mod seal;
pub mod setup_link;
pub mod signer;
pub mod signing;
pub mod symmetric;

pub use attestation::{check_id, verify_attestation};
pub use error::{Error, FailureRow, Result};
pub use grant::{
    verify_client_grant, verify_client_grant_signer, verify_client_revocation, ClientGrant,
    ClientRevocation, VerifiedGrant,
};
pub use hw_attestation::{verify_piv_attestation, HardwarePolicy, PivAttestation};
pub use keys::{Algorithm, Fingerprint, PublicKey, Role};
pub use manifest::{
    verify_manifest, DraftKey, Manifest, ManifestDraft, ManifestKey, ManifestSigner, PgpSecretKey,
};
pub use mechanism::{check_operation, Mechanism, Op};
pub use request::verify_request;
pub use response::{verify_response, Outcome};
