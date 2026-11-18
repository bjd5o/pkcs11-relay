//! One error enum for every check in the core.
//!
//! Each variant belongs to exactly one row of the spec's Failure handling table (see
//! [`Error::failure_row`]), so callers map errors to PKCS#11 return codes in one place.

/// PKCS#11 return codes the core's failures map to. Values from the PKCS#11 v2.40 headers.
pub mod ckr {
    pub const GENERAL_ERROR: u64 = 0x0000_0005;
    pub const DATA_LEN_RANGE: u64 = 0x0000_0021;
    pub const DEVICE_ERROR: u64 = 0x0000_0030;
    pub const FUNCTION_CANCELED: u64 = 0x0000_0050;
    pub const KEY_FUNCTION_NOT_PERMITTED: u64 = 0x0000_0068;
    pub const MECHANISM_INVALID: u64 = 0x0000_0070;
    pub const MECHANISM_PARAM_INVALID: u64 = 0x0000_0071;
    pub const BUFFER_TOO_SMALL: u64 = 0x0000_0150;
    pub const FUNCTION_REJECTED: u64 = 0x0000_0200;
}

/// Rows of the spec's Failure handling table, plus `Internal` for failures outside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureRow {
    /// Manifest signature invalid, rolled back or expired (and unreachable): zero slots.
    ManifestRejected,
    /// Operation outside the key's role: `CKR_KEY_FUNCTION_NOT_PERMITTED`.
    RoleViolation,
    /// Mechanism not allowed for the key: `CKR_MECHANISM_INVALID` (or its parameter variant).
    MechanismNotAllowed,
    /// Attestation invalid, expired or not signed by a manifest attest key: `CKR_DEVICE_ERROR`.
    AttestationRejected,
    /// Response signed by a key other than the attested device key, or not bound to this
    /// request: `CKR_DEVICE_ERROR`, logged as possible tampering.
    ResponseTampered,
    /// No answer before `expires_at`: `CKR_FUNCTION_CANCELED`.
    Expired,
    /// A message rejected by the approver or relay before any operation (not a provider row).
    RequestRejected,
    /// Anything else: malformed input, card errors, internal failures.
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    // --- Manifest (row: zero slots) ---
    #[error("manifest signature invalid: {0}")]
    ManifestSignatureInvalid(String),
    #[error("manifest malformed: {0}")]
    ManifestMalformed(String),
    #[error("manifest rolled back: version {version} is lower than cached version {cached}")]
    ManifestRolledBack { version: u64, cached: u64 },
    #[error("manifest version {version} differs from the cached copy of the same version")]
    ManifestVersionConflict { version: u64 },
    #[error("manifest expired: valid_until {valid_until}, now {now}")]
    ManifestExpired { valid_until: u64, now: u64 },
    #[error("manifest hardware attestation invalid: {0}")]
    HardwareAttestationInvalid(String),

    // --- Local operation checks ---
    #[error("operation not permitted for the key's role")]
    KeyFunctionNotPermitted,
    #[error("mechanism not allowed for this key")]
    MechanismInvalid,
    #[error("mechanism parameters not supported")]
    MechanismParamInvalid,
    #[error("input length out of range")]
    DataLenRange,

    // --- Attestation (row: CKR_DEVICE_ERROR) ---
    #[error("attestation invalid: {0}")]
    AttestationInvalid(String),
    #[error("attestation not signed by a manifest attest key")]
    AttestationUnknownSigner,
    #[error("attestation outside its validity window")]
    AttestationExpired,
    #[error("attestation window of {window} s exceeds the manifest's maximum of {max} s")]
    AttestationWindowTooLong { window: u64, max: u64 },

    // --- Response (row: CKR_DEVICE_ERROR, possible tampering) ---
    #[error("response signed by a key other than the attested device key")]
    ResponseSignerMismatch,
    #[error("response signature invalid")]
    ResponseSignatureInvalid,
    #[error("response not bound to this request: {0}")]
    ResponseNotBound(String),
    #[error("signature result does not verify against the hardware key")]
    ResultSignatureInvalid,
    #[error("sealed result could not be opened")]
    ResultOpenFailed,

    // --- Approver-side request checks ---
    #[error("request signature invalid")]
    RequestSignatureInvalid,
    #[error("request expired or not yet valid")]
    RequestExpired,
    #[error("request id seen before")]
    RequestReplayed,
    #[error("key not in the manifest")]
    UnknownKey,
    #[error("client not approved for this key, or key not operated by this device")]
    KeyNotApproved,
    #[error("request invalid: {0}")]
    RequestInvalid(String),
    #[error("relay authentication failed: {0}")]
    RelayAuth(String),

    // --- Setup links (wire-format §11; checked by the app and the relay) ---
    #[error("not a valid setup link: {0}")]
    SetupLinkInvalid(String),
    #[error("the setup link names signer {link}, not the manifest signer {expected}")]
    SetupLinkWrongSigner { link: String, expected: String },
    #[error("the setup link's signature is not valid: {0}")]
    SetupLinkSignatureInvalid(String),
    #[error("the setup link is valid from {iat} to {exp}; it is now {now}")]
    SetupLinkExpired { iat: u64, exp: u64, now: u64 },

    // --- Everything else ---
    #[error("decode error: {0}")]
    Decode(String),
    #[error("invalid key: {0}")]
    InvalidKey(String),
    #[error("card error: {0}")]
    Card(String),
    #[error("crypto failure: {0}")]
    Crypto(String),
}

impl Error {
    /// The Failure handling row this error belongs to.
    pub fn failure_row(&self) -> FailureRow {
        use Error::*;
        match self {
            ManifestSignatureInvalid(_)
            | ManifestMalformed(_)
            | ManifestRolledBack { .. }
            | ManifestVersionConflict { .. }
            | ManifestExpired { .. }
            | HardwareAttestationInvalid(_) => FailureRow::ManifestRejected,
            KeyFunctionNotPermitted => FailureRow::RoleViolation,
            MechanismInvalid | MechanismParamInvalid | DataLenRange => {
                FailureRow::MechanismNotAllowed
            }
            AttestationInvalid(_)
            | AttestationUnknownSigner
            | AttestationExpired
            | AttestationWindowTooLong { .. } => FailureRow::AttestationRejected,
            ResponseSignerMismatch
            | ResponseSignatureInvalid
            | ResponseNotBound(_)
            | ResultSignatureInvalid
            | ResultOpenFailed => FailureRow::ResponseTampered,
            RequestExpired => FailureRow::Expired,
            RequestSignatureInvalid
            | RequestReplayed
            | UnknownKey
            | KeyNotApproved
            | RequestInvalid(_)
            | RelayAuth(_)
            | SetupLinkInvalid(_)
            | SetupLinkWrongSigner { .. }
            | SetupLinkSignatureInvalid(_)
            | SetupLinkExpired { .. } => FailureRow::RequestRejected,
            Decode(_) | InvalidKey(_) | Card(_) | Crypto(_) => FailureRow::Internal,
        }
    }

    /// The PKCS#11 return code the provider reports for this error.
    ///
    /// `None` for manifest errors: those never fail a call, they make the provider list zero
    /// slots (or keep its valid cached copy).
    pub fn ckr(&self) -> Option<u64> {
        use Error::*;
        Some(match self {
            ManifestSignatureInvalid(_)
            | ManifestMalformed(_)
            | ManifestRolledBack { .. }
            | ManifestVersionConflict { .. }
            | ManifestExpired { .. }
            | HardwareAttestationInvalid(_) => return None,
            KeyFunctionNotPermitted => ckr::KEY_FUNCTION_NOT_PERMITTED,
            MechanismInvalid => ckr::MECHANISM_INVALID,
            MechanismParamInvalid => ckr::MECHANISM_PARAM_INVALID,
            DataLenRange => ckr::DATA_LEN_RANGE,
            RequestExpired => ckr::FUNCTION_CANCELED,
            _ => ckr::DEVICE_ERROR,
        })
    }

    /// The variant name, stable across releases: used in logs and golden vectors.
    pub fn kind(&self) -> &'static str {
        use Error::*;
        match self {
            ManifestSignatureInvalid(_) => "ManifestSignatureInvalid",
            ManifestMalformed(_) => "ManifestMalformed",
            ManifestRolledBack { .. } => "ManifestRolledBack",
            ManifestVersionConflict { .. } => "ManifestVersionConflict",
            ManifestExpired { .. } => "ManifestExpired",
            HardwareAttestationInvalid(_) => "HardwareAttestationInvalid",
            KeyFunctionNotPermitted => "KeyFunctionNotPermitted",
            MechanismInvalid => "MechanismInvalid",
            MechanismParamInvalid => "MechanismParamInvalid",
            DataLenRange => "DataLenRange",
            AttestationInvalid(_) => "AttestationInvalid",
            AttestationUnknownSigner => "AttestationUnknownSigner",
            AttestationExpired => "AttestationExpired",
            AttestationWindowTooLong { .. } => "AttestationWindowTooLong",
            ResponseSignerMismatch => "ResponseSignerMismatch",
            ResponseSignatureInvalid => "ResponseSignatureInvalid",
            ResponseNotBound(_) => "ResponseNotBound",
            ResultSignatureInvalid => "ResultSignatureInvalid",
            ResultOpenFailed => "ResultOpenFailed",
            RequestSignatureInvalid => "RequestSignatureInvalid",
            RequestExpired => "RequestExpired",
            RequestReplayed => "RequestReplayed",
            UnknownKey => "UnknownKey",
            KeyNotApproved => "KeyNotApproved",
            RequestInvalid(_) => "RequestInvalid",
            RelayAuth(_) => "RelayAuth",
            SetupLinkInvalid(_) => "SetupLinkInvalid",
            SetupLinkWrongSigner { .. } => "SetupLinkWrongSigner",
            SetupLinkSignatureInvalid(_) => "SetupLinkSignatureInvalid",
            SetupLinkExpired { .. } => "SetupLinkExpired",
            Decode(_) => "Decode",
            InvalidKey(_) => "InvalidKey",
            Card(_) => "Card",
            Crypto(_) => "Crypto",
        }
    }

    /// Whether the provider should log this as possible tampering ("log loudly").
    pub fn is_tampering(&self) -> bool {
        self.failure_row() == FailureRow::ResponseTampered
    }
}

pub type Result<T> = std::result::Result<T, Error>;
