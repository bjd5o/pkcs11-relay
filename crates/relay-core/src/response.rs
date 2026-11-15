//! Response envelopes (wire-format §6): built and signed by the approver's device key, verified
//! by the provider.

use zeroize::Zeroizing;

use crate::attestation::{self, AttestationStatement};
use crate::cbor::{self, Fields, MapBuilder};
use crate::error::{Error, Result};
use crate::keys::Fingerprint;
use crate::manifest::{Manifest, ManifestKey};
use crate::mechanism::Mechanism;
use crate::request::SignedRequest;
use crate::seal::{self, ReplyKey};

pub const CONTEXT: &str = "relay-pkcs11/response/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Approved,
    Denied,
    Error,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Approved => "approved",
            Status::Denied => "denied",
            Status::Error => "error",
        }
    }
    fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "approved" => Status::Approved,
            "denied" => Status::Denied,
            "error" => Status::Error,
            _ => return Err(Error::Decode(format!("unknown status `{s}`"))),
        })
    }
}

/// Reason codes for denials and errors (wire-format §6.1). A hint from an attested device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    UserDenied,
    Policy,
    Expired,
    CardAbsent,
    WrongPin,
    PinBlocked,
    /// Any card or decoding failure, including an OAEP decoding failure: never distinguished,
    /// so the relay sees no padding oracle.
    CardError,
    Internal,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::UserDenied => "user_denied",
            Reason::Policy => "policy",
            Reason::Expired => "expired",
            Reason::CardAbsent => "card_absent",
            Reason::WrongPin => "wrong_pin",
            Reason::PinBlocked => "pin_blocked",
            Reason::CardError => "card_error",
            Reason::Internal => "internal",
        }
    }
    fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "user_denied" => Reason::UserDenied,
            "policy" => Reason::Policy,
            "expired" => Reason::Expired,
            "card_absent" => Reason::CardAbsent,
            "wrong_pin" => Reason::WrongPin,
            "pin_blocked" => Reason::PinBlocked,
            "card_error" => Reason::CardError,
            "internal" => Reason::Internal,
            _ => return Err(Error::Decode(format!("unknown reason `{s}`"))),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedResponse {
    pub req_id: [u8; 16],
    pub request_hash: [u8; 32],
    pub status: Status,
    pub reason: Option<Reason>,
    pub responded_at: u64,
    pub sealed_result: Option<Vec<u8>>,
    pub device_key_fingerprint: Fingerprint,
    /// The attestation statement's exact bytes; not covered by `device_sig`.
    pub attestation: Vec<u8>,
}

impl UnsignedResponse {
    /// An approval: seals `result` to the request's reply key.
    pub fn approved(
        request: &SignedRequest,
        result: &[u8],
        attestation: &AttestationStatement,
        responded_at: u64,
    ) -> Result<Self> {
        let sealed = seal::seal(&request.fields.reply_pub, &request.fields.req_id, result)?;
        Ok(Self::build(
            request,
            Status::Approved,
            None,
            Some(sealed),
            attestation,
            responded_at,
        ))
    }

    pub fn denied(
        request: &SignedRequest,
        reason: Option<Reason>,
        attestation: &AttestationStatement,
        responded_at: u64,
    ) -> Self {
        Self::build(
            request,
            Status::Denied,
            reason,
            None,
            attestation,
            responded_at,
        )
    }

    pub fn error(
        request: &SignedRequest,
        reason: Option<Reason>,
        attestation: &AttestationStatement,
        responded_at: u64,
    ) -> Self {
        Self::build(
            request,
            Status::Error,
            reason,
            None,
            attestation,
            responded_at,
        )
    }

    fn build(
        request: &SignedRequest,
        status: Status,
        reason: Option<Reason>,
        sealed_result: Option<Vec<u8>>,
        attestation: &AttestationStatement,
        responded_at: u64,
    ) -> Self {
        UnsignedResponse {
            req_id: request.fields.req_id,
            request_hash: request.hash(),
            status,
            reason,
            responded_at,
            sealed_result,
            device_key_fingerprint: attestation.fields.device_key.fingerprint().clone(),
            attestation: attestation.bytes().to_vec(),
        }
    }

    /// Every field except `attestation` and `device_sig`.
    fn signed_map(&self) -> MapBuilder {
        MapBuilder::new()
            .uint("v", 1)
            .opt_text("reason", self.reason.map(Reason::as_str))
            .bytes("req_id", &self.req_id)
            .text("status", self.status.as_str())
            .bytes("request_hash", &self.request_hash)
            .uint("responded_at", self.responded_at)
            .opt_bytes("sealed_result", self.sealed_result.as_deref())
            .text(
                "device_key_fingerprint",
                self.device_key_fingerprint.as_str(),
            )
    }

    /// The bytes the device key signs.
    pub fn to_be_signed(&self) -> Vec<u8> {
        cbor::signed_bytes(CONTEXT, &self.signed_map().encode())
    }

    pub fn with_signature(self, sig: [u8; 64]) -> SignedResponse {
        let bytes = self
            .signed_map()
            .bytes("device_sig", &sig)
            .bytes("attestation", &self.attestation)
            .encode();
        SignedResponse {
            fields: self,
            device_sig: sig,
            bytes,
        }
    }

    fn check_shape(&self) -> Result<()> {
        match (self.status, &self.sealed_result, &self.reason) {
            (Status::Approved, Some(_), None) => Ok(()),
            (Status::Approved, _, _) => Err(Error::Decode(
                "approved needs sealed_result and no reason".into(),
            )),
            (_, None, _) => Ok(()),
            (_, Some(_), _) => Err(Error::Decode("sealed_result only with approved".into())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedResponse {
    pub fields: UnsignedResponse,
    pub device_sig: [u8; 64],
    bytes: Vec<u8>,
}

impl SignedResponse {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut f = Fields::new(cbor::decode_map(bytes)?);
        f.version()?;
        let reason = f
            .opt_text("reason")?
            .map(|r| Reason::parse(&r))
            .transpose()?;
        let req_id = f.fixed::<16>("req_id")?;
        let status = Status::parse(&f.text("status")?)?;
        let device_sig = f.fixed::<64>("device_sig")?;
        let attestation = f.bytes("attestation")?;
        let request_hash = f.fixed::<32>("request_hash")?;
        let responded_at = f.uint("responded_at")?;
        let sealed_result = f.opt_bytes("sealed_result")?;
        let device_key_fingerprint = Fingerprint::parse(&f.text("device_key_fingerprint")?)?;
        f.finish()?;
        let fields = UnsignedResponse {
            req_id,
            request_hash,
            status,
            reason,
            responded_at,
            sealed_result,
            device_key_fingerprint,
            attestation,
        };
        fields.check_shape()?;
        Ok(SignedResponse {
            fields,
            device_sig,
            bytes: bytes.to_vec(),
        })
    }
}

/// The outcome of a response that passed every check.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The result bytes, in the mechanism's output format. Zeroized on drop.
    Approved(Zeroizing<Vec<u8>>),
    /// `CKR_FUNCTION_REJECTED`.
    Denied(Option<Reason>),
    /// `CKR_DEVICE_ERROR`; the reason is logged.
    Error(Option<Reason>),
}

impl Outcome {
    /// The PKCS#11 return code for this outcome (Failure handling: signed denial and signed
    /// error rows).
    pub fn ckr(&self) -> u64 {
        match self {
            Outcome::Approved(_) => 0,
            Outcome::Denied(_) => crate::error::ckr::FUNCTION_REJECTED,
            Outcome::Error(_) => crate::error::ckr::DEVICE_ERROR,
        }
    }
}

/// `verify_response` (wire-format §6.2). Runs the spec's checks in order and stops at the
/// first failure:
///
/// 1. the attestation verifies against a manifest `attest` key;
/// 2. `now` is inside its window, allowing `skew`;
/// 3. the response's signer is the attested device key;
/// 4. `device_sig` verifies and the response is bound to this request;
///
/// then, for an approval, opens the sealed result (consuming the reply key), and
///
/// 5. for a signature result, verifies it against the hardware key from the manifest.
///
/// The reply key is consumed in every case, so it is zeroized whatever the outcome.
pub fn verify_response(
    response_bytes: &[u8],
    request_bytes: &[u8],
    manifest: &Manifest,
    now: u64,
    skew: u64,
    reply_key: ReplyKey,
) -> Result<Outcome> {
    let request = SignedRequest::decode(request_bytes)?;
    let resp = SignedResponse::decode(response_bytes)
        .map_err(|e| Error::ResponseNotBound(format!("undecodable: {e}")))?;
    let r = &resp.fields;

    // 1. Attestation signature against a manifest attest key.
    let st = attestation::verify_signature(&r.attestation, manifest)?;
    // 2. Validity window.
    attestation::check_window(&st, now, skew)?;
    // 3. The signer is the attested device key.
    if &r.device_key_fingerprint != st.fields.device_key.fingerprint() {
        return Err(Error::ResponseSignerMismatch);
    }
    // 4. Signature, then binding to this request.
    st.fields
        .device_key
        .verify_message(&r.to_be_signed(), &resp.device_sig)
        .map_err(|_| Error::ResponseSignatureInvalid)?;
    if r.req_id != request.fields.req_id {
        return Err(Error::ResponseNotBound("req_id differs".into()));
    }
    if r.request_hash != request.hash() {
        return Err(Error::ResponseNotBound("request_hash differs".into()));
    }

    match r.status {
        Status::Denied => return Ok(Outcome::Denied(r.reason)),
        Status::Error => return Ok(Outcome::Error(r.reason)),
        Status::Approved => {}
    }
    let sealed = r.sealed_result.as_deref().expect("checked by decode");
    let result = reply_key.open(&request.fields.req_id, sealed)?;

    // 5. A signature result must verify against the hardware key.
    if request.fields.mechanism.is_signature() {
        let key = manifest
            .key(&request.fields.key_fingerprint)
            .ok_or_else(|| {
                Error::ResponseNotBound("requested key no longer in the manifest".into())
            })?;
        verify_signature_result(
            key,
            &request.fields.mechanism,
            &request.fields.input,
            &result,
        )?;
    }
    Ok(Outcome::Approved(result))
}

/// Check 5: verify a signature result against the hardware key's public key.
pub fn verify_signature_result(
    key: &ManifestKey,
    mechanism: &Mechanism,
    input: &[u8],
    sig: &[u8],
) -> Result<()> {
    let bad = || Error::ResultSignatureInvalid;
    match mechanism {
        Mechanism::Sha256RsaPkcs | Mechanism::RsaPkcs => {
            let pk = key.public_key.rsa().ok_or_else(bad)?;
            let scheme = match mechanism {
                Mechanism::Sha256RsaPkcs => rsa::Pkcs1v15Sign::new::<sha2::Sha256>(),
                _ => rsa::Pkcs1v15Sign::new_unprefixed(),
            };
            let hashed: Vec<u8> = match mechanism {
                Mechanism::Sha256RsaPkcs => {
                    use sha2::Digest;
                    sha2::Sha256::digest(input).to_vec()
                }
                _ => input.to_vec(),
            };
            pk.verify(scheme, &hashed, sig).map_err(|_| bad())
        }
        Mechanism::EcdsaSha256 | Mechanism::Ecdsa => {
            let pk = key.public_key.p256().ok_or_else(bad)?;
            let sig = p256::ecdsa::Signature::from_slice(sig).map_err(|_| bad())?;
            if matches!(mechanism, Mechanism::EcdsaSha256) {
                use p256::ecdsa::signature::Verifier;
                pk.verify(input, &sig).map_err(|_| bad())
            } else {
                use p256::ecdsa::signature::hazmat::PrehashVerifier;
                pk.verify_prehash(input, &sig).map_err(|_| bad())
            }
        }
        Mechanism::RsaPkcsOaep { .. } => Ok(()),
    }
}

/// The relay's check of a posted response: well formed, signed by the authenticated device's
/// key, carrying an attestation that names that key, and bound to the pending request. The
/// relay cannot check the attestation's signer (it has no manifest); clients do.
pub fn verify_for_relay(
    bytes: &[u8],
    request: &SignedRequest,
    device_key: &crate::keys::PublicKey,
) -> Result<SignedResponse> {
    let resp = SignedResponse::decode(bytes)
        .map_err(|e| Error::ResponseNotBound(format!("undecodable: {e}")))?;
    let r = &resp.fields;
    if &r.device_key_fingerprint != device_key.fingerprint() {
        return Err(Error::ResponseSignerMismatch);
    }
    let st = AttestationStatement::decode(&r.attestation)
        .map_err(|e| Error::AttestationInvalid(e.to_string()))?;
    if st.fields.device_key.fingerprint() != device_key.fingerprint() {
        return Err(Error::ResponseSignerMismatch);
    }
    device_key
        .verify_message(&r.to_be_signed(), &resp.device_sig)
        .map_err(|_| Error::ResponseSignatureInvalid)?;
    if r.req_id != request.fields.req_id || r.request_hash != request.hash() {
        return Err(Error::ResponseNotBound("not for this request".into()));
    }
    Ok(resp)
}
