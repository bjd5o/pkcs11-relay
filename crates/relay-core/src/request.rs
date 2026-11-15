//! Request envelopes (wire-format §4): built and signed by the provider, verified by the
//! approver.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

use crate::attestation::check_id;
use crate::cbor::{self, Fields, MapBuilder};
use crate::error::{Error, Result};
use crate::keys::{Fingerprint, PublicKey};
use crate::manifest::{Manifest, ManifestKey};
use crate::mechanism::{check_operation, Mechanism, Op};
use crate::seal::{check_reply_pub, REPLY_PUB_LEN};
use crate::signing::random_bytes;

pub const CONTEXT: &str = "relay-pkcs11/request/v1";
/// The relay's maximum TTL (spec: Relay configuration, "max TTL 120 s").
pub const MAX_TTL: u64 = 120;

/// The requester's claims, shown on the approval screen as claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestContext {
    pub host: String,
    pub purpose: String,
    pub consumer: String,
}

impl RequestContext {
    fn check(&self) -> Result<()> {
        if self.host.is_empty()
            || self.host.len() > 255
            || self.purpose.len() > 255
            || self.consumer.len() > 255
        {
            return Err(Error::Decode(
                "context fields must be at most 255 bytes, host non-empty".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedRequest {
    pub req_id: [u8; 16],
    pub client_id: String,
    pub key_fingerprint: Fingerprint,
    pub op: Op,
    pub mechanism: Mechanism,
    pub input: Vec<u8>,
    pub context: RequestContext,
    pub reply_pub: [u8; REPLY_PUB_LEN],
    pub created_at: u64,
    pub expires_at: u64,
}

impl UnsignedRequest {
    /// Build a request with a fresh random `req_id`, after running the local role and
    /// mechanism check against the manifest key (Failure handling: rejected locally, no
    /// request sent).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client_id: &str,
        key: &ManifestKey,
        op: Op,
        mechanism: Mechanism,
        input: Vec<u8>,
        context: RequestContext,
        reply_pub: [u8; REPLY_PUB_LEN],
        created_at: u64,
        expires_at: u64,
    ) -> Result<Self> {
        check_operation(key.role, key.algorithm, op, &mechanism, input.len())?;
        let mut req_id = [0u8; 16];
        random_bytes(&mut req_id);
        let r = UnsignedRequest {
            req_id,
            client_id: client_id.into(),
            key_fingerprint: key.fingerprint.clone(),
            op,
            mechanism,
            input,
            context,
            reply_pub,
            created_at,
            expires_at,
        };
        r.check_shape()?;
        Ok(r)
    }

    fn check_shape(&self) -> Result<()> {
        check_id(&self.client_id)?;
        self.context.check()?;
        check_reply_pub(&self.reply_pub)?;
        if self.expires_at <= self.created_at || self.expires_at - self.created_at > MAX_TTL {
            return Err(Error::Decode(
                "expires_at must be within 120 s after created_at".into(),
            ));
        }
        Ok(())
    }

    fn map(&self) -> MapBuilder {
        MapBuilder::new()
            .uint("v", 1)
            .bytes("req_id", &self.req_id)
            .text("client_id", &self.client_id)
            .text("key_fingerprint", self.key_fingerprint.as_str())
            .text("op", self.op.as_str())
            .map("mechanism", self.mechanism.to_cbor())
            .bytes("input", &self.input)
            .map(
                "context",
                MapBuilder::new()
                    .text("host", &self.context.host)
                    .text("purpose", &self.context.purpose)
                    .text("consumer", &self.context.consumer),
            )
            .bytes("reply_pub", &self.reply_pub)
            .uint("created_at", self.created_at)
            .uint("expires_at", self.expires_at)
    }

    /// The bytes the client identity key signs.
    pub fn to_be_signed(&self) -> Vec<u8> {
        cbor::signed_bytes(CONTEXT, &self.map().encode())
    }

    pub fn with_signature(self, sig: [u8; 64]) -> SignedRequest {
        let bytes = self.map().bytes("client_sig", &sig).encode();
        SignedRequest {
            fields: self,
            client_sig: sig,
            bytes,
        }
    }
}

/// A decoded request with its exact bytes. Decoding checks shape, not signature or policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRequest {
    pub fields: UnsignedRequest,
    pub client_sig: [u8; 64],
    bytes: Vec<u8>,
}

impl SignedRequest {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// `request_hash`: SHA-256 of the exact bytes, including `client_sig`.
    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(&self.bytes).into()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut f = Fields::new(cbor::decode_map(bytes)?);
        f.version()?;
        let op = Op::parse(&f.text("op")?)?;
        let input = f.bytes("input")?;
        let req_id = f.fixed::<16>("req_id")?;
        let mut c = f.map("context")?;
        let context = RequestContext {
            host: c.text("host")?,
            purpose: c.text("purpose")?,
            consumer: c.text("consumer")?,
        };
        c.finish()?;
        let client_id = f.text("client_id")?;
        let mechanism = Mechanism::from_cbor(f.map("mechanism")?)?;
        let reply_pub = f.fixed::<REPLY_PUB_LEN>("reply_pub")?;
        let client_sig = f.fixed::<64>("client_sig")?;
        let created_at = f.uint("created_at")?;
        let expires_at = f.uint("expires_at")?;
        let key_fingerprint = Fingerprint::parse(&f.text("key_fingerprint")?)?;
        f.finish()?;
        let fields = UnsignedRequest {
            req_id,
            client_id,
            key_fingerprint,
            op,
            mechanism,
            input,
            context,
            reply_pub,
            created_at,
            expires_at,
        };
        fields.check_shape()?;
        Ok(SignedRequest {
            fields,
            client_sig,
            bytes: bytes.to_vec(),
        })
    }
}

/// Request ids the approver has seen, kept for a retention period (spec: 24 h).
#[derive(Debug, Default)]
pub struct ReplayCache {
    seen: HashMap<[u8; 16], u64>,
    retention: u64,
}

impl ReplayCache {
    pub fn new(retention_secs: u64) -> Self {
        ReplayCache {
            seen: HashMap::new(),
            retention: retention_secs,
        }
    }

    /// Record `req_id`; fail if it was seen within the retention period.
    pub fn check_and_insert(&mut self, req_id: [u8; 16], now: u64) -> Result<()> {
        let retention = self.retention;
        self.seen.retain(|_, t| now.saturating_sub(*t) <= retention);
        if self.seen.contains_key(&req_id) {
            return Err(Error::RequestReplayed);
        }
        self.seen.insert(req_id, now);
        Ok(())
    }
}

/// What the approver is allowed to act on, from its paired-client record and key map.
#[derive(Debug, Clone)]
pub struct ApproverPolicy<'a> {
    /// The paired client's id and identity key.
    pub client_id: &'a str,
    pub client_key: &'a PublicKey,
    /// Keys this client was approved for at pairing.
    pub approved_keys: &'a [Fingerprint],
    /// Keys this device can operate.
    pub operable_keys: &'a [Fingerprint],
}

/// A request that passed every approver check.
#[derive(Debug, Clone)]
pub struct VerifiedRequest {
    pub request: SignedRequest,
    pub key: ManifestKey,
}

/// The approver's request checks (spec: Approver application, "Check every request"):
/// signature from the paired client, not expired, not replayed, key operated by this device and
/// approved for the client, and the operation and mechanism fit the key's manifest role. The
/// per-client rate limit is the caller's.
pub fn verify_request(
    bytes: &[u8],
    policy: &ApproverPolicy<'_>,
    manifest: &Manifest,
    replay: &mut ReplayCache,
    now: u64,
    skew: u64,
) -> Result<VerifiedRequest> {
    let req = SignedRequest::decode(bytes).map_err(|e| Error::RequestInvalid(e.to_string()))?;
    let f = &req.fields;
    if f.client_id != policy.client_id {
        return Err(Error::RequestSignatureInvalid);
    }
    policy
        .client_key
        .verify_message(&f.to_be_signed(), &req.client_sig)
        .map_err(|_| Error::RequestSignatureInvalid)?;
    if f.created_at > now.saturating_add(skew) || now > f.expires_at.saturating_add(skew) {
        return Err(Error::RequestExpired);
    }
    replay.check_and_insert(f.req_id, now)?;
    let key = manifest
        .key(&f.key_fingerprint)
        .ok_or(Error::UnknownKey)?
        .clone();
    if !policy.approved_keys.contains(&f.key_fingerprint)
        || !policy.operable_keys.contains(&f.key_fingerprint)
    {
        return Err(Error::KeyNotApproved);
    }
    check_operation(key.role, key.algorithm, f.op, &f.mechanism, f.input.len())?;
    Ok(VerifiedRequest { request: req, key })
}

/// The relay's early rejection (spec: relay "Early rejection"): the request is well formed,
/// signed by the authenticated client, unexpired, and addresses a key the client was approved
/// for. Hygiene only: the approver and the provider check everything themselves.
pub fn verify_for_relay(
    bytes: &[u8],
    client_id: &str,
    client_key: &PublicKey,
    approved_keys: &[Fingerprint],
    now: u64,
    skew: u64,
) -> Result<SignedRequest> {
    let req = SignedRequest::decode(bytes).map_err(|e| Error::RequestInvalid(e.to_string()))?;
    let f = &req.fields;
    if f.client_id != client_id {
        return Err(Error::RequestSignatureInvalid);
    }
    client_key
        .verify_message(&f.to_be_signed(), &req.client_sig)
        .map_err(|_| Error::RequestSignatureInvalid)?;
    if f.created_at > now.saturating_add(skew) || now > f.expires_at {
        return Err(Error::RequestExpired);
    }
    if !approved_keys.contains(&f.key_fingerprint) {
        return Err(Error::KeyNotApproved);
    }
    Ok(req)
}
