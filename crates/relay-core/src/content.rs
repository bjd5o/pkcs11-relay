//! What the approval screen shows (MVP: hex and hash). Verified facts and the requester's
//! claims are kept in separate fields so a UI cannot blur them. Decoders for CSRs, git objects
//! and SSH come later behind the same type.

use sha2::{Digest, Sha256};

use crate::request::{RequestContext, VerifiedRequest};

/// Bytes of input shown as hex before truncation.
pub const PREVIEW_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalView {
    // Checked by the approver against its pairing record and the manifest.
    pub client_id: String,
    pub key_label: String,
    pub key_role: &'static str,
    pub token: String,
    pub op: &'static str,
    pub mechanism: &'static str,
    pub seconds_left: u64,
    // Computed by the approver from the input itself.
    pub input_len: usize,
    pub input_sha256: String,
    pub input_preview_hex: String,
    pub input_truncated: bool,
    /// The requester's own claims: host, purpose, consumer. Unverified.
    pub claims: RequestContext,
}

pub fn approval_view(v: &VerifiedRequest, now: u64) -> ApprovalView {
    let f = &v.request.fields;
    let shown = &f.input[..f.input.len().min(PREVIEW_LEN)];
    ApprovalView {
        client_id: f.client_id.clone(),
        key_label: v.key.label.clone(),
        key_role: v.key.role.as_str(),
        token: v.key.token.clone(),
        op: f.op.as_str(),
        mechanism: f.mechanism.name(),
        seconds_left: f.expires_at.saturating_sub(now),
        input_len: f.input.len(),
        input_sha256: hex::encode(Sha256::digest(&f.input)),
        input_preview_hex: hex::encode(shown),
        input_truncated: f.input.len() > PREVIEW_LEN,
        claims: f.context.clone(),
    }
}
