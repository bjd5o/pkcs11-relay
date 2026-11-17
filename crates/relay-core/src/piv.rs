//! PIV over APDUs (NIST SP 800-73-4, with YubiKey algorithm ids). Platforms only move bytes
//! through [`CardTransport`]; every command, response parser and format fix-up is here.

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::attestation::{AttestationStatement, UnsignedAttestation};
use crate::keys::Algorithm;
use crate::mechanism::Mechanism;
use crate::padding;
use crate::response::Reason;

/// PIV application identifier (spec: `A000000308`).
pub const PIV_AID: [u8; 5] = [0xA0, 0x00, 0x00, 0x03, 0x08];

/// Moves one APDU to the card and returns its response, including the two status bytes.
pub trait CardTransport {
    fn transmit(&mut self, apdu: &[u8]) -> std::result::Result<Vec<u8>, PivError>;

    /// Run `f` while holding the card for this caller alone, then leave the card with no PIN
    /// verified. Each sequence of commands that belongs together (`SELECT`, `VERIFY`, the
    /// operation) runs inside one session, so another program can neither interleave commands
    /// nor use the PIN verification afterwards. Callers use [`in_session`]. A transport that
    /// is already exclusive and powered down after each use (one NFC tap) just calls `f`.
    fn session(
        &mut self,
        f: &mut dyn FnMut(&mut dyn CardTransport),
    ) -> std::result::Result<(), PivError>;
}

/// Run `f` in one card session (see [`CardTransport::session`]) and return its result.
pub fn in_session<R>(
    t: &mut dyn CardTransport,
    f: impl FnOnce(&mut dyn CardTransport) -> Result<R>,
) -> Result<R> {
    let mut f = Some(f);
    let mut out = None;
    t.session(&mut |c| {
        if let Some(f) = f.take() {
            out = Some(f(c));
        }
    })?;
    out.unwrap_or_else(|| Err(PivError::Transport("card session did not run".into())))
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PivError {
    #[error("card unreachable: {0}")]
    Transport(String),
    #[error("wrong PIN, {retries} tries left")]
    WrongPin { retries: u8 },
    #[error("PIN blocked")]
    PinBlocked,
    #[error("security status not satisfied (PIN or touch required)")]
    SecurityStatusNotSatisfied,
    #[error("object or key not found")]
    NotFound,
    #[error("card returned status {0:04x}")]
    Status(u16),
    #[error("malformed card response: {0}")]
    Malformed(String),
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
}

impl PivError {
    /// The response reason code to report. Every failure that could depend on secret data
    /// (including OAEP decoding) is reported as `card_error`.
    pub fn reason(&self) -> Reason {
        match self {
            PivError::Transport(_) => Reason::CardAbsent,
            PivError::WrongPin { .. } => Reason::WrongPin,
            PivError::PinBlocked => Reason::PinBlocked,
            _ => Reason::CardError,
        }
    }
}

type Result<T> = std::result::Result<T, PivError>;

/// PIV key slots: `9a`, `9c`, `9d`, `9e` and the retired slots `82`–`95`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Slot(u8);

impl Slot {
    pub fn new(id: u8) -> Result<Self> {
        match id {
            0x9a | 0x9c | 0x9d | 0x9e | 0x82..=0x95 => Ok(Slot(id)),
            _ => Err(PivError::InvalidArgument(format!(
                "not a PIV key slot: {id:02x}"
            ))),
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        let id = u8::from_str_radix(s, 16)
            .map_err(|_| PivError::InvalidArgument(format!("bad slot `{s}`")))?;
        Slot::new(id)
    }

    pub fn id(self) -> u8 {
        self.0
    }

    /// The data object holding this slot's certificate.
    pub fn certificate_object(self) -> [u8; 3] {
        let last = match self.0 {
            0x9a => 0x05,
            0x9c => 0x0a,
            0x9d => 0x0b,
            0x9e => 0x01,
            r => 0x0d + (r - 0x82), // 82 -> 5FC10D ... 95 -> 5FC120
        };
        [0x5f, 0xc1, last]
    }
}

/// PIV algorithm identifiers.
pub fn algorithm_id(alg: Algorithm) -> Result<u8> {
    match alg {
        Algorithm::Rsa2048 => Ok(0x07),
        Algorithm::Rsa4096 => Ok(0x16),
        Algorithm::P256 => Ok(0x11),
        Algorithm::P384 => Ok(0x14),
        // YubiKey firmware 5.7 and later.
        Algorithm::X25519 => Ok(0xe1),
        // YubiKey firmware 5.7 and later.
        Algorithm::Ed25519 => Ok(0xe0),
    }
}

// --- BER-TLV ---

pub(crate) fn push_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xff {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    }
}

pub(crate) fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    push_len(&mut out, value.len());
    out.extend_from_slice(value);
    out
}

/// Parse one TLV at the start of `data`: `(tag, value, rest)`. Tags are one byte except the
/// two-byte `5F xx` form, which PIV uses only in requests.
pub(crate) fn parse_tlv(data: &[u8]) -> Result<(u8, &[u8], &[u8])> {
    let bad = || PivError::Malformed("truncated TLV".into());
    let (&tag, rest) = data.split_first().ok_or_else(bad)?;
    let (&l0, rest) = rest.split_first().ok_or_else(bad)?;
    let (len, rest) = match l0 {
        0..=0x7f => (l0 as usize, rest),
        0x81 => (*rest.first().ok_or_else(bad)? as usize, &rest[1..]),
        0x82 => {
            if rest.len() < 2 {
                return Err(bad());
            }
            (((rest[0] as usize) << 8) | rest[1] as usize, &rest[2..])
        }
        _ => return Err(PivError::Malformed("unsupported TLV length form".into())),
    };
    if rest.len() < len {
        return Err(bad());
    }
    Ok((tag, &rest[..len], &rest[len..]))
}

fn find_tlv(mut data: &[u8], want: u8) -> Result<&[u8]> {
    while !data.is_empty() {
        let (tag, value, rest) = parse_tlv(data)?;
        if tag == want {
            return Ok(value);
        }
        data = rest;
    }
    Err(PivError::Malformed(format!("tag {want:02x} not found")))
}

// --- APDU exchange ---

const MAX_RESPONSE: usize = 16 * 1024;

fn split_sw(resp: &[u8]) -> Result<(&[u8], u16)> {
    if resp.len() < 2 {
        return Err(PivError::Malformed(
            "response shorter than a status word".into(),
        ));
    }
    let (data, sw) = resp.split_at(resp.len() - 2);
    Ok((data, u16::from_be_bytes([sw[0], sw[1]])))
}

fn status_error(sw: u16) -> PivError {
    match sw {
        0x6983 => PivError::PinBlocked,
        0x6982 => PivError::SecurityStatusNotSatisfied,
        0x6a82 | 0x6a88 => PivError::NotFound,
        sw if sw & 0xfff0 == 0x63c0 => PivError::WrongPin {
            retries: (sw & 0x0f) as u8,
        },
        sw => PivError::Status(sw),
    }
}

/// Send one command, chaining the command data in 255-byte blocks (CLA `10`) and collecting
/// chained responses (`61xx` + GET RESPONSE); retries once on `6Cxx` with the given Le.
pub(crate) fn exchange(
    t: &mut dyn CardTransport,
    ins: u8,
    p1: u8,
    p2: u8,
    data: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let chunks: Vec<&[u8]> = if data.is_empty() {
        vec![&[][..]]
    } else {
        data.chunks(255).collect()
    };
    let mut resp = Zeroizing::new(Vec::new());
    for (i, chunk) in chunks.iter().enumerate() {
        let last = i + 1 == chunks.len();
        let mut apdu = Zeroizing::new(vec![if last { 0x00 } else { 0x10 }, ins, p1, p2]);
        if !chunk.is_empty() {
            apdu.push(chunk.len() as u8);
            apdu.extend_from_slice(chunk);
        }
        if !last {
            let r = t.transmit(&apdu)?;
            let (_, sw) = split_sw(&r)?;
            if sw != 0x9000 {
                return Err(status_error(sw));
            }
            continue;
        }
        apdu.push(0x00); // Le
        let mut r = Zeroizing::new(t.transmit(&apdu)?);
        let (_, sw) = split_sw(&r)?;
        if sw >> 8 == 0x6c {
            let n = apdu.len();
            apdu[n - 1] = sw as u8;
            *r = t.transmit(&apdu)?;
        }
        loop {
            let (body, sw) = split_sw(&r)?;
            resp.extend_from_slice(body);
            if resp.len() > MAX_RESPONSE {
                return Err(PivError::Malformed("response too long".into()));
            }
            match sw {
                0x9000 => break,
                sw if sw >> 8 == 0x61 => {
                    *r = t.transmit(&[0x00, 0xc0, 0x00, 0x00, sw as u8])?;
                }
                sw => return Err(status_error(sw)),
            }
        }
    }
    Ok(resp)
}

/// SELECT the PIV application.
pub fn select(t: &mut dyn CardTransport) -> Result<()> {
    exchange(t, 0xa4, 0x04, 0x00, &PIV_AID).map(|_| ())
}

/// The YubiKey's serial number (PIV `GET SERIAL`, INS `F8`, firmware 5 and later).
pub fn get_serial(t: &mut dyn CardTransport) -> Result<u32> {
    let r = exchange(t, 0xf8, 0x00, 0x00, &[])?;
    let b: [u8; 4] = r
        .as_slice()
        .try_into()
        .map_err(|_| PivError::Malformed("serial must be 4 bytes".into()))?;
    Ok(u32::from_be_bytes(b))
}

/// VERIFY the PIV application PIN. Sends it once and never retries: the caller stops after
/// one failure (CLAUDE.md hardware safety).
pub fn verify_pin(t: &mut dyn CardTransport, pin: &[u8]) -> Result<()> {
    if !(6..=8).contains(&pin.len()) || !pin.iter().all(u8::is_ascii) {
        return Err(PivError::InvalidArgument(
            "PIN must be 6-8 ASCII characters".into(),
        ));
    }
    let mut padded = Zeroizing::new([0xffu8; 8]);
    padded[..pin.len()].copy_from_slice(pin);
    let r = exchange(t, 0x20, 0x00, 0x80, &padded[..]);
    padded.zeroize();
    r.map(|_| ())
}

/// Remaining PIN tries, without presenting a PIN (`None` if already verified).
pub fn pin_retries(t: &mut dyn CardTransport) -> Result<Option<u8>> {
    match exchange(t, 0x20, 0x00, 0x80, &[]) {
        Ok(_) => Ok(None),
        Err(PivError::WrongPin { retries }) => Ok(Some(retries)),
        Err(e) => Err(e),
    }
}

/// GET DATA for a data object; returns the contents of the `53` wrapper.
pub fn get_data(t: &mut dyn CardTransport, object: [u8; 3]) -> Result<Vec<u8>> {
    let mut req = vec![0x5c, 0x03];
    req.extend_from_slice(&object);
    let resp = exchange(t, 0xcb, 0x3f, 0xff, &req)?;
    Ok(find_tlv(&resp, 0x53)?.to_vec())
}

/// Read the DER certificate in a slot's certificate object (tag `70`; uncompressed only).
pub fn read_certificate(t: &mut dyn CardTransport, slot: Slot) -> Result<Vec<u8>> {
    let obj = get_data(t, slot.certificate_object())?;
    if let Ok(info) = find_tlv(&obj, 0x71) {
        if info.first().is_some_and(|b| b & 0x01 != 0) {
            return Err(PivError::Malformed(
                "compressed certificates are not supported".into(),
            ));
        }
    }
    Ok(find_tlv(&obj, 0x70)?.to_vec())
}

/// The public key in a slot, from its certificate: how approvers discover what a card holds.
/// The certificate itself is not trusted; only the key's fingerprint is matched against the
/// manifest.
pub fn read_public_key(t: &mut dyn CardTransport, slot: Slot) -> Result<crate::keys::PublicKey> {
    use x509_cert::der::{Decode, Encode};
    let der = read_certificate(t, slot)?;
    let cert = x509_cert::Certificate::from_der(&der)
        .map_err(|e| PivError::Malformed(format!("certificate: {e}")))?;
    let spki = cert
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(|e| PivError::Malformed(e.to_string()))?;
    crate::keys::PublicKey::from_spki(&spki).map_err(|e| PivError::Malformed(e.to_string()))
}

/// GENERAL AUTHENTICATE with a challenge (`81`) and a response request (`82`).
pub fn general_authenticate(
    t: &mut dyn CardTransport,
    alg: u8,
    slot: Slot,
    input: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    general_authenticate_tagged(t, alg, slot, 0x81, input)
}

/// GENERAL AUTHENTICATE with the input under `tag`: `81` (challenge) or `85` (ECDH peer
/// public key).
pub fn general_authenticate_tagged(
    t: &mut dyn CardTransport,
    alg: u8,
    slot: Slot,
    tag: u8,
    input: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let mut inner = vec![0x82, 0x00];
    inner.extend_from_slice(&tlv(tag, input));
    let req = Zeroizing::new(tlv(0x7c, &inner));
    let resp = exchange(t, 0x87, alg, slot.id(), &req)?;
    let outer = find_tlv(&resp, 0x7c)?;
    Ok(Zeroizing::new(find_tlv(outer, 0x82)?.to_vec()))
}

fn left_pad(v: &[u8], k: usize) -> Result<Zeroizing<Vec<u8>>> {
    if v.len() > k {
        return Err(PivError::Malformed(
            "RSA result longer than the modulus".into(),
        ));
    }
    let mut out = Zeroizing::new(vec![0u8; k - v.len()]);
    out.extend_from_slice(v);
    Ok(out)
}

/// Raw RSA on the card, then OAEP-SHA256 decoding. Any decoding failure is a generic card
/// error.
pub fn decrypt_oaep(
    t: &mut dyn CardTransport,
    slot: Slot,
    alg: Algorithm,
    ciphertext: &[u8],
    label: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let k = alg
        .rsa_modulus_len()
        .ok_or_else(|| PivError::InvalidArgument("OAEP needs an RSA key".into()))?;
    if ciphertext.len() != k {
        return Err(PivError::InvalidArgument(
            "ciphertext must be the modulus length".into(),
        ));
    }
    let raw = general_authenticate(t, algorithm_id(alg)?, slot, ciphertext)?;
    let em = left_pad(&raw, k)?;
    padding::oaep_decode_sha256(&em, label, k)
        .map_err(|_| PivError::Malformed("decryption failed".into()))
}

/// PKCS#1 v1.5 padding, then raw RSA on the card.
pub fn sign_rsa_pkcs1(
    t: &mut dyn CardTransport,
    slot: Slot,
    alg: Algorithm,
    prefix: &[u8],
    hashed: &[u8],
) -> Result<Vec<u8>> {
    let k = alg
        .rsa_modulus_len()
        .ok_or_else(|| PivError::InvalidArgument("not an RSA key".into()))?;
    let em = padding::emsa_pkcs1v15_encode(prefix, hashed, k)
        .map_err(|_| PivError::InvalidArgument("input too long for the modulus".into()))?;
    let raw = general_authenticate(t, algorithm_id(alg)?, slot, &em)?;
    Ok(left_pad(&raw, k)?.to_vec())
}

/// ECDSA P-256 over a digest: the card returns DER, converted to `r || s`. A digest longer
/// than 32 bytes is truncated to its leftmost 32 (FIPS 186-4 §6.4); a shorter one is
/// left-padded with zeros, which is the same integer.
pub fn sign_ecdsa_p256(t: &mut dyn CardTransport, slot: Slot, digest: &[u8]) -> Result<[u8; 64]> {
    let mut d = [0u8; 32];
    if digest.len() >= 32 {
        d.copy_from_slice(&digest[..32]);
    } else {
        d[32 - digest.len()..].copy_from_slice(digest);
    }
    let der = general_authenticate(t, 0x11, slot, &d)?;
    padding::ecdsa_der_to_raw(&der)
        .map_err(|_| PivError::Malformed("invalid ECDSA signature from card".into()))
}

/// ECDSA over a digest with a P-256 or P-384 key: the digest is truncated or left-padded to
/// the field size, and the card's DER signature becomes `r || s`.
pub fn sign_ecdsa(
    t: &mut dyn CardTransport,
    slot: Slot,
    alg: Algorithm,
    digest: &[u8],
) -> Result<Vec<u8>> {
    let n = match alg {
        Algorithm::P256 | Algorithm::P384 => alg.ec_field_len().expect("EC field"),
        _ => {
            return Err(PivError::InvalidArgument(
                "ECDSA needs a P-256 or P-384 key".into(),
            ))
        }
    };
    let mut d = vec![0u8; n];
    if digest.len() >= n {
        d.copy_from_slice(&digest[..n]);
    } else {
        d[n - digest.len()..].copy_from_slice(digest);
    }
    let der = general_authenticate(t, algorithm_id(alg)?, slot, &d)?;
    padding::ecdsa_der_to_raw_for(alg, &der)
        .map_err(|_| PivError::Malformed("invalid ECDSA signature from card".into()))
}

/// Ed25519 on the card: GENERAL AUTHENTICATE over the whole message; the card returns the
/// 64-byte signature.
pub fn sign_eddsa(t: &mut dyn CardTransport, slot: Slot, message: &[u8]) -> Result<Vec<u8>> {
    let sig = general_authenticate(t, algorithm_id(Algorithm::Ed25519)?, slot, message)?;
    if sig.len() != 64 {
        return Err(PivError::Malformed(
            "Ed25519 signature must be 64 bytes".into(),
        ));
    }
    Ok(sig.to_vec())
}

/// ECDH on the card (GENERAL AUTHENTICATE, tag `85`): returns the shared secret, the
/// x-coordinate (P-256, P-384) or the X25519 output. An all-zero secret (a low-order X25519
/// peer key) is refused.
pub fn ecdh(
    t: &mut dyn CardTransport,
    slot: Slot,
    alg: Algorithm,
    peer: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    crate::mechanism::check_ecdh_peer(alg, peer)
        .map_err(|e| PivError::InvalidArgument(e.to_string()))?;
    let secret = general_authenticate_tagged(t, algorithm_id(alg)?, slot, 0x85, peer)?;
    let n = alg.ec_field_len().expect("ECDH curve");
    if secret.len() != n {
        return Err(PivError::Malformed(
            "shared secret has the wrong length".into(),
        ));
    }
    if secret.iter().all(|b| *b == 0) {
        return Err(PivError::Malformed("degenerate shared secret".into()));
    }
    Ok(secret)
}

/// ECDH, then the KDF: `CKD_NULL` keeps the leading `out_len` bytes of the shared secret,
/// `CKD_SHA256_KDF` runs ANSI X9.63 with SHA-256 over it and the shared data.
pub fn derive(
    t: &mut dyn CardTransport,
    slot: Slot,
    alg: Algorithm,
    peer: &[u8],
    kdf: crate::mechanism::Kdf,
    shared_data: &[u8],
    out_len: u32,
) -> Result<Zeroizing<Vec<u8>>> {
    let secret = ecdh(t, slot, alg, peer)?;
    let n = out_len as usize;
    let mut out = Zeroizing::new(vec![0u8; n]);
    match kdf {
        crate::mechanism::Kdf::Null => {
            if n > secret.len() {
                return Err(PivError::InvalidArgument(
                    "requested key longer than the shared secret".into(),
                ));
            }
            out.copy_from_slice(&secret[..n]);
        }
        crate::mechanism::Kdf::Sha256 => {
            ansi_x963_kdf::derive_key_into::<Sha256>(&secret, shared_data, &mut out)
                .map_err(|_| PivError::InvalidArgument("X9.63 KDF failed".into()))?;
        }
    }
    Ok(out)
}

/// Run a request's operation on the card and return the result in the mechanism's output
/// format (wire-format §3). The caller has already verified the request and the PIN.
pub fn perform(
    t: &mut dyn CardTransport,
    slot: Slot,
    alg: Algorithm,
    mechanism: &Mechanism,
    input: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    Ok(match mechanism {
        Mechanism::RsaPkcsOaep { label } => decrypt_oaep(t, slot, alg, input, label)?,
        Mechanism::Sha256RsaPkcs => Zeroizing::new(sign_rsa_pkcs1(
            t,
            slot,
            alg,
            &padding::SHA256_DIGEST_INFO_PREFIX,
            &Sha256::digest(input),
        )?),
        Mechanism::RsaPkcs => Zeroizing::new(sign_rsa_pkcs1(t, slot, alg, &[], input)?),
        Mechanism::EcdsaSha256 => Zeroizing::new(sign_ecdsa(t, slot, alg, &Sha256::digest(input))?),
        Mechanism::EcdsaSha384 => {
            Zeroizing::new(sign_ecdsa(t, slot, alg, &sha2::Sha384::digest(input))?)
        }
        Mechanism::Ecdsa => Zeroizing::new(sign_ecdsa(t, slot, alg, input)?),
        Mechanism::Eddsa => Zeroizing::new(sign_eddsa(t, slot, input)?),
        Mechanism::Ecdh1Derive {
            kdf,
            shared_data,
            out_len,
        } => derive(t, slot, alg, input, *kdf, shared_data, *out_len)?,
    })
}

/// Sign an attestation statement with the attest key in `slot` (P-256).
pub fn sign_attestation(
    t: &mut dyn CardTransport,
    slot: Slot,
    statement: UnsignedAttestation,
) -> Result<AttestationStatement> {
    let digest = Sha256::digest(statement.to_be_signed());
    let sig = sign_ecdsa_p256(t, slot, &digest)?;
    Ok(statement.with_signature(sig))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scripted transport: checks each APDU and returns canned responses.
    struct Script(Vec<(Vec<u8>, Vec<u8>)>);
    impl CardTransport for Script {
        fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
            let (want, resp) = self.0.remove(0);
            assert_eq!(hex::encode(apdu), hex::encode(want));
            Ok(resp)
        }
        fn session(&mut self, f: &mut dyn FnMut(&mut dyn CardTransport)) -> Result<()> {
            f(self);
            Ok(())
        }
    }

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s.replace(' ', "")).unwrap()
    }

    #[test]
    fn select_apdu() {
        let mut t = Script(vec![(h("00a4040005a00000030800"), h("9000"))]);
        select(&mut t).unwrap();
    }

    #[test]
    fn response_chaining_and_wrong_le() {
        let mut t = Script(vec![
            (h("00cb3fff055c035fc10500"), h("6c 10")),
            (h("00cb3fff055c035fc10510"), h("5304 70 02 aabb 6102")),
            (h("00c0000002"), h("ccdd 9000")),
        ]);
        let obj = get_data(&mut t, Slot::new(0x9a).unwrap().certificate_object()).unwrap();
        assert_eq!(hex::encode(obj), "7002aabb");
    }

    #[test]
    fn pin_errors_and_padding() {
        // A 6-digit PIN is padded with 0xFF to 8 bytes.
        let mut t = Script(vec![(h("0020008008 313233343536ffff 00"), h("63c2"))]);
        assert_eq!(
            verify_pin(&mut t, b"123456"),
            Err(PivError::WrongPin { retries: 2 })
        );
        let mut t = Script(vec![(h("0020008008 3132333435363738 00"), h("6983"))]);
        assert_eq!(verify_pin(&mut t, b"12345678"), Err(PivError::PinBlocked));
        assert!(verify_pin(&mut Script(vec![]), b"123").is_err());
    }

    #[test]
    fn command_chaining_for_rsa_input() {
        let input = vec![0x42u8; 256];
        let mut req = vec![0x82, 0x00];
        req.extend_from_slice(&tlv(0x81, &input));
        let req = tlv(0x7c, &req);
        let (a, b) = req.split_at(255);
        let mut first = h("10870795ff");
        first.extend_from_slice(a);
        let mut second = vec![0x00, 0x87, 0x07, 0x95, b.len() as u8];
        second.extend_from_slice(b);
        second.push(0);
        let mut t = Script(vec![
            (first, h("9000")),
            (second, h("7c 04 82 02 0102 9000")),
        ]);
        let out = general_authenticate(&mut t, 0x07, Slot::new(0x95).unwrap(), &input).unwrap();
        assert_eq!(&*out, &[1, 2]);
    }

    #[test]
    fn slots() {
        assert_eq!(
            Slot::new(0x82).unwrap().certificate_object(),
            [0x5f, 0xc1, 0x0d]
        );
        assert_eq!(
            Slot::new(0x95).unwrap().certificate_object(),
            [0x5f, 0xc1, 0x20]
        );
        assert!(Slot::new(0x80).is_err());
        assert!(Slot::parse("9d").is_ok());
    }

    #[test]
    fn tlv_lengths() {
        let v = vec![0u8; 300];
        let t = tlv(0x53, &v);
        assert_eq!(&t[..4], &[0x53, 0x82, 0x01, 0x2c]);
        let (tag, value, rest) = parse_tlv(&t).unwrap();
        assert_eq!((tag, value.len(), rest.len()), (0x53, 300, 0));
        assert!(parse_tlv(&[0x53, 0x82, 0x01]).is_err());
    }
}
