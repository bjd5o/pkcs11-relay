//! Setup links for the approver app (wire-format §11).
//!
//! `poh://setup?v=1&relay=…&ca=…&signer=…&device=…&iat=…&exp=…&sig=…`, signed by the manifest
//! signer over everything before `&sig=`. Parsing is strict: one fixed order, a small character
//! set and no percent-encoding, so nothing between the terminal and the app can change the
//! signed bytes and still have the link accepted.

use base64::Engine as _;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::manifest::ManifestSigner;

/// Every link starts with this; it is also the signature's context string.
pub const PREFIX: &str = "poh://setup?v=1&";
/// Longest link accepted.
pub const MAX_LINK_LEN: usize = 4096;
/// Longest `exp − iat` accepted.
pub const MAX_LIFETIME: u64 = 7 * 86_400;
/// Default lifetime `relayctl app-link` gives a link.
pub const DEFAULT_LIFETIME: u64 = 15 * 60;

const SIG_PARAM: &str = "&sig=";

/// A parsed link. Its fields are trustworthy only after [`verify_setup_link`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupLink {
    /// `https://host[:port]`
    pub relay: String,
    /// SHA-256 of the relay CA's SubjectPublicKeyInfo; `None` for a publicly trusted relay.
    pub ca: Option<[u8; 32]>,
    /// The manifest signer's OpenPGP fingerprint, uppercase hex.
    pub signer: String,
    pub device: String,
    pub iat: u64,
    pub exp: u64,
    /// The binary OpenPGP signature packet.
    pub sig: Vec<u8>,
    /// Everything before `&sig=`: the signed bytes.
    signed: String,
}

/// What a link says before it is signed (`relayctl app-link`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupLinkDraft {
    pub relay: String,
    pub ca: Option<[u8; 32]>,
    pub signer: String,
    pub device: String,
    pub iat: u64,
    pub exp: u64,
}

fn invalid(m: impl Into<String>) -> Error {
    Error::SetupLinkInvalid(m.into())
}

fn b64url() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

fn allowed(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~' | ':' | '/')
}

fn check_relay(r: &str) -> Result<()> {
    let rest = r
        .strip_prefix("https://")
        .ok_or_else(|| invalid("relay must be an https:// URL"))?;
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) if !h.contains(']') || h.ends_with(']') => (h, Some(p)),
        _ => (rest, None),
    };
    let host_ok = !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.'));
    let port_ok =
        port.is_none_or(|p| !p.is_empty() && p.len() <= 5 && p.parse::<u16>().is_ok_and(|n| n > 0));
    if !host_ok || !port_ok {
        return Err(invalid(
            "relay must be https://host[:port], with no path, query or user",
        ));
    }
    Ok(())
}

fn check_signer(s: &str) -> Result<()> {
    let ok = (s.len() == 40 || s.len() == 64)
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b));
    if ok {
        Ok(())
    } else {
        Err(invalid(
            "signer must be a 40- or 64-character uppercase hex fingerprint",
        ))
    }
}

fn check_times(iat: u64, exp: u64) -> Result<()> {
    if iat >= exp || exp - iat > MAX_LIFETIME {
        return Err(invalid(format!(
            "exp must be after iat and at most {} days later",
            MAX_LIFETIME / 86_400
        )));
    }
    Ok(())
}

impl SetupLinkDraft {
    /// The signed bytes: the link up to, not including, `&sig=`.
    pub fn signed_bytes(&self) -> Result<String> {
        check_relay(&self.relay)?;
        check_signer(&self.signer)?;
        crate::check_id(&self.device).map_err(|e| invalid(e.to_string()))?;
        check_times(self.iat, self.exp)?;
        let mut s = format!("{PREFIX}relay={}", self.relay);
        if let Some(ca) = &self.ca {
            s.push_str(&format!("&ca={}", b64url().encode(ca)));
        }
        s.push_str(&format!(
            "&signer={}&device={}&iat={}&exp={}",
            self.signer, self.device, self.iat, self.exp
        ));
        Ok(s)
    }

    /// The complete link, given the signature over [`SetupLinkDraft::signed_bytes`].
    pub fn with_signature(&self, sig: &[u8]) -> Result<String> {
        let link = format!(
            "{}{SIG_PARAM}{}",
            self.signed_bytes()?,
            b64url().encode(sig)
        );
        // Round-trip through the parser so a link that would be refused is never printed.
        parse(&link)?;
        Ok(link)
    }
}

impl SetupLink {
    /// The signed bytes.
    pub fn signed_bytes(&self) -> &str {
        &self.signed
    }

    /// SHA-256 of the signed bytes, hex: the link's identity for single use. It never covers
    /// `sig`, so a second valid signature over the same bytes is the same link.
    pub fn id(&self) -> String {
        hex::encode(Sha256::digest(self.signed.as_bytes()))
    }
}

fn param<'a>(
    it: &mut std::iter::Peekable<std::str::Split<'a, char>>,
    name: &str,
) -> Result<&'a str> {
    let p = it
        .next()
        .ok_or_else(|| invalid(format!("missing {name}")))?;
    p.strip_prefix(name)
        .and_then(|r| r.strip_prefix('='))
        .ok_or_else(|| invalid(format!("expected {name} here, found `{p}`")))
}

fn number(s: &str, name: &str) -> Result<u64> {
    if s.is_empty()
        || s.len() > 20
        || !s.bytes().all(|b| b.is_ascii_digit())
        || (s.len() > 1 && s.starts_with('0'))
    {
        return Err(invalid(format!("{name} must be a decimal number")));
    }
    s.parse()
        .map_err(|_| invalid(format!("{name} is out of range")))
}

/// Parse a link in its fixed form (wire-format §11.1). Checks form only, not the signature.
pub fn parse(link: &str) -> Result<SetupLink> {
    if link.len() > MAX_LINK_LEN {
        return Err(invalid("too long"));
    }
    let body = link
        .strip_prefix(PREFIX)
        .ok_or_else(|| invalid(format!("must start with {PREFIX}")))?;
    if let Some(c) = body
        .chars()
        .find(|c| !allowed(*c) && *c != '&' && *c != '=')
    {
        return Err(invalid(format!("character `{c}` is not allowed")));
    }
    let sig_at = link
        .rfind(SIG_PARAM)
        .ok_or_else(|| invalid("missing sig"))?;
    let signed = link[..sig_at].to_string();
    let mut it = body.split('&').peekable();
    let relay = param(&mut it, "relay")?;
    check_relay(relay)?;
    let ca = if it.peek().is_some_and(|p| p.starts_with("ca=")) {
        let v = param(&mut it, "ca")?;
        let raw = b64url()
            .decode(v)
            .map_err(|_| invalid("ca is not base64url"))?;
        Some(
            <[u8; 32]>::try_from(raw.as_slice())
                .map_err(|_| invalid("ca must be a SHA-256 hash"))?,
        )
    } else {
        None
    };
    let signer = param(&mut it, "signer")?;
    check_signer(signer)?;
    let device = param(&mut it, "device")?;
    crate::check_id(device).map_err(|e| invalid(format!("device: {e}")))?;
    let iat = number(param(&mut it, "iat")?, "iat")?;
    let exp = number(param(&mut it, "exp")?, "exp")?;
    check_times(iat, exp)?;
    let sig_b64 = param(&mut it, "sig")?;
    if it.next().is_some() {
        return Err(invalid("unexpected parameters after sig"));
    }
    let sig = b64url()
        .decode(sig_b64)
        .map_err(|_| invalid("sig is not base64url"))?;
    if sig.is_empty() {
        return Err(invalid("sig is empty"));
    }
    // The signed bytes end exactly where `&sig=` starts, and that is the last parameter.
    if link.len() != sig_at + SIG_PARAM.len() + sig_b64.len() {
        return Err(invalid("sig must be the last parameter"));
    }
    Ok(SetupLink {
        relay: relay.into(),
        ca,
        signer: signer.into(),
        device: device.into(),
        iat,
        exp,
        sig,
        signed,
    })
}

/// Parse and verify a link (wire-format §11.2): form, signer fingerprint, signature under the
/// §9.1 rules, then time. `signer` is the key the caller already trusts for the manifest.
pub fn verify_setup_link(
    link: &str,
    signer: &ManifestSigner,
    now: u64,
    skew: u64,
) -> Result<SetupLink> {
    let l = parse(link)?;
    let expected = signer.fingerprint();
    if l.signer != expected {
        return Err(Error::SetupLinkWrongSigner {
            link: l.signer.clone(),
            expected,
        });
    }
    signer
        .verify(l.signed.as_bytes(), &l.sig, now, skew)
        .map_err(|e| match e {
            Error::ManifestSignatureInvalid(m) => Error::SetupLinkSignatureInvalid(m),
            other => other,
        })?;
    if now.saturating_add(skew) < l.iat || now > l.exp.saturating_add(skew) {
        return Err(Error::SetupLinkExpired {
            iat: l.iat,
            exp: l.exp,
            now,
        });
    }
    Ok(l)
}

/// SHA-256 of a DER SubjectPublicKeyInfo: the `ca` pin.
pub fn spki_pin(spki_der: &[u8]) -> [u8; 32] {
    Sha256::digest(spki_der).into()
}

/// Check the relay CA certificate the app fetched without TLS verification (wire-format
/// §11.2): it must be a self-signed CA certificate whose SPKI hash is the link's `ca` pin.
/// Returns its PEM, to be used as the only trust anchor from then on.
pub fn check_relay_ca(pem: &[u8], pin: &[u8; 32]) -> Result<String> {
    use x509_cert::der::{DecodePem, Encode, EncodePem};
    let bad = |m: String| Error::SetupLinkInvalid(format!("relay CA: {m}"));
    let text = std::str::from_utf8(pem).map_err(|_| bad("not UTF-8 PEM".into()))?;
    let cert = x509_cert::Certificate::from_pem(text).map_err(|e| bad(e.to_string()))?;
    let tbs = cert.tbs_certificate();
    let spki = tbs
        .subject_public_key_info()
        .to_der()
        .map_err(|e| bad(e.to_string()))?;
    if spki_pin(&spki) != *pin {
        return Err(bad("its key does not match the link's ca pin".into()));
    }
    if tbs.subject() != tbs.issuer() {
        return Err(bad("not self-signed".into()));
    }
    let is_ca = tbs
        .get_extension::<x509_cert::ext::pkix::BasicConstraints>()
        .ok()
        .flatten()
        .is_some_and(|(_, bc)| bc.ca);
    if !is_ca {
        return Err(bad("not a CA certificate".into()));
    }
    cert.to_pem(x509_cert::der::pem::LineEnding::LF)
        .map_err(|e| bad(e.to_string()))
}
