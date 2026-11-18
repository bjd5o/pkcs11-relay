//! YubiKey PIV hardware attestation (wire-format §9.4).
//!
//! A manifest key may carry the attestation chain the YubiKey produced for it. This chain
//! proves the key was generated on a genuine YubiKey (firmware 5.7.4+), and it names the card's
//! serial, firmware and PIN/touch policy. Path validation is done by `rustls-webpki`; this
//! module adds the Yubico-specific rules: the PIV branch of the hierarchy, the binding to the
//! listed public key, and the leaf extensions.

use std::time::Duration;

use rustls_pki_types::{CertificateDer, UnixTime};
use webpki::{EndEntityCert, ExtendedKeyUsageValidator, KeyPurposeIdIter};
use x509_cert::der::{Decode, Encode};

use crate::error::{Error, Result};
use crate::keys::PublicKey;

/// `Yubico Attestation Root 1` (DER), from developers.yubico.com/PKI/yubico-ca-1.pem.
pub const YUBICO_ATTESTATION_ROOT_1: &[u8] =
    include_bytes!("../data/yubico-attestation-root-1.der");

/// Oldest firmware accepted. 5.7.4 is the first firmware under `Yubico Attestation Root 1`,
/// and firmware before 5.7 is affected by EUCLEAK (YSA-2024-03) for ECDSA keys.
pub const MIN_FIRMWARE: (u8, u8, u8) = (5, 7, 4);

/// The `format` value of a manifest key's `hardware_attestation`.
pub const FORMAT_YUBIKEY_PIV: &str = "yubikey-piv";

/// Certificates in a chain, leaf first, root excluded.
pub const MAX_CHAIN: usize = 4;
pub const MIN_CHAIN: usize = 2;
/// Largest certificate accepted, DER bytes.
pub const MAX_CERT_LEN: usize = 2048;

/// Subject common-name prefix of the intermediates that issue device `F9` certificates.
const PIV_CA_PREFIX: &str = "Yubico PIV Attestation ";

// 1.3.6.1.4.1.41482.3.{3,7,8,9}
const OID_FIRMWARE: &str = "1.3.6.1.4.1.41482.3.3";
const OID_SERIAL: &str = "1.3.6.1.4.1.41482.3.7";
const OID_POLICY: &str = "1.3.6.1.4.1.41482.3.8";
const OID_FORM_FACTOR: &str = "1.3.6.1.4.1.41482.3.9";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinPolicy {
    Never,
    Once,
    Always,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchPolicy {
    Never,
    Always,
    Cached,
}

impl PinPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            PinPolicy::Never => "never",
            PinPolicy::Once => "once",
            PinPolicy::Always => "always",
        }
    }
}

impl TouchPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            TouchPolicy::Never => "never",
            TouchPolicy::Always => "always",
            TouchPolicy::Cached => "cached",
        }
    }
}

/// What a verified chain says about the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PivAttestation {
    pub serial: u32,
    pub firmware: (u8, u8, u8),
    pub pin_policy: PinPolicy,
    pub touch_policy: TouchPolicy,
    pub form_factor: Option<u8>,
}

impl PivAttestation {
    pub fn firmware_string(&self) -> String {
        let (a, b, c) = self.firmware;
        format!("{a}.{b}.{c}")
    }
}

/// A manifest key's `hardware_attestation`, as parsed (not yet verified).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardwareAttestation {
    /// DER certificates, leaf first, root excluded.
    pub chain: Vec<Vec<u8>>,
}

/// Which hardware attestation a manifest must carry (wire-format §9.4, policy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardwarePolicy {
    /// Every `attest` key must carry a valid chain. On by default.
    pub require_for_attest: bool,
    /// Trust anchors (DER). The built-in Yubico root unless replaced for tests.
    pub roots: Vec<Vec<u8>>,
}

impl Default for HardwarePolicy {
    fn default() -> Self {
        HardwarePolicy {
            require_for_attest: true,
            roots: vec![YUBICO_ATTESTATION_ROOT_1.to_vec()],
        }
    }
}

impl HardwarePolicy {
    /// The default policy with `require_for_attest` set as given.
    pub fn yubico(require_for_attest: bool) -> Self {
        HardwarePolicy {
            require_for_attest,
            ..Default::default()
        }
    }

    /// Replace the trust anchors: for test hierarchies only. Each root must parse as a
    /// certificate.
    pub fn with_roots(require_for_attest: bool, roots: Vec<Vec<u8>>) -> Result<Self> {
        if roots.is_empty() {
            return Err(invalid("no attestation roots configured"));
        }
        for r in &roots {
            webpki::anchor_from_trusted_cert(&CertificateDer::from(r.as_slice()))
                .map_err(|e| invalid(format!("attestation root unusable: {e:?}")))?;
        }
        Ok(HardwarePolicy {
            require_for_attest,
            roots,
        })
    }

    /// Whether the roots are the built-in Yubico ones.
    pub fn is_builtin(&self) -> bool {
        self.roots.len() == 1 && self.roots[0] == YUBICO_ATTESTATION_ROOT_1
    }
}

/// Split a PEM bundle into DER certificates (for configured test roots and chain files).
pub fn certificates_from_pem(pem: &[u8]) -> Result<Vec<Vec<u8>>> {
    use x509_cert::der::DecodePem;
    let text = std::str::from_utf8(pem).map_err(|_| invalid("PEM is not UTF-8"))?;
    let mut out = Vec::new();
    let mut rest = text;
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    while let Some(start) = rest.find(BEGIN) {
        let after = &rest[start..];
        let end = after
            .find(END)
            .ok_or_else(|| invalid("PEM certificate without an end line"))?;
        let block = &after[..end + END.len()];
        let cert = x509_cert::Certificate::from_pem(block)
            .map_err(|e| invalid(format!("PEM certificate: {e}")))?;
        out.push(
            cert.to_der()
                .map_err(|e| invalid(format!("certificate: {e}")))?,
        );
        rest = &after[end + END.len()..];
    }
    if out.is_empty() {
        return Err(invalid("no certificates in PEM"));
    }
    Ok(out)
}

fn invalid(m: impl Into<String>) -> Error {
    Error::HardwareAttestationInvalid(m.into())
}

/// Accept any extended key usage: Yubico's attestation certificates don't use it, and what
/// makes a chain acceptable here is the PIV branch and the Yubico extensions.
struct AnyEku;

impl ExtendedKeyUsageValidator for AnyEku {
    fn validate(&self, iter: KeyPurposeIdIter<'_, '_>) -> std::result::Result<(), webpki::Error> {
        for id in iter {
            id?;
        }
        Ok(())
    }
}

static ALGORITHMS: &[&dyn rustls_pki_types::SignatureVerificationAlgorithm] = &[
    webpki::ring::RSA_PKCS1_2048_8192_SHA256,
    webpki::ring::RSA_PKCS1_2048_8192_SHA384,
    webpki::ring::RSA_PKCS1_2048_8192_SHA512,
    webpki::ring::RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS,
    webpki::ring::RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS,
    webpki::ring::RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS,
    webpki::ring::ECDSA_P256_SHA256,
    webpki::ring::ECDSA_P384_SHA384,
];

/// Verify a YubiKey PIV attestation chain for `public_key` (wire-format §9.4, steps 1–4).
pub fn verify_piv_attestation(
    chain: &[Vec<u8>],
    public_key: &PublicKey,
    roots: &[Vec<u8>],
    now: u64,
) -> Result<PivAttestation> {
    if chain.len() < MIN_CHAIN || chain.len() > MAX_CHAIN {
        return Err(invalid(format!(
            "chain must hold {MIN_CHAIN}-{MAX_CHAIN} certificates, has {}",
            chain.len()
        )));
    }
    if let Some(c) = chain.iter().find(|c| c.len() > MAX_CERT_LEN) {
        return Err(invalid(format!(
            "certificate of {} bytes exceeds {MAX_CERT_LEN}",
            c.len()
        )));
    }

    // Step 1: path validation.
    let anchors = roots
        .iter()
        .map(|r| {
            webpki::anchor_from_trusted_cert(&CertificateDer::from(r.as_slice()))
                .map(|a| a.to_owned())
                .map_err(|e| invalid(format!("attestation root unusable: {e:?}")))
        })
        .collect::<Result<Vec<_>>>()?;
    let leaf_der = CertificateDer::from(chain[0].as_slice());
    let intermediates: Vec<CertificateDer<'_>> = chain[1..]
        .iter()
        .map(|c| CertificateDer::from(c.as_slice()))
        .collect();
    let leaf = EndEntityCert::try_from(&leaf_der)
        .map_err(|e| invalid(format!("leaf certificate: {e:?}")))?;
    let time = UnixTime::since_unix_epoch(Duration::from_secs(now));
    let path = leaf
        .verify_for_usage(
            ALGORITHMS,
            &anchors,
            &intermediates,
            time,
            AnyEku,
            None,
            None,
        )
        .map_err(|e| invalid(format!("chain does not verify: {e:?}")))?;

    // Step 2: the path goes through a PIV attestation CA.
    let mut piv_branch = false;
    for c in path.intermediate_certificates() {
        let cert = x509_cert::Certificate::from_der(c.der().as_ref())
            .map_err(|e| invalid(format!("intermediate: {e}")))?;
        if let Ok(Some(cn)) = cert.tbs_certificate().subject().common_name() {
            if cn.value().starts_with(PIV_CA_PREFIX) {
                piv_branch = true;
            }
        }
    }
    if !piv_branch {
        return Err(invalid(
            "chain is not issued through a Yubico PIV Attestation CA",
        ));
    }

    // Step 3: the leaf attests exactly this key.
    let cert = x509_cert::Certificate::from_der(&chain[0])
        .map_err(|e| invalid(format!("leaf certificate: {e}")))?;
    let spki = cert
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(|e| invalid(format!("leaf key: {e}")))?;
    if spki != public_key.spki() {
        return Err(invalid("leaf attests a different public key"));
    }

    // Step 4: the Yubico extensions.
    let ext = |oid: &str| -> Option<Vec<u8>> {
        cert.tbs_certificate().extensions().and_then(|exts| {
            exts.iter()
                .find(|e| e.extn_id.to_string() == oid)
                .map(|e| e.extn_value.as_bytes().to_vec())
        })
    };
    let fw = ext(OID_FIRMWARE).ok_or_else(|| invalid("leaf has no firmware extension"))?;
    let firmware = match fw.as_slice() {
        [a, b, c] => (*a, *b, *c),
        _ => return Err(invalid("firmware extension must be 3 bytes")),
    };
    let serial =
        parse_serial(&ext(OID_SERIAL).ok_or_else(|| invalid("leaf has no serial extension"))?)?;
    let pol = ext(OID_POLICY).ok_or_else(|| invalid("leaf has no policy extension"))?;
    let (pin_policy, touch_policy) = match pol.as_slice() {
        [p, t] => (
            match p {
                1 => PinPolicy::Never,
                2 => PinPolicy::Once,
                3 => PinPolicy::Always,
                _ => return Err(invalid(format!("unknown PIN policy {p}"))),
            },
            match t {
                1 => TouchPolicy::Never,
                2 => TouchPolicy::Always,
                3 => TouchPolicy::Cached,
                _ => return Err(invalid(format!("unknown touch policy {t}"))),
            },
        ),
        _ => return Err(invalid("policy extension must be 2 bytes")),
    };
    let form_factor = match ext(OID_FORM_FACTOR) {
        None => None,
        Some(v) if v.len() == 1 => Some(v[0]),
        Some(_) => return Err(invalid("form factor extension must be 1 byte")),
    };
    if firmware < MIN_FIRMWARE {
        let (a, b, c) = firmware;
        return Err(invalid(format!("firmware {a}.{b}.{c} is older than 5.7.4")));
    }
    Ok(PivAttestation {
        serial,
        firmware,
        pin_policy,
        touch_policy,
        form_factor,
    })
}

/// The serial extension: a DER INTEGER, non-negative, fitting a u32.
fn parse_serial(v: &[u8]) -> Result<u32> {
    let bad = || invalid("serial extension is not a DER INTEGER fitting a u32");
    let [0x02, len, body @ ..] = v else {
        return Err(bad());
    };
    if *len as usize != body.len() || body.is_empty() || body[0] & 0x80 != 0 {
        return Err(bad());
    }
    let digits = if body.len() > 1 && body[0] == 0 {
        if body[1] & 0x80 == 0 {
            return Err(bad()); // non-minimal encoding
        }
        &body[1..]
    } else {
        body
    };
    if digits.len() > 4 {
        return Err(bad());
    }
    Ok(digits.iter().fold(0u32, |n, b| (n << 8) | u32::from(*b)))
}

/// A synthetic attestation hierarchy with the same shape as Yubico's, for tests, the
/// softcard and fixtures. Never used to verify anything real.
#[cfg(any(test, feature = "test-util"))]
pub mod testing {
    use std::str::FromStr;
    use std::time::{Duration, SystemTime};

    use x509_cert::builder::{profile::BuilderProfile, Builder, CertificateBuilder};
    use x509_cert::der::asn1::OctetString;
    use x509_cert::der::oid::ObjectIdentifier;
    use x509_cert::der::{Decode, Encode};
    use x509_cert::ext::pkix::BasicConstraints;
    use x509_cert::ext::Extension;
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::SubjectPublicKeyInfoOwned;
    use x509_cert::time::{Time, Validity};

    /// 2024-01-01, like Yubico's notBefore.
    pub const NOT_BEFORE: u64 = 1_704_067_200;
    /// 9999-12-31T23:59:59Z, like Yubico's notAfter.
    pub const NOT_AFTER: u64 = 253_402_300_799;

    pub struct Ca {
        key: p256::ecdsa::SigningKey,
        name: Name,
        pub cert: Vec<u8>,
    }

    /// How to build the hierarchy; the defaults mirror Yubico's.
    pub struct HierarchyOptions {
        /// Common name of the CA that issues device `F9` certificates.
        pub branch_cn: String,
        /// Whether the device `F9` certificate is a CA (it is on real cards).
        pub f9_is_ca: bool,
        /// notAfter of the device `F9` certificate, which the leaf copies.
        pub f9_not_after: u64,
    }

    impl Default for HierarchyOptions {
        fn default() -> Self {
            HierarchyOptions {
                branch_cn: "Yubico PIV Attestation Test 1".into(),
                f9_is_ca: true,
                f9_not_after: NOT_AFTER,
            }
        }
    }

    /// Root, intermediate and PIV attestation CA.
    pub struct TestHierarchy {
        pub root: Ca,
        pub intermediate: Ca,
        pub piv_ca: Ca,
        options: HierarchyOptions,
    }

    /// One card: its factory `F9` key and certificate.
    pub struct TestDevice {
        pub serial: u32,
        pub firmware: (u8, u8, u8),
        f9: Ca,
        chain_tail: Vec<Vec<u8>>,
        not_after: u64,
    }

    /// The leaf's Yubico extensions; `None` omits one.
    #[derive(Clone)]
    pub struct LeafOptions {
        pub firmware: Option<Vec<u8>>,
        pub serial: Option<Vec<u8>>,
        pub policy: Option<Vec<u8>>,
        pub form_factor: Option<Vec<u8>>,
        pub extra: Vec<Extension>,
    }

    impl LeafOptions {
        /// What a real card writes for a key with these policies (bytes as on the card).
        pub fn for_device(d: &TestDevice, pin: u8, touch: u8) -> Self {
            let (a, b, c) = d.firmware;
            LeafOptions {
                firmware: Some(vec![a, b, c]),
                serial: Some(der_integer(d.serial)),
                policy: Some(vec![pin, touch]),
                form_factor: Some(vec![0x03]),
                extra: Vec::new(),
            }
        }
    }

    pub fn der_integer(n: u32) -> Vec<u8> {
        let mut body: Vec<u8> = n
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        if body.is_empty() || body[0] & 0x80 != 0 {
            body.insert(0, 0);
        }
        let mut v = vec![0x02, body.len() as u8];
        v.extend(body);
        v
    }

    pub fn extension(oid: &str, critical: bool, value: Vec<u8>) -> Extension {
        Extension {
            extn_id: ObjectIdentifier::new_unwrap(oid),
            critical,
            extn_value: OctetString::new(value).expect("octet string"),
        }
    }

    fn basic_constraints(ca: bool, path_len: Option<u8>) -> Extension {
        let bc = BasicConstraints {
            ca,
            path_len_constraint: path_len,
        };
        extension("2.5.29.19", true, bc.to_der().expect("basic constraints"))
    }

    struct Profile {
        issuer: Name,
        subject: Name,
        extensions: Vec<Extension>,
    }

    impl BuilderProfile for Profile {
        fn get_issuer(&self, _subject: &Name) -> Name {
            self.issuer.clone()
        }
        fn get_subject(&self) -> Name {
            self.subject.clone()
        }
        fn build_extensions(
            &self,
            _spk: x509_cert::spki::SubjectPublicKeyInfoRef<'_>,
            _issuer_spk: x509_cert::spki::SubjectPublicKeyInfoRef<'_>,
            _tbs: &x509_cert::TbsCertificate,
        ) -> x509_cert::builder::Result<Vec<Extension>> {
            Ok(self.extensions.clone())
        }
    }

    fn time(secs: u64) -> Time {
        Time::try_from(SystemTime::UNIX_EPOCH + Duration::from_secs(secs)).expect("time")
    }

    fn new_key() -> p256::ecdsa::SigningKey {
        <p256::ecdsa::SigningKey as p256::elliptic_curve::Generate>::generate_from_rng(
            &mut rand_core::UnwrapErr(getrandom::SysRng),
        )
    }

    fn spki_of(key: &p256::ecdsa::SigningKey) -> Vec<u8> {
        p256::pkcs8::EncodePublicKey::to_public_key_der(key.verifying_key())
            .expect("spki")
            .into_vec()
    }

    fn issue(
        issuer: Option<(&Name, &p256::ecdsa::SigningKey)>,
        subject: Name,
        subject_spki: &[u8],
        own_key: &p256::ecdsa::SigningKey,
        not_after: u64,
        extensions: Vec<Extension>,
    ) -> Vec<u8> {
        let (issuer_name, issuer_key) = issuer.unwrap_or((&subject, own_key));
        let validity = Validity::new(time(NOT_BEFORE), time(not_after));
        let serial = SerialNumber::new(&{
            let mut b = [0u8; 16];
            getrandom::fill(&mut b).expect("random");
            b[0] &= 0x7f;
            b[0] |= 0x01;
            b
        })
        .expect("serial");
        let profile = Profile {
            issuer: issuer_name.clone(),
            subject,
            extensions,
        };
        let spki = SubjectPublicKeyInfoOwned::from_der(subject_spki).expect("spki");
        CertificateBuilder::new(profile, serial, validity, spki)
            .expect("builder")
            .build::<_, p256::ecdsa::DerSignature>(issuer_key)
            .expect("certificate")
            .to_der()
            .expect("DER")
    }

    fn ca(issuer: Option<&Ca>, cn: &str, ca: bool, path_len: Option<u8>, not_after: u64) -> Ca {
        let key = new_key();
        let name = Name::from_str(&format!("CN={cn}")).expect("name");
        let cert = issue(
            issuer.map(|i| (&i.name, &i.key)),
            name.clone(),
            &spki_of(&key),
            &key,
            not_after,
            vec![basic_constraints(ca, path_len)],
        );
        Ca { key, name, cert }
    }

    impl TestHierarchy {
        pub fn new() -> Self {
            Self::with_options(HierarchyOptions::default())
        }

        pub fn with_options(options: HierarchyOptions) -> Self {
            let root = ca(None, "Test Attestation Root 1", true, Some(3), NOT_AFTER);
            let intermediate = ca(
                Some(&root),
                "Test Attestation Intermediate 1",
                true,
                Some(2),
                NOT_AFTER,
            );
            let piv_ca = ca(
                Some(&intermediate),
                &options.branch_cn,
                true,
                Some(1),
                NOT_AFTER,
            );
            TestHierarchy {
                root,
                intermediate,
                piv_ca,
                options,
            }
        }

        pub fn root_der(&self) -> Vec<u8> {
            self.root.cert.clone()
        }

        /// The published intermediates (PIV attestation CA, then intermediate), as relayctl
        /// embeds Yubico's.
        pub fn intermediates(&self) -> Vec<Vec<u8>> {
            vec![self.piv_ca.cert.clone(), self.intermediate.cert.clone()]
        }

        /// A card with this serial and firmware, its `F9` certificate issued by the PIV CA.
        pub fn device(&self, serial: u32, firmware: (u8, u8, u8)) -> TestDevice {
            let o = &self.options;
            let f9 = ca(
                Some(&self.piv_ca),
                &format!("Test PIV Attestation device {serial}"),
                o.f9_is_ca,
                if o.f9_is_ca { Some(0) } else { None },
                o.f9_not_after,
            );
            TestDevice {
                serial,
                firmware,
                f9,
                chain_tail: vec![self.piv_ca.cert.clone(), self.intermediate.cert.clone()],
                not_after: o.f9_not_after,
            }
        }
    }

    impl Default for TestHierarchy {
        fn default() -> Self {
            Self::new()
        }
    }

    impl TestDevice {
        /// The `F9` certificate, as data object `5FFF01` holds it.
        pub fn f9_certificate(&self) -> Vec<u8> {
            self.f9.cert.clone()
        }

        /// The published intermediates above the `F9` certificate.
        pub fn intermediates(&self) -> Vec<Vec<u8>> {
            self.chain_tail.clone()
        }

        /// The attestation certificate `GET ATTESTATION` returns for a slot.
        pub fn attestation_certificate(&self, slot: u8, spki: &[u8], o: &LeafOptions) -> Vec<u8> {
            let mut exts = Vec::new();
            for (oid, v) in [
                ("1.3.6.1.4.1.41482.3.3", &o.firmware),
                ("1.3.6.1.4.1.41482.3.7", &o.serial),
                ("1.3.6.1.4.1.41482.3.8", &o.policy),
                ("1.3.6.1.4.1.41482.3.9", &o.form_factor),
            ] {
                if let Some(v) = v {
                    exts.push(extension(oid, false, v.clone()));
                }
            }
            exts.extend(o.extra.iter().cloned());
            let subject =
                Name::from_str(&format!("CN=YubiKey PIV Attestation {slot:02x}")).expect("name");
            issue(
                Some((&self.f9.name, &self.f9.key)),
                subject,
                spki,
                &self.f9.key,
                self.not_after,
                exts,
            )
        }

        /// The full manifest chain for a key: leaf, `F9`, PIV CA, intermediate.
        pub fn chain(&self, slot: u8, spki: &[u8], o: &LeafOptions) -> Vec<Vec<u8>> {
            let mut c = vec![
                self.attestation_certificate(slot, spki, o),
                self.f9_certificate(),
            ];
            c.extend(self.intermediates());
            c
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn builtin_root_is_yubico_attestation_root_1() {
        assert_eq!(
            hex::encode(Sha256::digest(YUBICO_ATTESTATION_ROOT_1)),
            "62760c6a6ef91679f454c8902b80fd009825b3f25da90f1fbace2ec6586cd5a8"
        );
        let cert = x509_cert::Certificate::from_der(YUBICO_ATTESTATION_ROOT_1).unwrap();
        assert_eq!(
            cert.tbs_certificate()
                .subject()
                .common_name()
                .unwrap()
                .unwrap()
                .value(),
            "Yubico Attestation Root 1"
        );
        assert!(HardwarePolicy::default().is_builtin());
        HardwarePolicy::with_roots(true, vec![YUBICO_ATTESTATION_ROOT_1.to_vec()]).unwrap();
    }

    #[test]
    fn serial_encoding() {
        assert_eq!(parse_serial(&[2, 1, 5]).unwrap(), 5);
        assert_eq!(
            parse_serial(&[2, 4, 0x02, 0x19, 0x1b, 0xee]).unwrap(),
            0x0219_1bee
        );
        assert_eq!(
            parse_serial(&[2, 5, 0, 0xff, 0, 0, 1]).unwrap(),
            0xff00_0001
        );
        for bad in [
            &[2u8, 0][..],
            &[2, 1, 0x80],
            &[2, 2, 0, 1],
            &[2, 5, 1, 0, 0, 0, 0],
            &[4, 1, 1],
            &[2, 2, 1],
        ] {
            assert!(parse_serial(bad).is_err(), "{bad:?}");
        }
    }
}
