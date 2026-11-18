//! Software PIV card behind [`relay_core::piv::CardTransport`], for tests only.
//!
//! It implements the subset of PIV the core uses: SELECT, VERIFY (PIN with a retry counter),
//! GENERAL AUTHENTICATE (raw RSA 2048/4096 and ECDSA P-256 over a digest), GET DATA for
//! certificate objects, command chaining and response chaining (`61xx` + GET RESPONSE). Keys
//! and certificates load from PEM files or are generated in memory.
//!
//! Never use it to protect anything: its private keys sit in process memory.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;

use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use relay_core::hw_attestation::testing::{LeafOptions, TestDevice};
use relay_core::piv::{algorithm_id, CardTransport, PivError, Slot, PIV_AID};
use relay_core::{Algorithm, PublicKey};
use rsa::traits::PublicKeyParts;
use x509_cert::builder::{profile::BuilderProfile, Builder, CertificateBuilder};
use x509_cert::der::{Decode, DecodePem, Encode};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;
use zeroize::Zeroizing;

const MAX_PIN_RETRIES: u8 = 3;
/// Serial of a card without a synthetic attestation.
pub const DEFAULT_SERIAL: u32 = 10_000_001;
const RESPONSE_CHUNK: usize = 256;

/// A private key held in a slot.
pub enum SlotKey {
    Rsa(Box<rsa::PrivateKey>),
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
    X25519(x25519_dalek::StaticSecret),
    Ed25519(ed25519_dalek::SigningKey),
}

/// RFC 8410 PKCS#8 prefix for an X25519 private key (followed by the 32 key bytes).
const X25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
];
/// RFC 8410 SPKI prefix for an X25519 public key (followed by the 32 key bytes).
const X25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
];

impl SlotKey {
    pub fn generate(alg: Algorithm) -> Self {
        let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
        match alg {
            Algorithm::Rsa2048 => SlotKey::Rsa(Box::new(
                rsa::PrivateKey::new(&mut rng, 2048).expect("RSA keygen"),
            )),
            Algorithm::Rsa4096 => SlotKey::Rsa(Box::new(
                rsa::PrivateKey::new(&mut rng, 4096).expect("RSA keygen"),
            )),
            Algorithm::P256 => SlotKey::P256(
                <p256::ecdsa::SigningKey as p256::elliptic_curve::Generate>::generate_from_rng(
                    &mut rng,
                ),
            ),
            Algorithm::P384 => SlotKey::P384(
                <p384::ecdsa::SigningKey as p384::elliptic_curve::Generate>::generate_from_rng(
                    &mut rng,
                ),
            ),
            Algorithm::X25519 => {
                let mut b = Zeroizing::new([0u8; 32]);
                relay_core::signing::random_bytes(&mut *b);
                SlotKey::X25519(x25519_dalek::StaticSecret::from(*b))
            }
            Algorithm::Ed25519 => SlotKey::Ed25519(ed25519_dalek::SigningKey::generate(&mut rng)),
        }
    }

    /// Load a PKCS#8 PEM private key (RSA, P-256, P-384 or X25519).
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, PivError> {
        if let Ok(k) = <p256::ecdsa::SigningKey as DecodePrivateKey>::from_pkcs8_pem(pem) {
            return Ok(SlotKey::P256(k));
        }
        if let Ok(k) =
            <p384::ecdsa::SigningKey as p384::pkcs8::DecodePrivateKey>::from_pkcs8_pem(pem)
        {
            return Ok(SlotKey::P384(k));
        }
        if let Ok(k) =
            <ed25519_dalek::SigningKey as ed25519_dalek::pkcs8::DecodePrivateKey>::from_pkcs8_pem(
                pem,
            )
        {
            return Ok(SlotKey::Ed25519(k));
        }
        if let Ok((label, der)) = p256::pkcs8::der::pem::decode_vec(pem.as_bytes()) {
            let der = Zeroizing::new(der);
            if label == "PRIVATE KEY" && der.len() == 48 && der.starts_with(&X25519_PKCS8_PREFIX) {
                let raw: [u8; 32] = der[16..].try_into().expect("32 bytes");
                return Ok(SlotKey::X25519(x25519_dalek::StaticSecret::from(raw)));
            }
        }
        <rsa::PrivateKey as rsa::pkcs8::DecodePrivateKey>::from_pkcs8_pem(pem)
            .map(|k| SlotKey::Rsa(Box::new(k)))
            .map_err(|_| {
                PivError::InvalidArgument("not an RSA, P-256, P-384 or X25519 PKCS#8 key".into())
            })
    }

    pub fn to_pkcs8_pem(&self) -> Zeroizing<String> {
        let pem = match self {
            SlotKey::Rsa(k) => {
                rsa::pkcs8::EncodePrivateKey::to_pkcs8_pem(k.as_ref(), LineEnding::LF)
                    .map(|p| p.to_string())
            }
            SlotKey::P256(k) => k.to_pkcs8_pem(LineEnding::LF).map(|p| p.to_string()),
            SlotKey::P384(k) => p384::pkcs8::EncodePrivateKey::to_pkcs8_pem(k, LineEnding::LF)
                .map(|p| p.to_string()),
            SlotKey::Ed25519(k) => {
                ed25519_dalek::pkcs8::EncodePrivateKey::to_pkcs8_pem(k, LineEnding::LF)
                    .map(|p| p.to_string())
            }
            SlotKey::X25519(k) => {
                let mut der = Zeroizing::new(X25519_PKCS8_PREFIX.to_vec());
                der.extend_from_slice(k.as_bytes());
                Ok(
                    p256::pkcs8::der::pem::encode_string("PRIVATE KEY", LineEnding::LF, &der)
                        .expect("PEM"),
                )
            }
        }
        .expect("encoding a valid key cannot fail");
        Zeroizing::new(pem)
    }

    pub fn algorithm(&self) -> Algorithm {
        match self {
            SlotKey::Rsa(k) if k.n().bit_width() == 4096 => Algorithm::Rsa4096,
            SlotKey::Rsa(_) => Algorithm::Rsa2048,
            SlotKey::P256(_) => Algorithm::P256,
            SlotKey::P384(_) => Algorithm::P384,
            SlotKey::X25519(_) => Algorithm::X25519,
            SlotKey::Ed25519(_) => Algorithm::Ed25519,
        }
    }

    pub fn public_key(&self) -> PublicKey {
        let der = match self {
            SlotKey::Rsa(k) => rsa::pkcs8::EncodePublicKey::to_public_key_der(&k.to_public_key())
                .map(|d| d.into_vec()),
            SlotKey::P256(k) => p256::pkcs8::EncodePublicKey::to_public_key_der(k.verifying_key())
                .map(|d| d.into_vec()),
            SlotKey::P384(k) => p384::pkcs8::EncodePublicKey::to_public_key_der(k.verifying_key())
                .map(|d| d.into_vec()),
            SlotKey::Ed25519(k) => {
                ed25519_dalek::pkcs8::EncodePublicKey::to_public_key_der(&k.verifying_key())
                    .map(|d| d.into_vec())
            }
            SlotKey::X25519(k) => {
                let mut v = X25519_SPKI_PREFIX.to_vec();
                v.extend_from_slice(x25519_dalek::PublicKey::from(k).as_bytes());
                Ok(v)
            }
        }
        .expect("encoding a valid key cannot fail");
        PublicKey::from_spki(&der).expect("generated keys are canonical")
    }

    /// A certificate for the key, as a YubiKey keeps one per slot. Self-signed, except X25519
    /// (which cannot sign): issued by a throwaway P-256 key. Only its public key matters.
    pub fn self_signed_certificate(&self, common_name: &str) -> Vec<u8> {
        let name = Name::from_str(&format!("CN={common_name}")).expect("valid CN");
        let spki =
            SubjectPublicKeyInfoOwned::from_der(self.public_key().spki()).expect("valid SPKI");
        let validity =
            Validity::from_now(Duration::from_secs(20 * 365 * 24 * 3600)).expect("validity");
        let builder =
            CertificateBuilder::new(SelfSigned(name), SerialNumber::from(1u32), validity, spki)
                .expect("builder");
        let cert = match self {
            SlotKey::Rsa(k) => {
                let signer = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(k.as_ref().clone());
                builder.build::<_, rsa::pkcs1v15::Signature>(&signer)
            }
            SlotKey::P256(k) => builder.build::<_, p256::ecdsa::DerSignature>(k),
            SlotKey::P384(k) => builder.build::<_, p384::ecdsa::DerSignature>(k),
            SlotKey::X25519(_) | SlotKey::Ed25519(_) => {
                let issuer =
                    <p256::ecdsa::SigningKey as p256::elliptic_curve::Generate>::generate_from_rng(
                        &mut rand_core::UnwrapErr(getrandom::SysRng),
                    );
                builder.build::<_, p256::ecdsa::DerSignature>(&issuer)
            }
        }
        .expect("certificate");
        cert.to_der().expect("certificate DER")
    }
}

/// Subject = issuer, no extensions: like the certificate `ykman piv keys generate` writes.
struct SelfSigned(Name);

impl BuilderProfile for SelfSigned {
    fn get_issuer(&self, subject: &Name) -> Name {
        subject.clone()
    }
    fn get_subject(&self) -> Name {
        self.0.clone()
    }
    fn build_extensions(
        &self,
        _spk: x509_cert::spki::SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: x509_cert::spki::SubjectPublicKeyInfoRef<'_>,
        _tbs: &x509_cert::TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<x509_cert::ext::Extension>> {
        Ok(Vec::new())
    }
}

struct SlotEntry {
    key: SlotKey,
    certificate: Vec<u8>,
    /// PIN and touch policy bytes as attestation reports them, for keys generated on the
    /// card; `None` for imported keys, which a YubiKey cannot attest.
    generated: Option<(u8, u8)>,
}

/// The card's state.
pub struct SoftCard {
    selected: bool,
    pin: Zeroizing<Vec<u8>>,
    retries: u8,
    verified: bool,
    slots: HashMap<u8, SlotEntry>,
    chain: Zeroizing<Vec<u8>>,
    pending: Zeroizing<Vec<u8>>,
    /// Every APDU received, with any VERIFY data blanked: for tests of the host side.
    pub log: Vec<Vec<u8>>,
    /// Card sessions run so far: for tests that the host side uses one per operation.
    pub sessions: usize,
    /// The card's serial (`GET SERIAL`).
    serial: u32,
    /// Factory attestation (slot `F9`), from a synthetic hierarchy; `None` answers
    /// `GET ATTESTATION` with "instruction not supported".
    attestation: Option<TestDevice>,
}

impl SoftCard {
    pub fn new(pin: &[u8]) -> Self {
        SoftCard {
            selected: false,
            pin: Zeroizing::new(pin.to_vec()),
            retries: MAX_PIN_RETRIES,
            verified: false,
            slots: HashMap::new(),
            chain: Zeroizing::new(Vec::new()),
            pending: Zeroizing::new(Vec::new()),
            log: Vec::new(),
            sessions: 0,
            serial: DEFAULT_SERIAL,
            attestation: None,
        }
    }

    /// Give the card a serial and a factory attestation key from a synthetic hierarchy.
    pub fn with_attestation(mut self, device: TestDevice) -> Self {
        self.serial = device.serial;
        self.attestation = Some(device);
        self
    }

    pub fn serial(&self) -> u32 {
        self.serial
    }

    /// Set the policy bytes attestation reports for a key generated on the card
    /// (PIN 01 never, 02 once, 03 always; touch 01 never, 02 always, 03 cached).
    pub fn set_policy(&mut self, slot: Slot, pin: u8, touch: u8) {
        if let Some(e) = self.slots.get_mut(&slot.id()) {
            if e.generated.is_some() {
                e.generated = Some((pin, touch));
            }
        }
    }

    /// Generate a key on the card, with a self-signed certificate; returns its public key.
    /// Attestation reports PIN `once` and touch `always` unless [`SoftCard::set_policy`]
    /// changes them.
    pub fn generate(&mut self, slot: Slot, alg: Algorithm) -> PublicKey {
        let key = SlotKey::generate(alg);
        let cert = key.self_signed_certificate(&format!("relay-softcard slot {:02x}", slot.id()));
        self.put(slot, key, cert, Some((0x02, 0x02)))
    }

    /// Import a key and its certificate; like on a YubiKey, it cannot be attested.
    pub fn insert(&mut self, slot: Slot, key: SlotKey, certificate_der: Vec<u8>) -> PublicKey {
        self.put(slot, key, certificate_der, None)
    }

    fn put(
        &mut self,
        slot: Slot,
        key: SlotKey,
        certificate: Vec<u8>,
        generated: Option<(u8, u8)>,
    ) -> PublicKey {
        let pk = key.public_key();
        self.slots.insert(
            slot.id(),
            SlotEntry {
                key,
                certificate,
                generated,
            },
        );
        pk
    }

    /// Load a slot from a PKCS#8 key PEM and a certificate PEM.
    pub fn load_pem(
        &mut self,
        slot: Slot,
        key_pem: &str,
        cert_pem: &str,
    ) -> Result<PublicKey, PivError> {
        let key = SlotKey::from_pkcs8_pem(key_pem)?;
        let cert = x509_cert::Certificate::from_pem(cert_pem.as_bytes())
            .map_err(|e| PivError::InvalidArgument(format!("bad certificate PEM: {e}")))?;
        let spki = cert
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .expect("SPKI DER");
        if spki != key.public_key().spki() {
            return Err(PivError::InvalidArgument(
                "certificate does not match key".into(),
            ));
        }
        Ok(self.insert(slot, key, cert.to_der().expect("certificate DER")))
    }

    /// Load a card from a directory of `slot-XX.key.pem` / `slot-XX.cert.pem` pairs.
    pub fn load_dir(dir: &std::path::Path, pin: &[u8]) -> Result<Self, PivError> {
        let mut card = SoftCard::new(pin);
        let entries = std::fs::read_dir(dir)
            .map_err(|e| PivError::InvalidArgument(format!("{}: {e}", dir.display())))?;
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let Some(slot) = name
                .strip_prefix("slot-")
                .and_then(|n| n.strip_suffix(".key.pem"))
            else {
                continue;
            };
            let slot = Slot::parse(slot)?;
            let read = |p: std::path::PathBuf| {
                std::fs::read_to_string(&p)
                    .map_err(|e| PivError::InvalidArgument(format!("{}: {e}", p.display())))
            };
            let key = read(e.path())?;
            let cert = read(dir.join(format!("slot-{:02x}.cert.pem", slot.id())))?;
            card.load_pem(slot, &key, &cert)?;
        }
        Ok(card)
    }

    /// Write a slot's key and certificate as `slot-XX.key.pem` / `slot-XX.cert.pem`.
    pub fn write_slot(
        dir: &std::path::Path,
        slot: Slot,
        key: &SlotKey,
        certificate_der: &[u8],
    ) -> std::io::Result<()> {
        use x509_cert::der::EncodePem;
        std::fs::create_dir_all(dir)?;
        let cert =
            x509_cert::Certificate::from_der(certificate_der).map_err(std::io::Error::other)?;
        std::fs::write(
            dir.join(format!("slot-{:02x}.key.pem", slot.id())),
            key.to_pkcs8_pem().as_bytes(),
        )?;
        std::fs::write(
            dir.join(format!("slot-{:02x}.cert.pem", slot.id())),
            cert.to_pem(LineEnding::LF).map_err(std::io::Error::other)?,
        )
    }

    pub fn public_key(&self, slot: Slot) -> Option<PublicKey> {
        self.slots.get(&slot.id()).map(|e| e.key.public_key())
    }

    /// Tries left before the PIN blocks.
    pub fn pin_retries(&self) -> u8 {
        self.retries
    }

    /// Simulate removing and reinserting the card: drops selection and PIN state.
    pub fn reset(&mut self) {
        self.selected = false;
        self.verified = false;
        self.chain.clear();
        self.pending.clear();
    }

    fn handle(&mut self, apdu: &[u8]) -> Vec<u8> {
        let sw = |s: u16| s.to_be_bytes().to_vec();
        if apdu.len() < 4 {
            return sw(0x6700);
        }
        let (cla, ins, p1, p2) = (apdu[0], apdu[1], apdu[2], apdu[3]);
        let body = &apdu[4..];
        let data: &[u8] = match body.len() {
            0 | 1 => &[],
            _ => {
                let lc = body[0] as usize;
                if body.len() < 1 + lc {
                    return sw(0x6700);
                }
                &body[1..1 + lc]
            }
        };
        if ins == 0xc0 {
            return self.next_chunk();
        }
        if cla & 0x10 != 0 {
            self.chain.extend_from_slice(data);
            return sw(0x9000);
        }
        let mut full = Zeroizing::new(std::mem::take(&mut *self.chain));
        full.extend_from_slice(data);

        let result: Result<Vec<u8>, u16> = match ins {
            0xa4 => {
                if p1 == 0x04 && full.starts_with(&PIV_AID) {
                    self.selected = true;
                    Ok(Vec::new())
                } else {
                    Err(0x6a82)
                }
            }
            _ if !self.selected => Err(0x6985),
            0x20 => self.verify(p1, p2, &full),
            0x87 => self.general_authenticate(p1, p2, &full),
            0xcb => self.get_data(&full),
            0xf8 => Ok(self.serial.to_be_bytes().to_vec()),
            0xf9 => self.attest(p1),
            _ => Err(0x6d00),
        };
        match result {
            Ok(out) => {
                *self.pending = out;
                self.next_chunk()
            }
            Err(s) => sw(s),
        }
    }

    fn next_chunk(&mut self) -> Vec<u8> {
        let n = self.pending.len().min(RESPONSE_CHUNK);
        let mut out: Vec<u8> = self.pending.drain(..n).collect();
        let left = self.pending.len();
        if left == 0 {
            out.extend_from_slice(&[0x90, 0x00]);
        } else {
            out.extend_from_slice(&[0x61, if left > 255 { 0 } else { left as u8 }]);
        }
        out
    }

    fn verify(&mut self, p1: u8, p2: u8, data: &[u8]) -> Result<Vec<u8>, u16> {
        if p2 != 0x80 {
            return Err(0x6a88);
        }
        // P1 = FF: reset the security status (SP 800-73-4), no PIN, no attempt spent.
        if p1 == 0xff {
            if !data.is_empty() {
                return Err(0x6a86);
            }
            self.verified = false;
            return Ok(Vec::new());
        }
        if self.retries == 0 {
            return Err(0x6983);
        }
        if data.is_empty() {
            return if self.verified {
                Ok(Vec::new())
            } else {
                Err(0x63c0 | self.retries as u16)
            };
        }
        if data.len() != 8 {
            return Err(0x6a80);
        }
        let given: Vec<u8> = data.iter().copied().take_while(|b| *b != 0xff).collect();
        let given = Zeroizing::new(given);
        if *given == *self.pin {
            self.retries = MAX_PIN_RETRIES;
            self.verified = true;
            Ok(Vec::new())
        } else {
            self.retries -= 1;
            self.verified = false;
            Err(if self.retries == 0 {
                0x6983
            } else {
                0x63c0 | self.retries as u16
            })
        }
    }

    fn general_authenticate(&mut self, alg: u8, slot: u8, data: &[u8]) -> Result<Vec<u8>, u16> {
        let entry = self.slots.get(&slot).ok_or(0x6a82u16)?;
        if algorithm_id(entry.key.algorithm()).ok() != Some(alg) {
            return Err(0x6a80);
        }
        if !self.verified {
            return Err(0x6982);
        }
        let (tag, challenge) = parse_challenge(data).ok_or(0x6a80u16)?;
        // Tag 85 asks for ECDH with the peer key; 81 for a signature or raw RSA.
        if tag == 0x85 {
            let secret: Zeroizing<Vec<u8>> = match &entry.key {
                SlotKey::P256(k) => {
                    let peer =
                        p256::PublicKey::from_sec1_bytes(&challenge).map_err(|_| 0x6a80u16)?;
                    let s = p256::ecdh::diffie_hellman(k.as_nonzero_scalar(), peer.as_affine());
                    Zeroizing::new(s.raw_secret_bytes().to_vec())
                }
                SlotKey::P384(k) => {
                    let peer =
                        p384::PublicKey::from_sec1_bytes(&challenge).map_err(|_| 0x6a80u16)?;
                    let s = p384::ecdh::diffie_hellman(k.as_nonzero_scalar(), peer.as_affine());
                    Zeroizing::new(s.raw_secret_bytes().to_vec())
                }
                SlotKey::X25519(k) => {
                    let peer: [u8; 32] = challenge.as_slice().try_into().map_err(|_| 0x6a80u16)?;
                    Zeroizing::new(
                        k.diffie_hellman(&x25519_dalek::PublicKey::from(peer))
                            .as_bytes()
                            .to_vec(),
                    )
                }
                SlotKey::Rsa(_) | SlotKey::Ed25519(_) => return Err(0x6a80),
            };
            return Ok(wrap_response(&secret));
        }
        if tag != 0x81 {
            return Err(0x6a80);
        }
        let out: Vec<u8> = match &entry.key {
            SlotKey::Rsa(k) => {
                let size = k.size();
                if challenge.len() != size {
                    return Err(0x6a80);
                }
                let c = rsa::BoxedUint::from_be_slice(&challenge, k.n_bits_precision())
                    .map_err(|_| 0x6a80u16)?;
                let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
                let m = rsa::hazmat::rsa_decrypt_and_check(k.as_ref(), Some(&mut rng), &c)
                    .map_err(|_| 0x6a80u16)?;
                m.to_be_bytes().to_vec()
            }
            SlotKey::P256(k) => {
                use p256::ecdsa::signature::hazmat::PrehashSigner;
                if challenge.len() != 32 {
                    return Err(0x6a80);
                }
                let sig: p256::ecdsa::Signature =
                    k.sign_prehash(&challenge).map_err(|_| 0x6a80u16)?;
                sig.to_der().as_bytes().to_vec()
            }
            SlotKey::P384(k) => {
                use p384::ecdsa::signature::hazmat::PrehashSigner;
                if challenge.len() != 48 {
                    return Err(0x6a80);
                }
                let sig: p384::ecdsa::Signature =
                    k.sign_prehash(&challenge).map_err(|_| 0x6a80u16)?;
                sig.to_der().as_bytes().to_vec()
            }
            SlotKey::Ed25519(k) => {
                // EdDSA signs the whole message (YubiKey 5.7: algorithm E0).
                use ed25519_dalek::Signer;
                k.sign(&challenge).to_bytes().to_vec()
            }
            SlotKey::X25519(_) => return Err(0x6a80),
        };
        Ok(wrap_response(&out))
    }

    /// `GET ATTESTATION`: a certificate for a key generated on the card, signed by `F9`.
    fn attest(&self, slot: u8) -> Result<Vec<u8>, u16> {
        let device = self.attestation.as_ref().ok_or(0x6d00u16)?;
        let entry = self.slots.get(&slot).ok_or(0x6a82u16)?;
        let (pin, touch) = entry.generated.ok_or(0x6a80u16)?;
        let o = LeafOptions::for_device(device, pin, touch);
        Ok(device.attestation_certificate(slot, entry.key.public_key().spki(), &o))
    }

    fn get_data(&self, data: &[u8]) -> Result<Vec<u8>, u16> {
        if data.len() != 5 || data[0] != 0x5c || data[1] != 0x03 {
            return Err(0x6a80);
        }
        let obj = [data[2], data[3], data[4]];
        let certificate = if obj == relay_core::piv::F9_CERTIFICATE_OBJECT {
            self.attestation
                .as_ref()
                .map(|d| d.f9_certificate())
                .ok_or(0x6a82u16)?
        } else {
            self.slots
                .iter()
                .find(|(id, _)| {
                    Slot::new(**id)
                        .map(|s| s.certificate_object() == obj)
                        .unwrap_or(false)
                })
                .map(|(_, e)| e.certificate.clone())
                .ok_or(0x6a82u16)?
        };
        let mut inner = vec![0x70];
        push_len(&mut inner, certificate.len());
        inner.extend_from_slice(&certificate);
        inner.extend_from_slice(&[0x71, 0x01, 0x00, 0xfe, 0x00]);
        let mut resp = vec![0x53];
        push_len(&mut resp, inner.len());
        resp.extend_from_slice(&inner);
        Ok(resp)
    }
}

impl CardTransport for SoftCard {
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, PivError> {
        let mut logged = apdu.to_vec();
        if apdu.len() > 5 && apdu[1] == 0x20 {
            logged.truncate(5); // never keep PIN bytes
        }
        self.log.push(logged);
        Ok(self.handle(apdu))
    }

    /// Like a PC/SC transaction ended with a card reset: selection and PIN state are gone.
    fn session(&mut self, f: &mut dyn FnMut(&mut dyn CardTransport)) -> Result<(), PivError> {
        self.sessions += 1;
        f(self);
        self.reset();
        Ok(())
    }
}

fn push_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xff {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    }
}

fn read_len(d: &[u8]) -> Option<(usize, &[u8])> {
    match *d.first()? {
        l @ 0..=0x7f => Some((l as usize, &d[1..])),
        0x81 => Some((*d.get(1)? as usize, d.get(2..)?)),
        0x82 => Some((
            ((*d.get(1)? as usize) << 8) | *d.get(2)? as usize,
            d.get(3..)?,
        )),
        _ => None,
    }
}

/// `7C { 82 L out }`.
fn wrap_response(out: &[u8]) -> Vec<u8> {
    let mut inner = vec![0x82];
    push_len(&mut inner, out.len());
    inner.extend_from_slice(out);
    let mut resp = vec![0x7c];
    push_len(&mut resp, inner.len());
    resp.extend_from_slice(&inner);
    resp
}

/// Extract the input and its tag (`81` challenge or `85` peer key) from
/// `7C { 82 00, 81|85 L data }`.
fn parse_challenge(data: &[u8]) -> Option<(u8, Zeroizing<Vec<u8>>)> {
    if *data.first()? != 0x7c {
        return None;
    }
    let (len, mut rest) = read_len(&data[1..])?;
    rest = rest.get(..len)?;
    while !rest.is_empty() {
        let tag = rest[0];
        let (l, after) = read_len(&rest[1..])?;
        let value = after.get(..l)?;
        if tag == 0x81 || tag == 0x85 {
            return Some((tag, Zeroizing::new(value.to_vec())));
        }
        rest = &after[l..];
    }
    None
}
