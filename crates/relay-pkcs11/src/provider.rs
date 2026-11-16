//! The provider's logic in safe Rust: slots, objects, sessions and operations. `ffi.rs` only
//! moves bytes between C and these functions.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use cryptoki_sys::*;
use relay_core::request::{RequestContext, UnsignedRequest};
use relay_core::seal::ReplyKey;
use relay_core::signing::SoftwareKey;
use relay_core::{
    verify_response, Algorithm, Error, Manifest, ManifestKey, ManifestSigner, Mechanism, Op,
    Outcome, Role,
};
use zeroize::Zeroizing;

use crate::client::{now, RelayClient};
use crate::config::Config;
use crate::discovery::{host_name, Discovery, SlotView};
use crate::log;

pub type Rv = CK_RV;

/// Map a core error to its PKCS#11 return code (Failure handling table).
pub fn rv(e: &Error) -> Rv {
    e.ckr().unwrap_or(relay_core::error::ckr::DEVICE_ERROR) as Rv
}

#[derive(Debug, Clone)]
pub struct Object {
    pub handle: CK_OBJECT_HANDLE,
    pub public: bool,
    pub key: ManifestKey,
}

/// An attribute value, or the reason it cannot be returned.
pub enum Attr {
    Value(Vec<u8>),
    Sensitive,
    Invalid,
}

fn ulong(v: CK_ULONG) -> Vec<u8> {
    v.to_ne_bytes().to_vec()
}

fn bool_attr(b: bool) -> Vec<u8> {
    vec![if b { CK_TRUE } else { CK_FALSE }]
}

/// DER OCTET STRING around the uncompressed point, as `CKA_EC_POINT` requires.
fn ec_point_der(point: &[u8]) -> Vec<u8> {
    let mut v = vec![0x04, point.len() as u8];
    v.extend_from_slice(point);
    v
}

impl Object {
    pub fn attribute(&self, t: CK_ATTRIBUTE_TYPE) -> Attr {
        let k = &self.key;
        let pk = &k.public_key;
        let rsa = k.algorithm.is_rsa();
        let signs = matches!(k.role, Role::Sign | Role::Auth);
        let decrypts = k.role == Role::Encrypt;
        let v = match t {
            CKA_CLASS => ulong(if self.public {
                CKO_PUBLIC_KEY
            } else {
                CKO_PRIVATE_KEY
            }),
            CKA_KEY_TYPE => ulong(if rsa { CKK_RSA } else { CKK_EC }),
            CKA_TOKEN => bool_attr(true),
            CKA_PRIVATE => bool_attr(false),
            CKA_MODIFIABLE
            | CKA_COPYABLE
            | CKA_DESTROYABLE
            | CKA_DERIVE
            | CKA_WRAP
            | CKA_UNWRAP
            | CKA_SIGN_RECOVER
            | CKA_VERIFY_RECOVER
            | CKA_ALWAYS_AUTHENTICATE
            | CKA_TRUSTED => bool_attr(false),
            CKA_LOCAL => bool_attr(true),
            CKA_LABEL => k.label.as_bytes().to_vec(),
            CKA_ID => k.id.clone(),
            CKA_SIGN if !self.public => bool_attr(signs),
            CKA_DECRYPT if !self.public => bool_attr(decrypts),
            CKA_VERIFY if self.public => bool_attr(signs),
            CKA_ENCRYPT if self.public => bool_attr(decrypts),
            CKA_SIGN | CKA_DECRYPT | CKA_VERIFY | CKA_ENCRYPT => bool_attr(false),
            CKA_SENSITIVE | CKA_ALWAYS_SENSITIVE | CKA_NEVER_EXTRACTABLE if !self.public => {
                bool_attr(true)
            }
            CKA_EXTRACTABLE if !self.public => bool_attr(false),
            CKA_MODULUS if rsa => pk.rsa_modulus().unwrap_or_default(),
            CKA_PUBLIC_EXPONENT if rsa => pk.rsa_public_exponent().unwrap_or_default(),
            CKA_MODULUS_BITS if rsa => {
                ulong((k.algorithm.rsa_modulus_len().unwrap_or(0) * 8) as CK_ULONG)
            }
            CKA_EC_PARAMS if !rsa => relay_core::keys::P256_EC_PARAMS.to_vec(),
            CKA_EC_POINT if !rsa => ec_point_der(&pk.ec_point().unwrap_or_default()),
            CKA_PUBLIC_KEY_INFO => pk.spki().to_vec(),
            CKA_PRIVATE_EXPONENT | CKA_PRIME_1 | CKA_PRIME_2 | CKA_EXPONENT_1 | CKA_EXPONENT_2
            | CKA_COEFFICIENT | CKA_VALUE
                if !self.public =>
            {
                return Attr::Sensitive
            }
            _ => return Attr::Invalid,
        };
        Attr::Value(v)
    }

    /// Whether every template attribute equals this object's value.
    pub fn matches(&self, template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)]) -> bool {
        template
            .iter()
            .all(|(t, want)| matches!(self.attribute(*t), Attr::Value(v) if &v == want))
    }
}

/// A cryptographic operation in progress. The result is cached after the first call so the
/// length-query second call needs no new approval (spec: one approval per operation).
pub struct Operation {
    pub op: Op,
    pub key: ManifestKey,
    pub mechanism: Mechanism,
    pub data: Vec<u8>,
    pub result: Option<Zeroizing<Vec<u8>>>,
    pub busy: bool,
}

pub struct Session {
    pub slot: CK_SLOT_ID,
    pub flags: CK_FLAGS,
    pub find: Option<Vec<CK_OBJECT_HANDLE>>,
    pub sign: Option<Operation>,
    pub decrypt: Option<Operation>,
    /// Software RSA-OAEP encryption with an `encrypt` key's public key: no approval needed.
    pub encrypt: Option<(ManifestKey, Vec<u8>)>,
}

pub struct Provider {
    pub cfg: Config,
    signer: ManifestSigner,
    relay: RelayClient,
    discovery: Mutex<Discovery>,
    pub sessions: Mutex<HashMap<CK_SESSION_HANDLE, Session>>,
    next_session: AtomicU64,
}

fn load_or_create_client_key(path: &std::path::Path) -> Result<SoftwareKey, String> {
    match std::fs::read_to_string(path) {
        Ok(pem) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(m) = std::fs::metadata(path) {
                    if m.permissions().mode() & 0o077 != 0 {
                        log::warn(&format!(
                            "{} is readable by others; it should be mode 0600",
                            path.display()
                        ));
                    }
                }
            }
            SoftwareKey::from_pkcs8_pem(&pem).map_err(|e| format!("client key: {e}"))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // First run: generate the identity key that pairing will register.
            let key = SoftwareKey::generate_ed25519();
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
            }
            let pem = key.to_pkcs8_pem().map_err(|e| e.to_string())?;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            use std::io::Write;
            opts.open(path)
                .and_then(|mut f| f.write_all(pem.as_bytes()))
                .map_err(|e| format!("writing {}: {e}", path.display()))?;
            log::warn(&format!(
                "generated a new client identity key at {}",
                path.display()
            ));
            Ok(key)
        }
        Err(e) => Err(format!("reading {}: {e}", path.display())),
    }
}

impl Provider {
    pub fn new(cfg: Config) -> Result<Self, String> {
        let signer_bytes = std::fs::read(&cfg.manifest_signer)
            .map_err(|e| format!("{}: {e}", cfg.manifest_signer.display()))?;
        let signer = ManifestSigner::from_bytes(&signer_bytes).map_err(|e| e.to_string())?;
        let key = Arc::new(load_or_create_client_key(&cfg.client_key)?);
        let ca = match &cfg.relay_ca_file {
            Some(p) => Some(std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?),
            None => None,
        };
        let relay = RelayClient::new(&cfg.relay_url, ca.as_deref(), key)?;
        let discovery = Mutex::new(Discovery::load(&cfg, &signer));
        Ok(Provider {
            cfg,
            signer,
            relay,
            discovery,
            sessions: Mutex::new(HashMap::new()),
            next_session: AtomicU64::new(1),
        })
    }

    fn disc(&self) -> std::sync::MutexGuard<'_, Discovery> {
        self.discovery.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn lock_sessions(&self) -> std::sync::MutexGuard<'_, HashMap<CK_SESSION_HANDLE, Session>> {
        self.sessions.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn slots(&self) -> Vec<SlotView> {
        self.disc().slots(&self.cfg, &self.signer, &self.relay)
    }

    /// Objects in a slot (private and public per key), with stable handles.
    pub fn objects(&self, slot: CK_SLOT_ID) -> Vec<Object> {
        let slots = self.slots();
        let Some(s) = slots.get(slot as usize) else {
            return Vec::new();
        };
        let mut d = self.disc();
        s.keys
            .iter()
            .flat_map(|k| {
                [false, true].map(|public| Object {
                    handle: d.handle(&k.fingerprint, public),
                    public,
                    key: k.clone(),
                })
            })
            .collect()
    }

    pub fn object(&self, slot: CK_SLOT_ID, h: CK_OBJECT_HANDLE) -> Option<Object> {
        self.objects(slot).into_iter().find(|o| o.handle == h)
    }

    pub fn open_session(&self, slot: CK_SLOT_ID, flags: CK_FLAGS) -> CK_SESSION_HANDLE {
        let h = self.next_session.fetch_add(1, Ordering::SeqCst);
        self.lock_sessions().insert(
            h,
            Session {
                slot,
                flags,
                find: None,
                sign: None,
                decrypt: None,
                encrypt: None,
            },
        );
        h
    }

    fn manifest_snapshot(&self) -> Option<Manifest> {
        self.disc().manifest().cloned()
    }

    /// One operation end to end: build and sign the request (core checks role, mechanism
    /// and length first), submit, wait until our deadline, verify, open.
    pub fn run(
        &self,
        op: Op,
        key: &ManifestKey,
        mechanism: Mechanism,
        input: Vec<u8>,
    ) -> Result<Zeroizing<Vec<u8>>, Rv> {
        let manifest = self.manifest_snapshot().ok_or(CKR_DEVICE_ERROR)?;
        let t = now();
        let deadline = t + self.cfg.timeout_secs;
        let reply = ReplyKey::generate();
        let consumer = std::env::current_exe()
            .ok()
            .and_then(|p| {
                p.file_name()
                    .map(|n| n.to_string_lossy().chars().take(255).collect())
            })
            .unwrap_or_default();
        let ctx = RequestContext {
            host: host_name(&self.cfg),
            purpose: self.cfg.purpose.chars().take(255).collect(),
            consumer,
        };
        let u = UnsignedRequest::new(
            &self.cfg.client_id,
            key,
            op,
            mechanism,
            input,
            ctx,
            reply.public_bytes(),
            t,
            deadline,
        )
        .map_err(|e| rv(&e))?;
        let req = u
            .clone()
            .with_signature(self.relay.key().sign(&u.to_be_signed()));
        let id = hex::encode(req.fields.req_id);
        log::info(&format!(
            "request {id}: {} with {} on {}",
            op.as_str(),
            req.fields.mechanism.name(),
            key.label
        ));
        match self.relay.post_cbor("/v1/requests", req.bytes()) {
            Ok(r) if r.status == 202 => {}
            Ok(r) => {
                log::warn(&format!(
                    "request {id} refused by the relay: HTTP {} {}",
                    r.status,
                    r.error_kind()
                ));
                return Err(CKR_DEVICE_ERROR);
            }
            Err(e) => {
                // Failure handling: relay unreachable for a request fails immediately.
                log::warn(&format!("relay unreachable for request {id}: {e}"));
                return Err(CKR_DEVICE_ERROR);
            }
        }
        loop {
            let t = now();
            if t >= deadline {
                log::warn(&format!("request {id}: no answer before expires_at"));
                return Err(CKR_FUNCTION_CANCELED);
            }
            let wait = (deadline - t).min(25);
            let r = match self
                .relay
                .get(&format!("/v1/requests/{id}/result?wait={wait}"))
            {
                Ok(r) => r,
                Err(e) => {
                    log::warn(&format!("request {id}: polling failed ({e}); retrying"));
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    continue;
                }
            };
            match r.status {
                200 => {
                    return match verify_response(
                        &r.body,
                        req.bytes(),
                        &manifest,
                        now(),
                        self.cfg.skew_secs,
                        reply,
                    ) {
                        Ok(Outcome::Approved(result)) => {
                            log::info(&format!("request {id}: approved"));
                            Ok(result)
                        }
                        Ok(o @ Outcome::Denied(reason)) => {
                            log::warn(&format!(
                                "request {id}: denied ({:?})",
                                reason.map(|r| r.as_str())
                            ));
                            Err(o.ckr() as Rv)
                        }
                        Ok(o @ Outcome::Error(reason)) => {
                            log::warn(&format!(
                                "request {id}: approver reported an error ({:?})",
                                reason.map(|r| r.as_str())
                            ));
                            Err(o.ckr() as Rv)
                        }
                        Err(e) => {
                            if e.is_tampering() {
                                log::error(&format!(
                                    "request {id}: RESPONSE REJECTED, POSSIBLE TAMPERING: {e}"
                                ));
                            } else {
                                log::warn(&format!("request {id}: response rejected: {e}"));
                            }
                            Err(rv(&e))
                        }
                    };
                }
                204 => continue,
                404 => {
                    log::warn(&format!("request {id}: expired at the relay"));
                    return Err(CKR_FUNCTION_CANCELED);
                }
                s => {
                    log::warn(&format!("request {id}: HTTP {s} {}", r.error_kind()));
                    return Err(CKR_DEVICE_ERROR);
                }
            }
        }
    }
}

/// The mechanisms a key supports (wire-format §3), as PKCS#11 types.
pub fn mechanisms_for(k: &ManifestKey) -> Vec<CK_MECHANISM_TYPE> {
    Mechanism::allowed_for(k.role, k.algorithm)
        .iter()
        .map(|m| *m as CK_MECHANISM_TYPE)
        .collect()
}

pub fn mechanism_info(m: CK_MECHANISM_TYPE, algs: &[Algorithm]) -> Option<CK_MECHANISM_INFO> {
    use relay_core::mechanism::ckm;
    let rsa_bits = || {
        let bits: Vec<CK_ULONG> = algs
            .iter()
            .filter_map(|a| a.rsa_modulus_len())
            .map(|k| (k * 8) as CK_ULONG)
            .collect();
        (
            bits.iter().min().copied().unwrap_or(2048),
            bits.iter().max().copied().unwrap_or(4096),
        )
    };
    let (min, max, flags) = match m as u64 {
        ckm::RSA_PKCS_OAEP => {
            let (a, b) = rsa_bits();
            (a, b, CKF_DECRYPT | CKF_ENCRYPT)
        }
        ckm::SHA256_RSA_PKCS | ckm::RSA_PKCS => {
            let (a, b) = rsa_bits();
            (a, b, CKF_SIGN)
        }
        ckm::ECDSA | ckm::ECDSA_SHA256 => (
            256,
            256,
            CKF_SIGN | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS,
        ),
        _ => return None,
    };
    Some(CK_MECHANISM_INFO {
        ulMinKeySize: min,
        ulMaxKeySize: max,
        flags: flags | CKF_HW,
    })
}
