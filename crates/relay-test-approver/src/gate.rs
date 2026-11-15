//! The milestone 2 gate, run as a client against a relay and the three fixture approvers:
//! request → approval → response, and the negative paths (expired request, denial, duplicate
//! id, unpaired client, unattested device). All client-side checks are `relay-core`'s.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use relay_core::error::ckr;
use relay_core::request::{RequestContext, SignedRequest, UnsignedRequest};
use relay_core::seal::ReplyKey;
use relay_core::signing::SoftwareKey;
use relay_core::{
    verify_response, Error, Manifest, ManifestKey, ManifestSigner, Mechanism, Op, Outcome,
};
use reqwest::{Method, StatusCode};
use serde::Deserialize;
use serde_json::json;

use crate::relay::{load_manifest, now, Relay};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub relay_url: String,
    pub manifest_url: String,
    pub manifest_signer: PathBuf,
    pub client_key: PathBuf,
    pub client_id: String,
}

struct Gate {
    relay: Relay,
    manifest: Manifest,
    client_id: String,
    failures: Vec<String>,
}

/// What a provider would return for one operation.
#[derive(Debug, PartialEq, Eq)]
enum Ret {
    Ok(Vec<u8>),
    Ckr(u64, String),
}

impl Gate {
    fn key(&self, label: &str) -> &ManifestKey {
        self.manifest
            .keys
            .iter()
            .find(|k| k.label == label)
            .unwrap_or_else(|| panic!("manifest has no {label}"))
    }

    fn check(&mut self, name: &str, ok: bool, detail: String) {
        if ok {
            println!("PASS  {name}");
        } else {
            println!("FAIL  {name}: {detail}");
            self.failures.push(name.to_string());
        }
    }

    fn build(
        &self,
        label: &str,
        op: Op,
        mech: Mechanism,
        input: Vec<u8>,
        ttl: u64,
    ) -> Result<(SignedRequest, ReplyKey), Error> {
        let reply = ReplyKey::generate();
        let ctx = RequestContext {
            host: "gate.test".into(),
            purpose: format!("milestone 2 gate: {label}"),
            consumer: "relay-test-approver gate".into(),
        };
        let t = now();
        let u = UnsignedRequest::new(
            &self.client_id,
            self.key(label),
            op,
            mech,
            input,
            ctx,
            reply.public_bytes(),
            t,
            t + ttl,
        )?;
        let sig = self.relay.key().sign(&u.to_be_signed());
        Ok((u.with_signature(sig), reply))
    }

    /// Submit, wait until the deadline, verify: the provider's operation path in miniature.
    async fn operate(&self, req: &SignedRequest, reply: ReplyKey) -> Ret {
        let r = match self.relay.post_cbor("/v1/requests", req.bytes()).await {
            Ok(r) => r,
            Err(e) => return Ret::Ckr(ckr::DEVICE_ERROR, e),
        };
        if r.status != StatusCode::ACCEPTED {
            return Ret::Ckr(
                ckr::DEVICE_ERROR,
                format!("submit: {} {}", r.status, r.error_kind()),
            );
        }
        loop {
            // Never wait past our own deadline (`expires_at`).
            let t = now();
            if t >= req.fields.expires_at {
                return Ret::Ckr(ckr::FUNCTION_CANCELED, "deadline passed".into());
            }
            let wait = (req.fields.expires_at - t).min(10);
            let path = format!(
                "/v1/requests/{}/result?wait={wait}",
                hex::encode(req.fields.req_id)
            );
            let r = match self.relay.get(&path).await {
                Ok(r) => r,
                Err(e) => return Ret::Ckr(ckr::DEVICE_ERROR, e),
            };
            match r.status {
                StatusCode::OK => {
                    return match verify_response(
                        &r.body,
                        req.bytes(),
                        &self.manifest,
                        now(),
                        60,
                        reply,
                    ) {
                        Ok(Outcome::Approved(res)) => Ret::Ok(res.to_vec()),
                        Ok(o @ Outcome::Denied(_)) | Ok(o @ Outcome::Error(_)) => {
                            let c = o.ckr();
                            Ret::Ckr(c, format!("{o:?}"))
                        }
                        Err(e) => Ret::Ckr(e.ckr().unwrap_or(ckr::GENERAL_ERROR), e.kind().into()),
                    };
                }
                StatusCode::NO_CONTENT => continue,
                StatusCode::NOT_FOUND => {
                    return Ret::Ckr(
                        ckr::FUNCTION_CANCELED,
                        "request expired at the relay".into(),
                    )
                }
                s => return Ret::Ckr(ckr::DEVICE_ERROR, format!("result: {s}")),
            }
        }
    }
}

fn rng() -> rand_core::UnwrapErr<getrandom::SysRng> {
    rand_core::UnwrapErr(getrandom::SysRng)
}

pub async fn run(cfg: Config) -> Result<(), String> {
    let signer = ManifestSigner::from_bytes(
        &std::fs::read(&cfg.manifest_signer).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let manifest = load_manifest(&cfg.manifest_url, &signer, 60).await?;
    let key = SoftwareKey::from_pkcs8_pem(
        &std::fs::read_to_string(&cfg.client_key).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let relay = Relay::new(&cfg.relay_url, Arc::new(key));
    let mut g = Gate {
        relay,
        manifest,
        client_id: cfg.client_id.clone(),
        failures: Vec::new(),
    };

    // --- Pairing (wait for the relay and approver A to come up) ---
    let b64 = base64::engine::general_purpose::STANDARD;
    let body = json!({"client_id": g.client_id, "public_key": b64.encode(g.relay.key().public_key().spki()), "host": "gate.test"});
    let code = relay_core::pairing::pairing_code(g.relay.key().public_key().spki());
    println!("pairing code {code}");
    let start = Instant::now();
    let mut approved = false;
    while start.elapsed() < Duration::from_secs(90) {
        if let Ok(r) = g.relay.post_json("/v1/clients/pending", &body).await {
            if r.json()["status"] == "approved" {
                approved = true;
                break;
            }
        }
        if let Ok(r) = g.relay.get("/v1/clients/self").await {
            if r.json()["status"] == "approved" {
                approved = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    g.check("pairing approved by device A", approved, "timed out".into());
    if !approved {
        return Err("pairing failed".into());
    }
    // Wait until all three devices have registered their keys.
    let want = [
        "openbao-unseal",
        "sign-ec",
        "sign-rsa",
        "auth-ec",
        "auth-rsa",
        "denied",
        "stale",
    ];
    let mut listed = Vec::new();
    for _ in 0..60 {
        let r = g.relay.get("/v1/keys").await?;
        listed = r.json()["keys"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|k| b64.decode(k["public_key"].as_str()?).ok())
            .filter_map(|spki| relay_core::PublicKey::from_spki(&spki).ok())
            .filter_map(|pk| g.manifest.key(pk.fingerprint()).map(|k| k.label.clone()))
            .collect();
        if want.iter().all(|w| listed.contains(&w.to_string())) {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let all = want.iter().all(|w| listed.contains(&w.to_string()));
    g.check(
        "keys listed: approved keys only, no attest key",
        all && !listed.iter().any(|l| l == "attest" || l == "unapproved"),
        format!("{listed:?}"),
    );

    // --- Request → approval → response ---
    let pt = b"the unseal key".to_vec();
    let pk = g.key("openbao-unseal").public_key.spki().to_vec();
    let rsa_pk = <rsa::PublicKey as rsa::pkcs8::DecodePublicKey>::from_public_key_der(&pk)
        .map_err(|e| e.to_string())?;
    let ct = rsa_pk
        .encrypt(&mut rng(), rsa::Oaep::<sha2::Sha256>::new(), &pt)
        .map_err(|e| e.to_string())?;
    let (req, reply) = g
        .build(
            "openbao-unseal",
            Op::Decrypt,
            Mechanism::RsaPkcsOaep { label: vec![] },
            ct,
            60,
        )
        .map_err(|e| e.to_string())?;
    let r = g.operate(&req, reply).await;
    g.check(
        "decrypt (RSA-OAEP) approved, plaintext recovered",
        r == Ret::Ok(pt),
        format!("{r:?}"),
    );

    // Duplicate id: the same signed bytes again.
    let dup = g.relay.post_cbor("/v1/requests", req.bytes()).await?;
    g.check(
        "duplicate request id rejected",
        dup.status == StatusCode::CONFLICT && dup.error_kind() == "DuplicateRequestId",
        format!("{} {}", dup.status, dup.error_kind()),
    );

    let digest_info = {
        use sha2::Digest;
        let mut v = relay_core::padding::SHA256_DIGEST_INFO_PREFIX.to_vec();
        v.extend_from_slice(&sha2::Sha256::digest(b"ssh challenge"));
        v
    };
    for (label, mech, input) in [
        ("sign-ec", Mechanism::EcdsaSha256, b"a release tag".to_vec()),
        (
            "sign-rsa",
            Mechanism::Sha256RsaPkcs,
            b"a release tag".to_vec(),
        ),
        ("auth-ec", Mechanism::Ecdsa, vec![0x5a; 32]),
        ("auth-rsa", Mechanism::RsaPkcs, digest_info.clone()),
    ] {
        let name = format!(
            "sign with {label} ({}) approved, signature passes check 5",
            mech.name()
        );
        let (req, reply) = g
            .build(label, Op::Sign, mech, input, 60)
            .map_err(|e| e.to_string())?;
        let r = g.operate(&req, reply).await;
        g.check(&name, matches!(r, Ret::Ok(_)), format!("{r:?}"));
    }

    // --- Negative paths ---
    let (req, reply) = g
        .build("denied", Op::Sign, Mechanism::Ecdsa, vec![1; 32], 60)
        .map_err(|e| e.to_string())?;
    let r = g.operate(&req, reply).await;
    g.check(
        "signed denial → CKR_FUNCTION_REJECTED",
        matches!(r, Ret::Ckr(ckr::FUNCTION_REJECTED, _)),
        format!("{r:?}"),
    );

    let (req, reply) = g
        .build("stale", Op::Sign, Mechanism::Ecdsa, vec![2; 32], 60)
        .map_err(|e| e.to_string())?;
    let r = g.operate(&req, reply).await;
    g.check(
        "unattested device (expired attestation) → CKR_DEVICE_ERROR",
        matches!(&r, Ret::Ckr(ckr::DEVICE_ERROR, k) if k == "AttestationExpired"),
        format!("{r:?}"),
    );

    // Device B answers after a delay longer than this request's lifetime.
    let (req, reply) = g
        .build("denied", Op::Sign, Mechanism::Ecdsa, vec![3; 32], 1)
        .map_err(|e| e.to_string())?;
    let r = g.operate(&req, reply).await;
    g.check(
        "expired request → CKR_FUNCTION_CANCELED",
        matches!(r, Ret::Ckr(ckr::FUNCTION_CANCELED, _)),
        format!("{r:?}"),
    );

    let intruder = g.relay.with_key(Arc::new(SoftwareKey::generate_ed25519()));
    let (req, _) = g
        .build(
            "sign-ec",
            Op::Sign,
            Mechanism::EcdsaSha256,
            b"x".to_vec(),
            60,
        )
        .map_err(|e| e.to_string())?;
    let r = intruder.post_cbor("/v1/requests", req.bytes()).await?;
    g.check(
        "unpaired client rejected",
        r.status == StatusCode::FORBIDDEN && r.error_kind() == "UnpairedClient",
        format!("{} {}", r.status, r.error_kind()),
    );

    let (req, _) = g
        .build("unapproved", Op::Sign, Mechanism::Ecdsa, vec![4; 32], 60)
        .map_err(|e| e.to_string())?;
    let r = g.relay.post_cbor("/v1/requests", req.bytes()).await?;
    g.check(
        "key the client was not approved for rejected",
        r.status == StatusCode::FORBIDDEN && r.error_kind() == "KeyNotApproved",
        format!("{} {}", r.status, r.error_kind()),
    );

    let h = relay_core::relay_auth::AuthHeaders::sign(g.relay.key(), "GET", "/v1/keys", b"", now());
    let first = g
        .relay
        .send_with(
            Method::GET,
            "/v1/keys",
            Vec::new(),
            "application/octet-stream",
            &h,
        )
        .await?;
    let replay = g
        .relay
        .send_with(
            Method::GET,
            "/v1/keys",
            Vec::new(),
            "application/octet-stream",
            &h,
        )
        .await?;
    g.check(
        "relay-auth replay rejected",
        first.status == StatusCode::OK && replay.status == StatusCode::UNAUTHORIZED,
        format!("{} then {}", first.status, replay.status),
    );

    let local = g.build(
        "sign-ec",
        Op::Decrypt,
        Mechanism::RsaPkcsOaep { label: vec![] },
        vec![0; 256],
        60,
    );
    g.check(
        "role violation refused locally",
        matches!(local, Err(Error::KeyFunctionNotPermitted)),
        format!("{:?}", local.err()),
    );

    if g.failures.is_empty() {
        println!("gate passed");
        Ok(())
    } else {
        Err(format!(
            "{} gate check(s) failed: {:?}",
            g.failures.len(),
            g.failures
        ))
    }
}
