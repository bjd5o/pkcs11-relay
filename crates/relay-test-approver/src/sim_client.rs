//! `sim-client`: the client side of the simulator end-to-end test (tests/sim-e2e.sh). It pairs
//! (the person in the simulator approves the code), submits one RSA-OAEP decrypt with the
//! `openbao-unseal` key, waits for the app's answer and checks the plaintext, exactly as the
//! provider would. Blocking; the relay CA from the gate config.

use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use relay_approver::relay::RelayClient;
use relay_core::mechanism::Mechanism;
use relay_core::request::{RequestContext, UnsignedRequest};
use relay_core::response::{verify_response, Outcome};
use relay_core::seal::ReplyKey;
use relay_core::signing::SoftwareKey;
use relay_core::{ManifestSigner, Op};

use crate::gate::Config;
use crate::relay::now;

const SECRET: &[u8] = b"the unseal key, decrypted on a simulated iPhone";

pub fn run(cfg: &Config, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    let read = |p: &std::path::Path| std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()));
    let pem = String::from_utf8_lossy(&read(&cfg.client_key)?).into_owned();
    let key = Arc::new(SoftwareKey::from_pkcs8_pem(&pem).map_err(|e| e.to_string())?);
    let ca = cfg.relay_ca_file.as_deref().map(read).transpose()?;
    let relay =
        RelayClient::new(&cfg.relay_url, ca.as_deref(), key.clone()).map_err(|e| e.to_string())?;
    let signer =
        ManifestSigner::from_bytes(&read(&cfg.manifest_signer)?).map_err(|e| e.to_string())?;
    let (manifest, _) = relay
        .fetch_manifest(&cfg.manifest_url, &signer, None, now(), 60)
        .map_err(|e| e.to_string())?;
    let unseal = manifest
        .keys
        .iter()
        .find(|k| k.label == "openbao-unseal")
        .ok_or("no openbao-unseal key in the manifest")?
        .clone();

    // Pairing: ask until the person in the simulator approves.
    let b64 = base64::engine::general_purpose::STANDARD;
    let body = serde_json::json!({"client_id": cfg.client_id, "public_key": b64.encode(key.public_key().spki()), "host": "sim-e2e"});
    println!(
        "sim-client: pairing code {}",
        relay_core::pairing::pairing_code(key.public_key().spki())
    );
    loop {
        let r = relay
            .call(
                "POST",
                "/v1/clients/pending",
                body.to_string().as_bytes(),
                "application/json",
            )
            .map_err(|e| e.to_string())?;
        if r.json()["status"] == "approved" {
            break;
        }
        if Instant::now() > deadline {
            return Err("pairing was not approved in time".into());
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    println!("sim-client: paired");

    // One decrypt, resubmitted if it expires before the person gets to it.
    let ct = relay_core::padding::encrypt_oaep_sha256(&unseal.public_key, &[], SECRET)
        .map_err(|e| e.to_string())?;
    while Instant::now() < deadline {
        let reply = ReplyKey::generate();
        let t = now();
        let u = UnsignedRequest::new(
            &cfg.client_id,
            &unseal,
            Op::Decrypt,
            Mechanism::RsaPkcsOaep { label: vec![] },
            ct.clone(),
            RequestContext {
                host: "sim-e2e".into(),
                purpose: "simulator end-to-end decrypt".into(),
                consumer: "sim-client".into(),
            },
            reply.public_bytes(),
            t,
            t + 110,
        )
        .map_err(|e| e.to_string())?;
        let req = u.clone().with_signature(key.sign(&u.to_be_signed()));
        let r = relay
            .call("POST", "/v1/requests", req.bytes(), "application/cbor")
            .map_err(|e| e.to_string())?;
        if r.status != 202 {
            return Err(format!(
                "submit: HTTP {} {}",
                r.status,
                String::from_utf8_lossy(&r.body)
            ));
        }
        println!(
            "sim-client: decrypt request {} submitted",
            hex::encode(req.fields.req_id)
        );
        loop {
            if now() >= req.fields.expires_at {
                println!("sim-client: request expired; submitting again");
                break;
            }
            let path = format!(
                "/v1/requests/{}/result?wait=10",
                hex::encode(req.fields.req_id)
            );
            let r = relay
                .call("GET", &path, b"", "application/octet-stream")
                .map_err(|e| e.to_string())?;
            match r.status {
                200 => {
                    return match verify_response(&r.body, req.bytes(), &manifest, now(), 60, reply)
                        .map_err(|e| e.to_string())?
                    {
                        Outcome::Approved(pt) if pt.as_slice() == SECRET => {
                            println!("sim-client: decrypt approved and verified");
                            Ok(())
                        }
                        o => Err(format!("unexpected outcome: {o:?}")),
                    };
                }
                204 => continue,
                404 => break,
                s => return Err(format!("result: HTTP {s}")),
            }
        }
    }
    Err("no approval in time".into())
}
