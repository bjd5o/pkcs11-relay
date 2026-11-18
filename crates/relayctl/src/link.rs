//! `relayctl app-link`: a signed setup link for the approver app, printed as a URL and a QR
//! code (wire-format §11). The link holds only public pins; it is signed by the manifest
//! signer, through gpg (an OpenPGP card works through gpg-agent) or a software key for tests.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use relay_core::setup_link::{spki_pin, SetupLinkDraft, DEFAULT_LIFETIME, MAX_LIFETIME};
use relay_core::signer::{self, SignerStatus};
use relay_core::ManifestSigner;

use crate::util::{duration, now, utc};

/// How the link is signed.
pub enum LinkSigner<'a> {
    Gpg { key: &'a str, program: &'a str },
    Software(&'a Path),
}

/// What `app-link` needs; anything `None` is asked for, unless `no_input`.
pub struct Options<'a> {
    pub relay_url: Option<String>,
    pub relay_ca: Option<PathBuf>,
    pub public_relay: bool,
    pub signer: Option<LinkSigner<'a>>,
    pub device_id: Option<String>,
    pub valid_for: Option<u64>,
    pub no_input: bool,
    pub skip_relay_check: bool,
    pub svg: Option<PathBuf>,
    /// `relay-server` and its config, to check the device id isn't registered already.
    pub relay_admin: Option<(String, PathBuf)>,
    /// Revoke an existing device with this id first (after a typed confirmation).
    pub replace: bool,
}

fn admin(relay_server: &str, config: &Path, args: &[&str]) -> Result<String, String> {
    let o = Command::new(relay_server)
        .arg("--config")
        .arg(config)
        .arg("admin")
        .args(args)
        .output()
        .map_err(|e| format!("running {relay_server}: {e}"))?;
    if !o.status.success() {
        return Err(format!(
            "{relay_server} admin {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&o.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&o.stdout).into_owned())
}

/// Refuse a device id the relay already holds, unless `replace` revokes it (confirmed).
fn check_device_free(
    admin_cmd: &(String, PathBuf),
    device: &str,
    replace: bool,
) -> Result<(), String> {
    let list = admin(&admin_cmd.0, &admin_cmd.1, &["devices", "list"])?;
    let taken = list.lines().any(|l| {
        serde_json::from_str::<serde_json::Value>(l)
            .ok()
            .is_some_and(|v| v["device_id"] == device)
    });
    if !taken {
        return Ok(());
    }
    if !replace {
        return Err(format!(
            "device {device} is already registered at the relay; choose another id, or pass --replace to revoke it first"
        ));
    }
    if !crate::util::confirm_phrase(
        &format!("Revoke device {device} at the relay so a new phone can take its id?"),
        &format!("revoke {device}"),
    )? {
        return Err("not revoked".into());
    }
    admin(&admin_cmd.0, &admin_cmd.1, &["devices", "revoke", device])?;
    eprintln!("revoked device {device}");
    Ok(())
}

/// The finished link and what to show beside it.
pub struct Link {
    pub url: String,
    pub fingerprint: String,
    pub exp: u64,
}

fn ask(question: &str, default: Option<&str>) -> Result<String, String> {
    let mut out = std::io::stderr();
    match default {
        Some(d) => write!(out, "{question} [{d}]: "),
        None => write!(out, "{question}: "),
    }
    .and_then(|_| out.flush())
    .map_err(|e| e.to_string())?;
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    let line = line.trim().to_string();
    match (line.is_empty(), default) {
        (true, Some(d)) => Ok(d.to_string()),
        (true, None) => Err(format!("{question}: no answer")),
        (false, _) => Ok(line),
    }
}

fn need<T>(v: Option<T>, no_input: bool, flag: &str) -> Result<Option<T>, String> {
    match (v, no_input) {
        (Some(v), _) => Ok(Some(v)),
        (None, true) => Err(format!("{flag} is required with --no-input")),
        (None, false) => Ok(None),
    }
}

/// This machine's address on the default route, as a suggestion (no packet is sent).
fn lan_address() -> Option<String> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:9").ok()?;
    Some(s.local_addr().ok()?.ip().to_string())
}

/// The SPKI pin of the first certificate in a PEM file.
pub fn ca_pin(pem: &[u8]) -> Result<[u8; 32], String> {
    use x509_cert::der::{DecodePem, Encode};
    let cert = x509_cert::Certificate::from_pem(pem).map_err(|e| format!("relay CA: {e}"))?;
    let spki = cert
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(|e| e.to_string())?;
    Ok(spki_pin(&spki))
}

/// The signer's public key, armored.
fn public_key(s: &LinkSigner<'_>) -> Result<Vec<u8>, String> {
    match s {
        LinkSigner::Gpg { key, program } => {
            let o = Command::new(program)
                .args(["--armor", "--export", key])
                .output()
                .map_err(|e| format!("running {program}: {e}"))?;
            if !o.status.success() || o.stdout.is_empty() {
                return Err(format!("{program} --export {key} returned no key"));
            }
            Ok(o.stdout)
        }
        LinkSigner::Software(p) => {
            let k = relay_core::PgpSecretKey::from_bytes(
                &std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?,
            )
            .map_err(|e| e.to_string())?;
            Ok(k.public_armored().map_err(|e| e.to_string())?.into_bytes())
        }
    }
}

/// A binary detached signature over `data`.
fn sign(s: &LinkSigner<'_>, data: &[u8]) -> Result<Vec<u8>, String> {
    match s {
        LinkSigner::Gpg { key, program } => {
            let mut child = Command::new(program)
                .args([
                    "--detach-sign",
                    "--digest-algo",
                    "SHA256",
                    "--local-user",
                    key,
                    "--output",
                    "-",
                ])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .map_err(|e| format!("running {program}: {e}"))?;
            child
                .stdin
                .take()
                .expect("stdin")
                .write_all(data)
                .map_err(|e| e.to_string())?;
            let o = child.wait_with_output().map_err(|e| e.to_string())?;
            if !o.status.success() {
                return Err(format!("{program} failed ({})", o.status));
            }
            Ok(o.stdout)
        }
        LinkSigner::Software(p) => {
            let k = relay_core::PgpSecretKey::from_bytes(
                &std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?,
            )
            .map_err(|e| e.to_string())?;
            k.sign_detached_binary(data).map_err(|e| e.to_string())
        }
    }
}

/// Check the live relay: TLS chains to the CA (when pinned), it serves that CA and the same
/// signer key.
fn check_relay(url: &str, ca: Option<&[u8]>, fingerprint: &str) -> Result<(), String> {
    let throwaway = std::sync::Arc::new(relay_core::signing::SoftwareKey::generate_p256());
    let rc = relay_approver::relay::RelayClient::new(url, ca, throwaway)
        .map_err(|e| format!("relay: {e}"))?;
    let get = |path: &str| {
        rc.call("GET", path, b"", "application/json")
            .map_err(|e| format!("{url}{path}: {e}"))
            .and_then(|r| {
                if r.ok() {
                    Ok(r.body)
                } else {
                    Err(format!("{url}{path}: HTTP {}", r.status))
                }
            })
    };
    if let Some(ca) = ca {
        let served = get("/v1/relay-ca.pem")?;
        if ca_pin(&served)? != ca_pin(ca)? {
            return Err(
                "the relay serves a different CA at /v1/relay-ca.pem than --relay-ca".into(),
            );
        }
    }
    let key = ManifestSigner::from_bytes(&get("/v1/manifest-signer.asc")?)
        .map_err(|e| format!("relay's signer key: {e}"))?;
    if key.fingerprint() != fingerprint {
        return Err(format!(
            "the relay trusts manifest signer {}, not {fingerprint}",
            key.fingerprint()
        ));
    }
    Ok(())
}

/// Make, check and sign a link.
pub fn make(o: Options<'_>) -> Result<Link, String> {
    let relay = match need(o.relay_url, o.no_input, "--relay-url")? {
        Some(r) => r,
        None => {
            let suggestion = lan_address().map(|ip| format!("https://{ip}:8443"));
            ask("Relay URL", suggestion.as_deref())?
        }
    };
    let relay = relay.trim_end_matches('/').to_string();
    let ca_pem = if o.public_relay {
        None
    } else {
        let path = match need(o.relay_ca, o.no_input, "--relay-ca (or --public-relay)")? {
            Some(p) => p,
            None => PathBuf::from(ask("Relay CA certificate (PEM file)", None)?),
        };
        Some(std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?)
    };
    let link_signer = o
        .signer
        .ok_or("give --gpg-key, or --pgp-secret for a software key")?;
    let key_bytes = public_key(&link_signer)?;
    let key = signer::parse_key(&key_bytes).map_err(|e| e.to_string())?;
    let fingerprint = signer::fingerprint(&key);
    match signer::signer_status(&[key], now()).map_err(|e| e.to_string())? {
        SignerStatus::Usable { .. } => {}
        s => {
            return Err(format!(
                "manifest signer {fingerprint} {}; the app and the relay would refuse it",
                s.describe()
            ))
        }
    }
    eprintln!("manifest signer {fingerprint}");
    let device = match need(o.device_id, o.no_input, "--device-id")? {
        Some(d) => d,
        None => ask("Device id for this phone (a-z, 0-9, -)", Some("iphone"))?,
    };
    relay_core::check_id(&device).map_err(|e| format!("device id: {e}"))?;
    match &o.relay_admin {
        Some(a) => check_device_free(a, &device, o.replace)?,
        None if o.replace => return Err("--replace needs --relay-config".into()),
        None => eprintln!(
            "note: not checking whether {device} is already registered (give --relay-config to check)"
        ),
    }
    let lifetime = o.valid_for.unwrap_or(DEFAULT_LIFETIME);
    if lifetime == 0 || lifetime > MAX_LIFETIME {
        return Err("--valid-for must be at most 7d".into());
    }
    if !o.skip_relay_check {
        check_relay(&relay, ca_pem.as_deref(), &fingerprint)?;
    }
    let iat = now();
    let draft = SetupLinkDraft {
        relay,
        ca: ca_pem.as_deref().map(ca_pin).transpose()?,
        signer: fingerprint.clone(),
        device,
        iat,
        exp: iat + lifetime,
    };
    let bytes = draft.signed_bytes().map_err(|e| e.to_string())?;
    let sig = sign(&link_signer, bytes.as_bytes())?;
    let url = draft.with_signature(&sig).map_err(|e| e.to_string())?;
    // The same check the relay and the app run.
    let verifier = ManifestSigner::from_bytes(&key_bytes).map_err(|e| e.to_string())?;
    relay_core::setup_link::verify_setup_link(&url, &verifier, now(), 60)
        .map_err(|e| format!("the signed link does not verify: {e}"))?;
    if let Some(p) = &o.svg {
        crate::util::write(p, svg(&url)?)?;
    }
    Ok(Link {
        url,
        fingerprint,
        exp: draft.exp,
    })
}

/// The QR code as Unicode half-blocks, light on dark so it scans from a dark terminal too.
pub fn terminal_qr(url: &str) -> Result<String, String> {
    use qrcode::render::unicode::Dense1x2;
    let code = qrcode::QrCode::new(url.as_bytes()).map_err(|e| e.to_string())?;
    Ok(code
        .render::<Dense1x2>()
        .dark_color(Dense1x2::Light)
        .light_color(Dense1x2::Dark)
        .quiet_zone(true)
        .build())
}

pub fn svg(url: &str) -> Result<String, String> {
    use qrcode::render::svg;
    let code = qrcode::QrCode::new(url.as_bytes()).map_err(|e| e.to_string())?;
    Ok(code.render::<svg::Color>().min_dimensions(400, 400).build())
}

/// What `app-link` prints.
pub fn show(link: &Link) -> Result<String, String> {
    let mut out = format!("{}\n\n{}\n", link.url, terminal_qr(&link.url)?);
    out.push_str(&format!(
        "Scan with the iPhone camera. Signer {}; the link works until {} ({}).\n",
        link.fingerprint,
        utc(link.exp),
        duration(link.exp.saturating_sub(now()))
    ));
    if link.url.len() > 600 {
        out.push_str(
            "Note: this signer's signatures make a large code that is hard to scan from a screen; \
             an Ed25519 signing key gives a much smaller one, or use --svg to scan an image.\n",
        );
    }
    Ok(out)
}
