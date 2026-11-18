//! `relayctl manifest`: edit, sign and verify the trust manifest. Parsing and every check are
//! `relay-core`'s (`ManifestDraft`, `verify_manifest`).

use std::path::{Path, PathBuf};
use std::process::Command;

use relay_core::hw_attestation::HardwareAttestation;
use relay_core::manifest::{DraftKey, ManifestDraft, PgpSecretKey};
use relay_core::{verify_manifest, Fingerprint, Manifest, ManifestSigner, PublicKey, Role};

use crate::util::{now, utc, write};

pub fn sig_path(manifest: &Path) -> PathBuf {
    let mut s = manifest.as_os_str().to_owned();
    s.push(".asc");
    PathBuf::from(s)
}

fn load(path: &Path) -> Result<ManifestDraft, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    ManifestDraft::from_json(&bytes).map_err(|e| format!("{}: {e}", path.display()))
}

fn save(path: &Path, d: &ManifestDraft) -> Result<(), String> {
    write(path, d.to_json().map_err(|e| e.to_string())?)
}

/// Start an empty manifest. Signing bumps the version, so the first signed copy is version 2.
pub fn init(path: &Path) -> Result<(), String> {
    if path.exists() {
        return Err(format!("{} exists", path.display()));
    }
    let t = now();
    save(
        path,
        &ManifestDraft {
            version: 1,
            issued_at: t,
            valid_until: t + 86_400,
            keys: Vec::new(),
        },
    )
}

pub fn add(
    path: &Path,
    key: PublicKey,
    hardware_attestation: Option<HardwareAttestation>,
    role: Role,
    label: &str,
    id_hex: &str,
    token: &str,
) -> Result<Fingerprint, String> {
    let mut d = load(path)?;
    let id = hex::decode(id_hex).map_err(|_| "id must be hex".to_string())?;
    let fp = key.fingerprint().clone();
    d.keys.push(DraftKey {
        role,
        label: label.into(),
        id,
        token: token.into(),
        public_key: key,
        hardware_attestation,
    });
    // to_json re-validates everything: roles, algorithms, duplicates.
    save(path, &d)?;
    Ok(fp)
}

/// Remove keys by fingerprint, or by label (optionally within one token). Returns how many.
pub fn remove(
    path: &Path,
    fingerprint: Option<&str>,
    label: Option<&str>,
    token: Option<&str>,
) -> Result<usize, String> {
    let mut d = load(path)?;
    let before = d.keys.len();
    d.keys.retain(|k| {
        let hit = match (fingerprint, label) {
            (Some(fp), _) => k.public_key.fingerprint().as_str() == fp,
            (None, Some(l)) => k.label == l && token.is_none_or(|t| k.token == t),
            (None, None) => false,
        };
        !hit
    });
    let n = before - d.keys.len();
    if n == 0 {
        return Err("no matching key".into());
    }
    save(path, &d)?;
    Ok(n)
}

pub fn show(path: &Path, anchors: &crate::hw::Anchors) -> Result<String, String> {
    let d = load(path)?;
    let t = now();
    let mut out = format!(
        "version {}\nissued  {}\nvalid   until {}{}\n",
        d.version,
        utc(d.issued_at),
        utc(d.valid_until),
        if now() > d.valid_until {
            "  (EXPIRED)"
        } else {
            ""
        }
    );
    for k in &d.keys {
        out.push_str(&format!(
            "  {:<8} {:<9} {:<18} id={:<4} token={:<16} {}\n",
            k.role.as_str(),
            k.public_key.algorithm().as_str(),
            k.label,
            hex::encode(&k.id),
            k.token,
            k.public_key.fingerprint()
        ));
        if let Some(h) = &k.hardware_attestation {
            let line = match relay_core::verify_piv_attestation(
                &h.chain,
                &k.public_key,
                &anchors.roots,
                t,
            ) {
                Ok(a) => format!("attested: {}", crate::hw::describe(&a)),
                Err(e) => format!("attestation INVALID: {e}"),
            };
            out.push_str(&format!("           {line}\n"));
        } else if k.role == Role::Attest {
            out.push_str("           no hardware attestation\n");
        }
    }
    Ok(out)
}

/// How the detached signature is made.
pub enum Signer<'a> {
    /// `gpg --detach-sign` with this key (for example the OpenPGP card's signing key).
    Gpg { key: &'a str, program: &'a str },
    /// A software OpenPGP secret key file (unprotected), e.g. for test setups.
    Software(&'a Path),
}

/// Bump the version, set `issued_at` to now and `valid_until` `valid_days` ahead, write the
/// JSON and its armored detached signature. If `verify_with` is given, the result is then
/// checked exactly as a client would.
pub fn sign(
    path: &Path,
    valid_days: u64,
    signer: Signer<'_>,
    verify_with: Option<(&Path, &relay_core::HardwarePolicy)>,
) -> Result<u64, String> {
    let mut d = load(path)?;
    d.version += 1;
    d.issued_at = now();
    d.valid_until = d.issued_at + valid_days * 86_400;
    let json = d.to_json().map_err(|e| e.to_string())?;
    write(path, &json)?;
    let asc = sig_path(path);
    match signer {
        Signer::Gpg { key, program } => {
            let status = Command::new(program)
                .args([
                    "--yes",
                    "--armor",
                    "--detach-sign",
                    "--digest-algo",
                    "SHA256",
                    "--local-user",
                    key,
                    "--output",
                ])
                .arg(&asc)
                .arg(path)
                .status()
                .map_err(|e| format!("running {program}: {e}"))?;
            if !status.success() {
                return Err(format!("{program} failed ({status})"));
            }
        }
        Signer::Software(secret) => {
            let k = PgpSecretKey::from_bytes(
                &std::fs::read(secret).map_err(|e| format!("{}: {e}", secret.display()))?,
            )
            .map_err(|e| e.to_string())?;
            write(&asc, k.sign_detached(&json).map_err(|e| e.to_string())?)?;
        }
    }
    if let Some((signer, policy)) = verify_with {
        verify(path, &asc, signer, policy, None, 60)?;
    }
    Ok(d.version)
}

/// Check a manifest exactly as clients do (`relay_core::verify_manifest`). `cached` is a
/// previously accepted manifest (with its `.asc`), for the rollback check.
pub fn verify(
    path: &Path,
    sig: &Path,
    signer: &Path,
    policy: &relay_core::HardwarePolicy,
    cached: Option<&Path>,
    skew: u64,
) -> Result<Manifest, String> {
    let read = |p: &Path| std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()));
    let signer = ManifestSigner::from_bytes(&read(signer)?).map_err(|e| e.to_string())?;
    let t = now();
    let cached = match cached {
        Some(c) => Some(
            verify_manifest(
                &read(c)?,
                &read(&sig_path(c))?,
                &signer,
                policy,
                None,
                t,
                skew,
            )
            .map_err(|e| format!("cached copy: {e}"))?,
        ),
        None => None,
    };
    verify_manifest(
        &read(path)?,
        &read(sig)?,
        &signer,
        policy,
        cached.as_ref(),
        t,
        skew,
    )
    .map_err(|e| format!("{} ({})", e, e.kind()))
}
