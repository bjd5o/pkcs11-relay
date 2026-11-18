//! `relayctl` command line.
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::Command;

use clap::{Parser, Subcommand, ValueEnum};
use relay_core::piv::Slot;
use relay_core::{Algorithm, Role};
use relayctl::keygen::{self, Pin, Touch};
use relayctl::{card, hw, manifest, util};

#[derive(Parser)]
#[command(
    version,
    about = "pkcs11-relay admin CLI: keys, manifest, attestation, relay admin"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Keys on a YubiKey (PIV). Every command needs RELAY_TEST_YUBIKEY_SERIAL=<serial>.
    Key {
        #[command(subcommand)]
        command: KeyCmd,
    },
    /// Edit, sign and verify the trust manifest.
    Manifest {
        #[command(subcommand)]
        command: ManifestCmd,
    },
    /// Device attestation with an attest key on a YubiKey.
    Attest {
        #[command(subcommand)]
        command: AttestCmd,
    },
    /// Write the setup file the approver app imports: relay URL and CA, manifest URL and
    /// signer, device id and attestation window. Public material only.
    AppConfig {
        #[arg(long)]
        relay_url: String,
        /// The relay's CA certificate (PEM).
        #[arg(long)]
        relay_ca: Option<PathBuf>,
        /// Default: <relay-url>/v1/manifest.
        #[arg(long)]
        manifest_url: Option<String>,
        /// The manifest signer's OpenPGP public key.
        #[arg(long)]
        signer: PathBuf,
        #[arg(long)]
        device_id: String,
        #[arg(long, default_value_t = 30)]
        attestation_days: u64,
        /// A window in minutes instead of days (to test renewal, which starts at 75%).
        #[arg(long, conflicts_with = "attestation_days")]
        attestation_minutes: Option<u64>,
        /// Testing only: PEM roots that replace Yubico's attestation root in the app.
        #[arg(long, hide = true)]
        attestation_roots: Option<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    /// The relay's admin commands (runs `relay-server admin`).
    Relay {
        /// The relay-server binary.
        #[arg(long, default_value = "relay-server")]
        relay_server: String,
        /// The relay's config file.
        #[arg(long)]
        config: Option<PathBuf>,
        #[command(subcommand)]
        command: RelayCmd,
    },
}

fn slot(s: &str) -> Result<Slot, String> {
    Slot::parse(s).map_err(|e| e.to_string())
}

#[derive(Clone, Copy, ValueEnum)]
enum RoleArg {
    Sign,
    Auth,
    Encrypt,
    Attest,
}

impl From<RoleArg> for Role {
    fn from(r: RoleArg) -> Role {
        match r {
            RoleArg::Sign => Role::Sign,
            RoleArg::Auth => Role::Auth,
            RoleArg::Encrypt => Role::Encrypt,
            RoleArg::Attest => Role::Attest,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum AlgArg {
    #[value(name = "rsa2048")]
    Rsa2048,
    #[value(name = "rsa4096")]
    Rsa4096,
    P256,
    P384,
    Ed25519,
    X25519,
}

impl From<AlgArg> for Algorithm {
    fn from(a: AlgArg) -> Algorithm {
        match a {
            AlgArg::Rsa2048 => Algorithm::Rsa2048,
            AlgArg::Rsa4096 => Algorithm::Rsa4096,
            AlgArg::P256 => Algorithm::P256,
            AlgArg::P384 => Algorithm::P384,
            AlgArg::Ed25519 => Algorithm::Ed25519,
            AlgArg::X25519 => Algorithm::X25519,
        }
    }
}

/// PIN policy `never` is deliberately not offered (spec: never use it on these keys).
#[derive(Clone, Copy, ValueEnum)]
enum PinArg {
    Once,
    Always,
}

#[derive(Clone, Copy, ValueEnum)]
enum TouchArg {
    Never,
    Always,
    Cached,
}

#[derive(Subcommand)]
enum KeyCmd {
    /// Generate a key in a slot, write its certificate, print the fingerprint.
    Generate {
        #[arg(long)]
        serial: u32,
        #[arg(long, value_parser = slot)]
        slot: Slot,
        #[arg(long, value_enum)]
        role: RoleArg,
        #[arg(long, value_enum)]
        alg: AlgArg,
        #[arg(long, value_enum, default_value = "once")]
        pin_policy: PinArg,
        /// Default: `always` for attest keys, `never` otherwise.
        #[arg(long, value_enum)]
        touch_policy: Option<TouchArg>,
        /// Replace a key already in the slot (asks for a typed confirmation too).
        #[arg(long)]
        force: bool,
        /// Write the public key here (PEM).
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long, default_value = "pkcs11-relay key")]
        common_name: String,
    },
    /// List the keys (with certificates) on a YubiKey.
    List {
        #[arg(long)]
        serial: u32,
    },
    /// Check that a card session leaves no PIN verified: sign once with the PIN, then try
    /// again without it in a new session, which must be refused. Writes nothing to the card.
    /// Use a signing key with PIN policy `once` and touch `never`.
    CheckPinReset {
        #[arg(long)]
        serial: u32,
        #[arg(long, value_parser = slot)]
        slot: Slot,
    },
    /// Export a slot's public key (PEM).
    Export {
        #[arg(long)]
        serial: u32,
        #[arg(long, value_parser = slot)]
        slot: Slot,
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ManifestCmd {
    /// Start an empty manifest.
    Init {
        #[arg(long)]
        manifest: PathBuf,
    },
    /// Add a key, from a public-key file or a YubiKey slot.
    Add {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long, conflicts_with_all = ["serial", "slot"])]
        public_key: Option<PathBuf>,
        #[arg(long, requires = "slot")]
        serial: Option<u32>,
        #[arg(long, value_parser = slot, requires = "serial")]
        slot: Option<Slot>,
        #[arg(long, value_enum)]
        role: RoleArg,
        #[arg(long)]
        label: String,
        /// CKA_ID, hex.
        #[arg(long)]
        id: String,
        /// The hardware token the key lives on (one PKCS#11 slot per token).
        #[arg(long)]
        token: String,
        /// With --serial/--slot: don't store the key's YubiKey attestation. By default it is
        /// read (read-only) and stored for attest keys.
        #[arg(long, conflicts_with_all = ["hardware_attestation", "attestation_chain"])]
        no_hardware_attestation: bool,
        /// With --serial/--slot: also store the attestation for a key of another role (only keys
        /// generated on the card have one).
        #[arg(long, requires = "slot")]
        hardware_attestation: bool,
        /// With --public-key: a PEM chain gathered elsewhere (attestation certificate, then
        /// the F9 certificate, then any intermediates).
        #[arg(long, requires = "public_key")]
        attestation_chain: Option<PathBuf>,
        /// Testing only: trust these roots instead of Yubico's.
        #[arg(long, hide = true)]
        attestation_roots: Option<PathBuf>,
    },
    /// Set the manifest's device policy.
    Set {
        #[arg(long)]
        manifest: PathBuf,
        /// Whether every attest key must carry a YubiKey attestation chain.
        #[arg(long)]
        require_hardware_attestation: Option<bool>,
        /// The longest attestation window clients accept, e.g. `7d`, `12h`, `30m`.
        #[arg(long, value_parser = util::parse_duration)]
        max_attestation_window: Option<u64>,
    },
    /// Remove keys by fingerprint or label.
    Remove {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long, conflicts_with = "label")]
        fingerprint: Option<String>,
        #[arg(long)]
        label: Option<String>,
        #[arg(long)]
        token: Option<String>,
    },
    Show {
        #[arg(long)]
        manifest: PathBuf,
        /// Testing only: trust these roots instead of Yubico's.
        #[arg(long, hide = true)]
        attestation_roots: Option<PathBuf>,
    },
    /// Increase the version, set the validity, write the detached signature.
    Sign {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long, default_value_t = 30)]
        valid_days: u64,
        /// Sign with gpg using this key (e.g. your OpenPGP card's key id).
        #[arg(long, conflicts_with = "pgp_secret")]
        gpg_key: Option<String>,
        #[arg(long, default_value = "gpg")]
        gpg: String,
        /// Sign with this unprotected software OpenPGP secret key instead (test setups).
        #[arg(long)]
        pgp_secret: Option<PathBuf>,
        /// Verify the result against this signer public key, as clients would.
        #[arg(long)]
        verify_with: Option<PathBuf>,
        /// Testing only: trust these roots instead of Yubico's.
        #[arg(long, hide = true)]
        attestation_roots: Option<PathBuf>,
    },
    /// Check a manifest exactly as clients do.
    Verify {
        #[arg(long)]
        manifest: PathBuf,
        /// Default: <manifest>.asc
        #[arg(long)]
        signature: Option<PathBuf>,
        #[arg(long)]
        signer: PathBuf,
        /// A previously accepted manifest (with its .asc), for the rollback check.
        #[arg(long)]
        cached: Option<PathBuf>,
        #[arg(long, default_value_t = 60)]
        skew: u64,
        /// Testing only: trust these roots instead of Yubico's.
        #[arg(long, hide = true)]
        attestation_roots: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum AttestCmd {
    /// Sign a device's attestation with the attest key (offline-attest-key flow).
    Sign {
        #[arg(long)]
        serial: u32,
        #[arg(long, value_parser = slot)]
        slot: Slot,
        #[arg(long)]
        device_id: String,
        /// The device's public key (PEM or DER SubjectPublicKeyInfo, P-256).
        #[arg(long)]
        device_key: PathBuf,
        #[arg(long, default_value_t = 30)]
        days: u64,
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
enum RelayCmd {
    Clients {
        #[command(subcommand)]
        command: ListRevoke,
    },
    Devices {
        #[command(subcommand)]
        command: ListRevoke,
    },
    /// Export the audit log as JSON lines.
    Audit {
        #[arg(long, default_value_t = 0)]
        since: i64,
    },
}

#[derive(Subcommand)]
enum ListRevoke {
    List,
    Revoke { id: String },
}

fn main() {
    if let Err(e) = run(Cli::parse()) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Cmd::Key { command } => match command {
            KeyCmd::Generate {
                serial,
                slot,
                role,
                alg,
                pin_policy,
                touch_policy,
                force,
                out,
                common_name,
            } => {
                let role: Role = role.into();
                let touch = match touch_policy {
                    Some(TouchArg::Never) => Touch::Never,
                    Some(TouchArg::Always) => Touch::Always,
                    Some(TouchArg::Cached) => Touch::Cached,
                    None if role == Role::Attest => Touch::Always,
                    None => Touch::Never,
                };
                let pin = match pin_policy {
                    PinArg::Once => Pin::Once,
                    PinArg::Always => Pin::Always,
                };
                let g = keygen::Generate {
                    serial,
                    slot,
                    role,
                    alg: alg.into(),
                    pin,
                    touch,
                    force,
                    common_name,
                };
                let pk = keygen::generate(&g)?;
                println!("{}", card::fingerprint_line(slot, &pk));
                if let Some(out) = out {
                    util::write(&out, util::public_key_pem(&pk))?;
                }
                Ok(())
            }
            KeyCmd::List { serial } => {
                let mut c = relay_pcsc::open(serial)?;
                for (s, k) in card::list(&mut c)? {
                    println!("{}", card::fingerprint_line(s, &k));
                }
                Ok(())
            }
            KeyCmd::CheckPinReset { serial, slot } => {
                let mut c = relay_pcsc::open(serial)?;
                let pin = util::prompt_secret("PIV PIN: ")?;
                match card::check_pin_reset(&mut c, slot, pin.as_bytes())? {
                    card::PinReset::Cleared => {
                        println!("ok: the second session was refused without a PIN; sessions clear the PIN state");
                        Ok(())
                    }
                    card::PinReset::StillVerified => Err(
                        "FAILED: the second session signed without a PIN; the PIN stayed verified across sessions".into(),
                    ),
                }
            }
            KeyCmd::Export { serial, slot, out } => {
                let mut c = relay_pcsc::open(serial)?;
                let pem = util::public_key_pem(&card::export(&mut c, slot)?);
                match out {
                    Some(p) => util::write(&p, pem),
                    None => {
                        print!("{pem}");
                        Ok(())
                    }
                }
            }
        },
        Cmd::Manifest { command } => match command {
            ManifestCmd::Init { manifest: m } => manifest::init(&m),
            ManifestCmd::Add {
                manifest: m,
                public_key,
                serial,
                slot,
                role,
                label,
                id,
                token,
                no_hardware_attestation,
                hardware_attestation,
                attestation_chain,
                attestation_roots,
            } => {
                let role: Role = role.into();
                let anchors = hw::Anchors::load(attestation_roots.as_deref())?;
                let (key, hw_att) = match (public_key, serial, slot) {
                    (Some(p), _, _) => {
                        let key = util::read_public_key(&p)?;
                        match attestation_chain {
                            Some(c) => {
                                let (h, a) = hw::from_pem(&c, &key, &anchors, util::now())?;
                                println!("attested: {}", hw::describe(&a));
                                (key, Some(h))
                            }
                            None => (key, None),
                        }
                    }
                    (None, Some(serial), Some(slot)) => {
                        let mut c = relay_pcsc::open(serial)?;
                        let want = !no_hardware_attestation
                            && (role == Role::Attest || hardware_attestation);
                        if want {
                            let (key, h, a) = hw::from_card(&mut c, slot, &anchors, util::now())?;
                            println!("attested: {}", hw::describe(&a));
                            (key, Some(h))
                        } else {
                            (card::export(&mut c, slot)?, None)
                        }
                    }
                    _ => return Err("give --public-key, or --serial and --slot".into()),
                };
                if role == Role::Attest && hw_att.is_none() {
                    eprintln!(
                        "warning: attest key without hardware attestation; clients reject it unless configured with require = false"
                    );
                }
                let fp = manifest::add(&m, key, hw_att, role, &label, &id, &token)?;
                println!("added {fp}");
                Ok(())
            }
            ManifestCmd::Set {
                manifest: m,
                require_hardware_attestation,
                max_attestation_window,
            } => {
                manifest::set(&m, require_hardware_attestation, max_attestation_window)?;
                print!("{}", manifest::show(&m, &hw::Anchors::load(None)?)?);
                Ok(())
            }
            ManifestCmd::Remove {
                manifest: m,
                fingerprint,
                label,
                token,
            } => {
                let n = manifest::remove(
                    &m,
                    fingerprint.as_deref(),
                    label.as_deref(),
                    token.as_deref(),
                )?;
                println!("removed {n} key(s)");
                Ok(())
            }
            ManifestCmd::Show {
                manifest: m,
                attestation_roots,
            } => {
                let anchors = hw::Anchors::load(attestation_roots.as_deref())?;
                print!("{}", manifest::show(&m, &anchors)?);
                Ok(())
            }
            ManifestCmd::Sign {
                manifest: m,
                valid_days,
                gpg_key,
                gpg,
                pgp_secret,
                verify_with,
                attestation_roots,
            } => {
                let signer = match (&gpg_key, &pgp_secret) {
                    (Some(k), None) => manifest::Signer::Gpg {
                        key: k,
                        program: &gpg,
                    },
                    (None, Some(p)) => manifest::Signer::Software(p),
                    _ => return Err("give --gpg-key or --pgp-secret".into()),
                };
                let policy = hw::Anchors::load(attestation_roots.as_deref())?.policy()?;
                let v = manifest::sign(
                    &m,
                    valid_days,
                    signer,
                    verify_with.as_deref().map(|p| (p, &policy)),
                )?;
                println!(
                    "signed version {v}; wrote {} and {}",
                    m.display(),
                    manifest::sig_path(&m).display()
                );
                Ok(())
            }
            ManifestCmd::Verify {
                manifest: m,
                signature,
                signer,
                cached,
                skew,
                attestation_roots,
            } => {
                let sig = signature.unwrap_or_else(|| manifest::sig_path(&m));
                let policy = hw::Anchors::load(attestation_roots.as_deref())?.policy()?;
                let v = manifest::verify(&m, &sig, &signer, &policy, cached.as_deref(), skew)?;
                println!(
                    "OK: version {}, valid until {}, {} keys",
                    v.version,
                    util::utc(v.valid_until),
                    v.keys.len()
                );
                for k in v.keys.iter().filter(|k| k.attested.is_some()) {
                    println!(
                        "  {} attested: {}",
                        k.label,
                        hw::describe(k.attested.as_ref().expect("attested"))
                    );
                }
                Ok(())
            }
        },
        Cmd::Attest {
            command:
                AttestCmd::Sign {
                    serial,
                    slot,
                    device_id,
                    device_key,
                    days,
                    out,
                },
        } => {
            let device = util::read_public_key(&device_key)?;
            let mut c = relay_pcsc::open(serial)?;
            let pin = util::prompt_secret("PIV PIN: ")?;
            eprintln!("Touch the YubiKey if it blinks...");
            let t = util::now();
            let st = card::attest(
                &mut c,
                slot,
                pin.as_bytes(),
                &device_id,
                device,
                t,
                t + days * 86_400,
            )?;
            util::write(&out, st.bytes())?;
            println!(
                "attestation for {device_id} valid until {}; wrote {}",
                util::utc(t + days * 86_400),
                out.display()
            );
            Ok(())
        }
        Cmd::AppConfig {
            relay_url,
            relay_ca,
            manifest_url,
            signer,
            device_id,
            attestation_days,
            attestation_minutes,
            attestation_roots,
            out,
        } => {
            let signer_pem = std::fs::read_to_string(&signer)
                .map_err(|e| format!("{}: {e}", signer.display()))?;
            let fp = relay_core::ManifestSigner::from_bytes(signer_pem.as_bytes())
                .map_err(|e| e.to_string())?
                .fingerprint();
            relay_core::check_id(&device_id).map_err(|e| e.to_string())?;
            let ca = match relay_ca {
                Some(p) => {
                    Some(std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?)
                }
                None => None,
            };
            let base = relay_url.trim_end_matches('/').to_string();
            let v = serde_json::json!({
                "relay_url": base,
                "relay_ca_pem": ca,
                "manifest_url": manifest_url.unwrap_or_else(|| format!("{base}/v1/manifest")),
                "manifest_signer": signer_pem,
                "device_id": device_id,
                "attestation_window_secs": attestation_minutes.map_or(attestation_days * 86_400, |m| m * 60),
                "attestation_roots_pem": attestation_roots
                    .map(|p| std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display())))
                    .transpose()?,
            });
            util::write(&out, serde_json::to_vec_pretty(&v).expect("json"))?;
            println!(
                "wrote {}; the app will show signer fingerprint {fp}",
                out.display()
            );
            Ok(())
        }
        Cmd::Relay {
            relay_server,
            config,
            command,
        } => {
            let mut args: Vec<String> = Vec::new();
            if let Some(c) = config {
                args.extend(["--config".into(), c.display().to_string()]);
            }
            args.push("admin".into());
            match command {
                RelayCmd::Clients { command } => {
                    args.push("clients".into());
                    push_lr(&mut args, command);
                }
                RelayCmd::Devices { command } => {
                    args.push("devices".into());
                    push_lr(&mut args, command);
                }
                RelayCmd::Audit { since } => args.extend([
                    "audit".into(),
                    "export".into(),
                    "--since".into(),
                    since.to_string(),
                ]),
            }
            let status = Command::new(&relay_server)
                .args(&args)
                .status()
                .map_err(|e| format!("running {relay_server}: {e}"))?;
            if status.success() {
                Ok(())
            } else {
                Err(format!("{relay_server} failed ({status})"))
            }
        }
    }
}

fn push_lr(args: &mut Vec<String>, c: ListRevoke) {
    match c {
        ListRevoke::List => args.push("list".into()),
        ListRevoke::Revoke { id } => args.extend(["revoke".into(), id]),
    }
}
