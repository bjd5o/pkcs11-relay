//! `relay-test-approver`: run a headless approver, run the gate, or generate fixtures.
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};
use relay_test_approver::approver::{Approver, Behavior, Config, FATAL};

#[derive(Parser)]
#[command(version, about = "Headless approver for pkcs11-relay tests")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run an approver.
    Run {
        #[arg(long)]
        config: PathBuf,
        /// Approve every request that passes the checks (the default behaviour; stated
        /// explicitly in CI configs).
        #[arg(long)]
        auto_approve: bool,
        /// Deny every request that passes the checks.
        #[arg(long, conflicts_with = "auto_approve")]
        deny: bool,
        /// Wait this many seconds before answering.
        #[arg(long, default_value_t = 0)]
        delay: u64,
        /// Sign a statement whose window has already ended (negative tests).
        #[arg(long)]
        expired_attestation: bool,
        /// Long-poll instead of holding a WebSocket.
        #[arg(long)]
        long_poll: bool,
        /// Use a real YubiKey over PC/SC: `pcsc_serial` in the config, which must match
        /// RELAY_TEST_YUBIKEY_SERIAL.
        #[arg(long)]
        pcsc: bool,
    },
    /// Run the milestone 2 gate as a client.
    Gate {
        #[arg(long)]
        config: PathBuf,
    },
    /// Write test fixtures (keys, signed manifest, configs).
    GenFixtures {
        #[arg(long)]
        out: PathBuf,
        /// Where `out` is mounted in the containers that read it.
        #[arg(long, default_value = "/fixtures")]
        root: String,
        #[arg(long, default_value = "https://relay:8443")]
        relay_url: String,
        /// Networks the relay accepts pairing from.
        #[arg(
            long,
            value_delimiter = ',',
            default_value = "172.16.0.0/12,10.0.0.0/8,192.168.0.0/16,127.0.0.0/8"
        )]
        pairing_cidrs: Vec<String>,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    if let Err(e) = run(Cli::parse()).await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Cmd::Run {
            config,
            auto_approve: _,
            deny,
            delay,
            expired_attestation,
            long_poll,
            pcsc,
        } => {
            let cfg: Config =
                toml::from_str(&std::fs::read_to_string(&config).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
            let pin = std::fs::read_to_string(&cfg.pin_file).map_err(|e| e.to_string())?;
            // Opens the card afresh for each startup attempt.
            let open = || -> Result<Box<dyn relay_core::piv::CardTransport + Send>, String> {
                if pcsc {
                    let serial = cfg
                        .pcsc_serial
                        .ok_or("pcsc_serial is required with --pcsc")?;
                    Ok(Box::new(relay_pcsc::open(serial)?))
                } else {
                    let dir = cfg
                        .softcard_dir
                        .as_ref()
                        .ok_or("softcard_dir is required without --pcsc")?;
                    Ok(Box::new(
                        relay_softcard::SoftCard::load_dir(dir, pin.trim().as_bytes())
                            .map_err(|e| e.to_string())?,
                    ))
                }
            };
            let behavior = Behavior {
                deny,
                delay: Duration::from_secs(delay),
                expired_attestation,
                long_poll,
            };
            // Retry startup until the relay is reachable, but never after a rejected PIN.
            loop {
                match Approver::start(cfg.clone(), behavior.clone(), open()?).await {
                    Ok(a) => {
                        a.run().await;
                        return Ok(());
                    }
                    Err(e) if e.starts_with(FATAL) => return Err(e),
                    Err(e) => {
                        tracing::warn!(error = e, "approver startup failed; retrying");
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    }
                }
            }
        }
        Cmd::Gate { config } => {
            let cfg = toml::from_str(&std::fs::read_to_string(&config).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
            relay_test_approver::gate::run(cfg).await
        }
        Cmd::GenFixtures {
            out,
            root,
            relay_url,
            pairing_cidrs,
        } => {
            let now = std::time::UNIX_EPOCH
                .elapsed()
                .map_err(|e| e.to_string())?
                .as_secs();
            relay_test_approver::fixtures::generate(&out, &root, &relay_url, &pairing_cidrs, now)?;
            eprintln!("fixtures written to {}", out.display());
            Ok(())
        }
    }
}
