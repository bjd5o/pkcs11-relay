//! `relay-server`: the relay binary.
#![forbid(unsafe_code)]

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use relay_server::config::Config;

#[derive(Parser)]
#[command(version, about = "pkcs11-relay relay service")]
struct Cli {
    /// TOML config file; `RELAY_*` environment variables override it.
    #[arg(long, short, env = "RELAY_CONFIG")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the relay (the default).
    Serve,
    /// Inspect and revoke registrations, export the audit log.
    Admin {
        #[command(subcommand)]
        command: Admin,
    },
    /// Exit 0 if the relay answers /healthz (for container health checks).
    Healthcheck {
        #[arg(long, default_value = "http://127.0.0.1:8080/healthz")]
        url: String,
    },
}

#[derive(Subcommand)]
enum Admin {
    Clients {
        #[command(subcommand)]
        command: ListRevoke,
    },
    Devices {
        #[command(subcommand)]
        command: ListRevoke,
    },
    Audit {
        #[command(subcommand)]
        command: AuditCmd,
    },
}

#[derive(Subcommand)]
enum ListRevoke {
    List,
    Revoke { id: String },
}

#[derive(Subcommand)]
enum AuditCmd {
    /// Write audit events as JSON lines.
    Export {
        /// Only events at or after this Unix time.
        #[arg(long, default_value_t = 0)]
        since: i64,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli).await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), String> {
    if let Some(Cmd::Healthcheck { url }) = &cli.command {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let r = reqwest::get(url).await.map_err(|e| e.to_string())?;
        return if r.status().is_success() {
            Ok(())
        } else {
            Err(format!("status {}", r.status()))
        };
    }
    let cfg = Config::load(cli.config.as_deref())?;
    match cli.command.unwrap_or(Cmd::Serve) {
        Cmd::Serve => {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "info".into()),
                )
                .init();
            let listener = tokio::net::TcpListener::bind(&cfg.listen)
                .await
                .map_err(|e| format!("bind {}: {e}", cfg.listen))?;
            tracing::info!(listen = cfg.listen, data_dir = %cfg.data_dir.display(), "relay starting");
            let st = relay_server::build_state(cfg).await?;
            relay_server::serve_on(listener, st).await
        }
        Cmd::Admin { command } => {
            let db = relay_server::db::open(&cfg.data_dir).await?;
            use relay_server::admin as a;
            match command {
                Admin::Clients {
                    command: ListRevoke::List,
                } => a::list_clients(&db).await,
                Admin::Clients {
                    command: ListRevoke::Revoke { id },
                } => a::revoke_client(&db, &id).await,
                Admin::Devices {
                    command: ListRevoke::List,
                } => a::list_devices(&db).await,
                Admin::Devices {
                    command: ListRevoke::Revoke { id },
                } => a::revoke_device(&db, &id).await,
                Admin::Audit {
                    command: AuditCmd::Export { since },
                } => a::export_audit(&db, since).await,
            }
        }
        Cmd::Healthcheck { .. } => unreachable!(),
    }
}
