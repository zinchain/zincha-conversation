use std::{io::Write, path::PathBuf};

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;
use zincha_conversation::{chain, storage::Database, transport, Config, ConversationService};

#[derive(Parser)]
#[command(name = "zincha-conversation", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
    Migrate {
        #[arg(long)]
        config: PathBuf,
    },
    Check {
        #[arg(long)]
        config: PathBuf,
    },
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    Certificate {
        #[command(subcommand)]
        command: CertificateCommand,
    },
    ChainReadKey {
        #[command(subcommand)]
        command: ChainReadKeyCommand,
    },
}

#[derive(Subcommand)]
enum ProfileCommand {
    Export {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum CertificateCommand {
    Generate {
        #[arg(long)]
        host: String,
        #[arg(long)]
        certificate: PathBuf,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long, default_value_t = 365)]
        valid_days: u32,
    },
    /// Generate the next independent identity used during a two-pin rotation.
    Rotate {
        #[arg(long)]
        host: String,
        #[arg(long)]
        next_certificate: PathBuf,
        #[arg(long)]
        next_private_key: PathBuf,
        #[arg(long, default_value_t = 365)]
        valid_days: u32,
    },
}

#[derive(Subcommand)]
enum ChainReadKeyCommand {
    /// Create a dedicated Ed25519 key for delegated chain reads.
    Generate {
        #[arg(long)]
        secret_key: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    match Cli::parse().command {
        Command::Serve { config } => {
            ConversationService::from_config(Config::load(&config)?)
                .await?
                .serve()
                .await?
        }
        Command::Migrate { config } => {
            let config = Config::load(&config)?;
            Database::connect(&config.database.url, config.database.max_connections)
                .await?
                .migrate()
                .await?;
        }
        Command::Check { config } => {
            let config = Config::load(&config)?;
            let profile = transport::build_profile(&config)?;
            println!(
                "configuration valid for service {} with {} interface(s)",
                config.service.service_id,
                profile.interfaces.len(),
            );
        }
        Command::Profile { command } => match command {
            ProfileCommand::Export { config, output } => {
                let bytes = transport::canonical_profile_json(&Config::load(&config)?)?;
                if let Some(path) = output {
                    std::fs::write(path, bytes)?;
                } else {
                    std::io::stdout().lock().write_all(&bytes)?;
                }
            }
        },
        Command::Certificate { command } => match command {
            CertificateCommand::Generate {
                host,
                certificate,
                private_key,
                valid_days,
            } => {
                let pin =
                    transport::generate_identity(&host, &certificate, &private_key, valid_days)?;
                println!("{}", serde_json::to_string(&pin)?);
            }
            CertificateCommand::Rotate {
                host,
                next_certificate,
                next_private_key,
                valid_days,
            } => {
                let pin = transport::generate_identity(
                    &host,
                    &next_certificate,
                    &next_private_key,
                    valid_days,
                )?;
                println!("{}", serde_json::to_string(&pin)?);
            }
        },
        Command::ChainReadKey { command } => match command {
            ChainReadKeyCommand::Generate { secret_key } => {
                let info = chain::generate_chain_read_key(&secret_key)?;
                println!("{}", serde_json::to_string(&info)?);
            }
        },
    }
    Ok(())
}
