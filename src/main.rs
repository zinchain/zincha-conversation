use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;
use zincha_conversation::{storage::Database, Config, ConversationService};

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
            println!(
                "configuration valid for service {}",
                config.service.service_id
            );
        }
    }
    Ok(())
}
