use crate::DaemonClient;
use clap::{Args, Subcommand};

#[derive(Args)]
pub struct PolicyArgs {
    #[command(subcommand)]
    pub subcommand: PolicySubcommand,
}

#[derive(Subcommand)]
pub enum PolicySubcommand {
    Show { id: String },
    Suggest { id: String },
    Apply { id: String, #[arg(short = 'f', long)] file: std::path::PathBuf },
    History { id: String },
}

pub async fn execute(args: PolicyArgs, client: &DaemonClient) -> anyhow::Result<()> {
    match args.subcommand {
        PolicySubcommand::Show { id } => {
            let resp = client.get(&format!("/api/v1/isoboxes/{}/policy", id)).await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        PolicySubcommand::Suggest { id } => {
            let resp = client.get(&format!("/api/v1/isoboxes/{}/policy/suggest", id)).await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        PolicySubcommand::Apply { id, file } => {
            let content = std::fs::read_to_string(&file)?;
            let policy: serde_json::Value = toml::from_str(&content)?;
            let resp = client.post(&format!("/api/v1/isoboxes/{}/policy", id), policy).await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        PolicySubcommand::History { id } => {
            let resp = client.get(&format!("/api/v1/isoboxes/{}/policy/history", id)).await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
    }
    Ok(())
}
