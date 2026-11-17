use crate::DaemonClient;
use clap::{Args, Subcommand};

#[derive(Args)]
pub struct FeedArgs {
    #[command(subcommand)]
    pub subcommand: FeedSubcommand,
}

#[derive(Subcommand)]
pub enum FeedSubcommand {
    List,
    Update { name: Option<String> },
    Status,
}

pub async fn execute(args: FeedArgs, client: &DaemonClient) -> anyhow::Result<()> {
    match args.subcommand {
        FeedSubcommand::List => {
            let resp = client.get("/api/v1/feeds").await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        FeedSubcommand::Update { name } => {
            let path = name.as_deref()
                .map(|n| format!("/api/v1/feeds/{}/update", n))
                .unwrap_or_else(|| "/api/v1/feeds/update".into());
            let resp = client.post(&path, serde_json::json!({})).await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        FeedSubcommand::Status => {
            let resp = client.get("/api/v1/feeds/status").await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
    }
    Ok(())
}
