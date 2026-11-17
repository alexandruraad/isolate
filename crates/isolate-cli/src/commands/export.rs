use crate::DaemonClient;
use clap::Args;

#[derive(Args)]
pub struct ExportArgs {
    pub id: String,
    #[arg(long, default_value = "json")]
    pub format: String,
    #[arg(short = 'o', long)]
    pub output: Option<std::path::PathBuf>,
}

pub async fn execute(args: ExportArgs, client: &DaemonClient) -> anyhow::Result<()> {
    let resp = client.get(&format!("/api/v1/isoboxes/{}/export?format={}", args.id, args.format)).await?;
    println!("{}", serde_json::to_string_pretty(&resp)?);
    Ok(())
}
