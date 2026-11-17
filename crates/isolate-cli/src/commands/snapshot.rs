use crate::DaemonClient;
use clap::Args;

#[derive(Args)]
pub struct SnapshotArgs {
    pub id: String,
    #[arg(short = 'o', long)]
    pub output: Option<std::path::PathBuf>,
    #[arg(long)]
    pub include_memory: bool,
}

pub async fn execute(args: SnapshotArgs, client: &DaemonClient) -> anyhow::Result<()> {
    let body = serde_json::json!({
        "output": args.output,
        "include_memory": args.include_memory,
    });
    let resp = client.post(&format!("/api/v1/isoboxes/{}/snapshot", args.id), body).await?;
    println!("{}", serde_json::to_string_pretty(&resp)?);
    Ok(())
}
