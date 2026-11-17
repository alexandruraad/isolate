use crate::DaemonClient;
use clap::Args;

#[derive(Args)]
pub struct InspectArgs {
    pub id: String,
    #[arg(long)]
    pub format: Option<String>,
}

pub async fn execute(args: InspectArgs, client: &DaemonClient) -> anyhow::Result<()> {
    let resp = client.get(&format!("/api/v1/isoboxes/{}", args.id)).await?;
    println!("{}", serde_json::to_string_pretty(&resp)?);
    Ok(())
}
