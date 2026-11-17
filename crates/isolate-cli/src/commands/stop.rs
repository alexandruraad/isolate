use crate::DaemonClient;
use clap::Args;

#[derive(Args)]
pub struct StopArgs { pub id: String }

pub async fn execute(args: StopArgs, client: &DaemonClient) -> anyhow::Result<()> {
    let resp = client.delete(&format!("/api/v1/isoboxes/{}", args.id)).await?;
    println!("{}", serde_json::to_string_pretty(&resp)?);
    Ok(())
}
