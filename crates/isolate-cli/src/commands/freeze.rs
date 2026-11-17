use crate::DaemonClient;
use clap::Args;

#[derive(Args)]
pub struct FreezeArgs { pub id: String }

#[derive(Args)]
pub struct ThawArgs { pub id: String }

pub async fn execute_freeze(args: FreezeArgs, client: &DaemonClient) -> anyhow::Result<()> {
    let resp = client.post(&format!("/api/v1/isoboxes/{}/freeze", args.id), serde_json::json!({})).await?;
    println!("{}", serde_json::to_string_pretty(&resp)?);
    Ok(())
}

pub async fn execute_thaw(args: ThawArgs, client: &DaemonClient) -> anyhow::Result<()> {
    let resp = client.post(&format!("/api/v1/isoboxes/{}/thaw", args.id), serde_json::json!({})).await?;
    println!("{}", serde_json::to_string_pretty(&resp)?);
    Ok(())
}
