use crate::DaemonClient;
use clap::Args;

#[derive(Args)]
pub struct PsArgs {
    /// Output format
    #[arg(long, default_value = "table")]
    pub format: String,

    /// Refresh every second
    #[arg(long, short = 'w')]
    pub watch: bool,
}

pub async fn execute(args: PsArgs, client: &DaemonClient) -> anyhow::Result<()> {
    loop {
        let resp = client.get("/api/v1/isoboxes").await?;

        if args.format == "json" {
            println!("{}", serde_json::to_string_pretty(&resp)?);
        } else {
            // Table format
            println!("{:<36}  {:<20}  {:<10}", "ID", "NAME", "STATE");
            println!("{}", "-".repeat(70));
            if let Some(isoboxes) = resp.get("isoboxes").and_then(|v| v.as_array()) {
                for ib in isoboxes {
                    let id = ib.get("id").and_then(|v| v.as_str()).unwrap_or("-");
                    let name = ib.get("name").and_then(|v| v.as_str()).unwrap_or("-");
                    let state = ib.get("state").and_then(|v| v.as_str()).unwrap_or("-");
                    println!("{:<36}  {:<20}  {:<10}", id, name, state);
                }
            }
        }

        if !args.watch {
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        print!("\x1B[2J\x1B[H"); // clear screen
    }

    Ok(())
}
