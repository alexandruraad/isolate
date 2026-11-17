use crate::DaemonClient;
use clap::Args;

#[derive(Args)]
pub struct AlertArgs {
    /// Filter to specific isobox
    #[arg(short = 'i', long)]
    pub isobox: Option<String>,

    /// Follow alert stream (like tail -f)
    #[arg(short = 'f', long)]
    pub follow: bool,

    /// Minimum severity
    #[arg(long, default_value = "info")]
    pub severity: String,
}

pub async fn execute(args: AlertArgs, client: &DaemonClient) -> anyhow::Result<()> {
    let path = if let Some(id) = &args.isobox {
        format!("/api/v1/isoboxes/{}/alerts", id)
    } else {
        "/api/v1/alerts".into()
    };

    loop {
        match client.get(&path).await {
            Ok(resp) => {
                if let Some(alerts) = resp.get("alerts").and_then(|v| v.as_array()) {
                    for alert in alerts {
                        let ts = alert.get("timestamp").and_then(|v| v.as_str()).unwrap_or("-");
                        let sev = alert.get("severity").and_then(|v| v.as_str()).unwrap_or("info");
                        let title = alert.get("title").and_then(|v| v.as_str()).unwrap_or("-");
                        let isobox = alert.get("isobox_id").and_then(|v| v.as_str()).unwrap_or("-");

                        let sev_tag = match sev {
                            "critical" | "emergency" => format!("\x1b[31m[{:^8}]\x1b[0m", sev.to_uppercase()),
                            "warn" => format!("\x1b[33m[{:^8}]\x1b[0m", "WARN"),
                            _ => format!("[{:^8}]", "INFO"),
                        };

                        println!("{sev_tag} {ts}  {isobox:.20}  {title}");
                    }
                }
            }
            Err(e) => eprintln!("error: {e}"),
        }

        if !args.follow {
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    }

    Ok(())
}
