use crate::DaemonClient;
use clap::Args;

#[derive(Args)]
pub struct RunArgs {
    /// Policy preset name
    #[arg(short = 'p', long)]
    pub policy: Option<String>,

    /// Policy file path
    #[arg(short = 'f', long = "policy-file")]
    pub policy_file: Option<std::path::PathBuf>,

    /// Name for this isobox
    #[arg(long)]
    pub name: Option<String>,

    /// Workload class for baseline grouping
    #[arg(long)]
    pub class: Option<String>,

    /// Default enforcement action
    #[arg(long, default_value = "audit")]
    pub action: String,

    /// Apply hardening suggestions automatically
    #[arg(long)]
    pub auto_harden: bool,

    /// Disable intelligence engine
    #[arg(long)]
    pub no_intel: bool,

    /// Block all network connections
    #[arg(long)]
    pub no_network: bool,

    /// Mount root filesystem read-only
    #[arg(long)]
    pub read_only_root: bool,

    /// Kill isobox after N seconds
    #[arg(long)]
    pub timeout: Option<u64>,

    /// Run in background, print isobox ID
    #[arg(short = 'd', long)]
    pub detach: bool,

    /// Command and arguments to run
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

pub async fn execute(args: RunArgs, client: &DaemonClient) -> anyhow::Result<()> {
    let body = serde_json::json!({
        "command": args.command,
        "policy": args.policy,
        "policy_file": args.policy_file,
        "name": args.name,
        "class": args.class,
        "action": args.action,
        "auto_harden": args.auto_harden,
        "no_intel": args.no_intel,
        "no_network": args.no_network,
        "read_only_root": args.read_only_root,
        "timeout": args.timeout,
    });

    match client.post("/api/v1/isoboxes", body).await {
        Ok(resp) => {
            if args.detach {
                if let Some(id) = resp.get("id").and_then(|v| v.as_str()) {
                    println!("{id}");
                }
            } else {
                println!("{}", serde_json::to_string_pretty(&resp)?);
            }
        }
        Err(e) => {
            eprintln!("error: could not connect to isolatd: {e}");
            eprintln!("hint: start isolatd with: sudo isolatd");
            std::process::exit(1);
        }
    }

    Ok(())
}
