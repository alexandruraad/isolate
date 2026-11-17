use crate::DaemonClient;
use clap::Args;

#[derive(Args)]
pub struct AttachArgs {
    pub id: String,
}

pub async fn execute(args: AttachArgs, client: &DaemonClient) -> anyhow::Result<()> {
    println!("Attaching TUI to isobox {}...", args.id);
    println!("(TUI dashboard available in Phase 4 — run `isolate-tui` directly)");
    Ok(())
}
