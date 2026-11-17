//! isobox — the isolate command-line interface.
//!
//! Primary control surface for all isobox operations.
//! Communicates with isolatd via REST/gRPC.

mod commands;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "isobox",
    about = "isolate — multi-layer sandboxing with always-watching intelligence",
    version,
    propagate_version = true,
)]
struct Cli {
    /// isolatd address (default: 127.0.0.1:7778)
    #[arg(long, env = "ISOLATE_DAEMON", default_value = "127.0.0.1:7778", global = true)]
    daemon: String,

    /// Output format
    #[arg(long, value_enum, default_value = "text", global = true)]
    format: OutputFormat,

    /// Verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Wrap a workload in an isobox and start it
    Run(commands::run::RunArgs),
    /// List active isoboxes
    Ps(commands::ps::PsArgs),
    /// Show detailed state of an isobox
    Inspect(commands::inspect::InspectArgs),
    /// Attach TUI dashboard to an isobox
    Attach(commands::attach::AttachArgs),
    /// Gracefully stop an isobox
    Stop(commands::stop::StopArgs),
    /// Freeze all activity in an isobox
    Freeze(commands::freeze::FreezeArgs),
    /// Resume a frozen isobox
    Thaw(commands::freeze::ThawArgs),
    /// Take a forensic snapshot
    Snapshot(commands::snapshot::SnapshotArgs),
    /// Export forensic data
    Export(commands::export::ExportArgs),
    /// Show, edit, or apply isobox policy
    Policy(commands::policy::PolicyArgs),
    /// View or follow alerts
    Alert(commands::alert::AlertArgs),
    /// Manage threat intelligence feeds
    Feed(commands::feed::FeedArgs),
}

#[derive(Clone, clap::ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Yaml,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::from_default_env()
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(cli.verbose)
        .init();

    let client = DaemonClient::new(&cli.daemon);

    match cli.command {
        Command::Run(args)      => commands::run::execute(args, &client).await?,
        Command::Ps(args)       => commands::ps::execute(args, &client).await?,
        Command::Inspect(args)  => commands::inspect::execute(args, &client).await?,
        Command::Attach(args)   => commands::attach::execute(args, &client).await?,
        Command::Stop(args)     => commands::stop::execute(args, &client).await?,
        Command::Freeze(args)   => commands::freeze::execute_freeze(args, &client).await?,
        Command::Thaw(args)     => commands::freeze::execute_thaw(args, &client).await?,
        Command::Snapshot(args) => commands::snapshot::execute(args, &client).await?,
        Command::Export(args)   => commands::export::execute(args, &client).await?,
        Command::Policy(args)   => commands::policy::execute(args, &client).await?,
        Command::Alert(args)    => commands::alert::execute(args, &client).await?,
        Command::Feed(args)     => commands::feed::execute(args, &client).await?,
    }

    Ok(())
}

/// HTTP client for the isolatd REST API.
pub struct DaemonClient {
    base_url: String,
    http: reqwest::Client,
}

impl DaemonClient {
    pub fn new(addr: &str) -> Self {
        Self {
            base_url: format!("http://{addr}"),
            http: reqwest::Client::new(),
        }
    }

    pub async fn get(&self, path: &str) -> anyhow::Result<serde_json::Value> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self.http.get(&url).send().await?.json().await?;
        Ok(resp)
    }

    pub async fn post(&self, path: &str, body: serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self.http.post(&url).json(&body).send().await?.json().await?;
        Ok(resp)
    }

    pub async fn delete(&self, path: &str) -> anyhow::Result<serde_json::Value> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self.http.delete(&url).send().await?.json().await?;
        Ok(resp)
    }
}
