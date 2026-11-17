//! isolatd — The isolate daemon.
//!
//! Runs as a privileged service and:
//!   - Manages isobox lifecycle (create, freeze, stop, kill)
//!   - Exposes gRPC :7777, REST :7778, WebSocket :7779
//!   - Routes events through the intelligence + policy engines
//!   - Sends heartbeats to isolate-paladin
//!   - Persists all events to SQLite

mod demo;
mod grpc;
mod rest;
mod spawner;
mod supervisor;
mod ws;

use anyhow::Result;
use isolate_config::schema::DaemonConfig;
use isolate_events::bus::EventBus;
use isolate_sandbox::engine::SandboxEngine;
use isolate_store::Store;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("isolatd=info".parse()?)
                .add_directive("isolate_sandbox=info".parse()?)
                .add_directive("isolate_intel=info".parse()?)
        )
        .json()
        .init();

    info!("isolatd starting");

    // Load daemon configuration
    let config = load_daemon_config()?;

    // Initialize event bus
    let (bus, bus_worker) = EventBus::new();

    // Start bus dispatch loop
    tokio::task::spawn_blocking(move || bus_worker.run());

    // Initialize store
    let data_dir = &config.daemon.data_dir;
    tokio::fs::create_dir_all(data_dir).await?;
    let store = Store::open(&data_dir.join("isolate.db")).await?;

    // Initialize sandbox engine
    let engine = SandboxEngine::new(bus.clone());

    // Initialize intelligence engine
    let (intel_tx, mut intel_rx) = tokio::sync::mpsc::unbounded_channel();
    let intel_engine = isolate_intel::IntelEngine::new(intel_tx);

    // Initialize policy enforcer
    let (enforcer_tx, mut enforcer_rx) = tokio::sync::mpsc::unbounded_channel();
    let enforcer = isolate_policy::PolicyEnforcer::new(enforcer_tx);

    // Store events from bus
    let store_clone = store.clone();
    let mut store_rx = bus.subscribe_events();
    tokio::spawn(async move {
        loop {
            match store_rx.recv().await {
                Ok(event) => {
                    if let Err(e) = store_clone.insert_event(&event).await {
                        tracing::warn!("store event failed: {e}");
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!("store receiver lagged {n} events");
                }
                Err(_) => break,
            }
        }
    });

    // Initialize demo store (populated on demand via POST /api/v1/demo/seed)
    let demo = demo::new_store();

    // Initialize spawn registry (tracks running isobox processes for stop/kill)
    let spawn_reg = spawner::new_registry();

    // Start REST API
    let rest_addr: std::net::SocketAddr = config.daemon.rest_addr.parse()?;
    let engine_rest   = engine.clone();
    let store_rest    = store.clone();
    let bus_rest      = bus.clone();
    let demo_rest     = demo.clone();
    let spawn_reg_rest = spawn_reg.clone();
    tokio::spawn(async move {
        rest::serve(rest_addr, engine_rest, store_rest, bus_rest, demo_rest, spawn_reg_rest).await;
    });

    // Start WebSocket event stream
    let ws_addr: std::net::SocketAddr = config.daemon.ws_addr.parse()?;
    let bus_ws = bus.clone();
    tokio::spawn(async move {
        ws::serve(ws_addr, bus_ws).await;
    });

    // Start gRPC server (placeholder — full impl with tonic in Phase 1)
    let grpc_addr: std::net::SocketAddr = config.daemon.grpc_addr.parse()?;
    info!(addr = %grpc_addr, "gRPC server starting (skeleton)");

    info!("isolatd running — all systems nominal");

    // Keep alive
    tokio::signal::ctrl_c().await?;
    info!("isolatd shutting down");
    Ok(())
}

fn load_daemon_config() -> Result<DaemonConfig> {
    // Try /etc/isolate/daemon.toml, then ./daemon.toml
    let paths = ["/etc/isolate/daemon.toml", "daemon.toml"];

    for path in &paths {
        if std::path::Path::new(path).exists() {
            let content = std::fs::read_to_string(path)?;
            return Ok(toml::from_str(&content)?);
        }
    }

    // Use defaults
    Ok(DaemonConfig {
        daemon: isolate_config::schema::DaemonSection {
            grpc_addr: "127.0.0.1:7777".into(),
            rest_addr: "127.0.0.1:7778".into(),
            ws_addr: "127.0.0.1:7779".into(),
            data_dir: "/var/lib/isolate".into(),
            tls_cert: None,
            tls_key: None,
            paladin_socket: None,
        },
    })
}
