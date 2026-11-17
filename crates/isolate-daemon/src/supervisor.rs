// SPDX-License-Identifier: Apache-2.0
//! Isobox lifecycle supervisor.
//!
//! The supervisor owns all `ActiveIsobox` records that `isolatd` is currently
//! managing. It:
//!   - Starts the SandboxEngine task loops
//!   - Monitors isobox exit status and fires `IsolateEvent::Process` exit events
//!   - Sends periodic heartbeats to `isolate-paladin` (via Unix socket)
//!   - Handles ordered shutdown (freeze → snapshot → destroy)

use anyhow::Result;
use isolate_core::{IsoboxId, IsoboxConfig};
use isolate_events::bus::EventBus;
use isolate_sandbox::engine::SandboxEngine;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use tokio::time::{Duration, interval};
use tracing::{info, warn, error};

/// Commands the supervisor understands.
#[derive(Debug)]
pub enum SupervisorCmd {
    /// Start a new isobox
    Start { id: IsoboxId, config: Box<IsoboxConfig> },
    /// Freeze (pause) an isobox
    Freeze { id: IsoboxId },
    /// Thaw (resume) a frozen isobox
    Thaw { id: IsoboxId },
    /// Take a forensic snapshot
    Snapshot { id: IsoboxId, path: std::path::PathBuf },
    /// Gracefully stop an isobox
    Stop { id: IsoboxId },
    /// Kill an isobox immediately (no cleanup)
    Kill { id: IsoboxId },
    /// Shut down the supervisor
    Shutdown,
}

/// Per-isobox runtime state.
#[derive(Debug)]
struct ManagedIsobox {
    id: IsoboxId,
    #[allow(dead_code)]
    config: IsoboxConfig,
    started_at: std::time::Instant,
    frozen: bool,
}

/// The supervisor actor — spawned as a background task in `isolatd`.
pub struct Supervisor {
    engine: SandboxEngine,
    isoboxes: Arc<Mutex<HashMap<IsoboxId, ManagedIsobox>>>,
    cmd_tx: mpsc::UnboundedSender<SupervisorCmd>,
    cmd_rx: mpsc::UnboundedReceiver<SupervisorCmd>,
    paladin_socket: Option<String>,
}

impl Supervisor {
    pub fn new(engine: SandboxEngine, paladin_socket: Option<String>) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        Self {
            engine,
            isoboxes: Arc::new(Mutex::new(HashMap::new())),
            cmd_tx,
            cmd_rx,
            paladin_socket,
        }
    }

    /// Clone the sender half so other tasks can issue commands.
    pub fn handle(&self) -> SupervisorHandle {
        SupervisorHandle { tx: self.cmd_tx.clone() }
    }

    /// Run the supervisor event loop.
    pub async fn run(mut self) {
        let mut heartbeat = interval(Duration::from_secs(5));
        let paladin_socket = self.paladin_socket.clone();

        loop {
            tokio::select! {
                // Process incoming commands
                Some(cmd) = self.cmd_rx.recv() => {
                    match cmd {
                        SupervisorCmd::Start { id, config } => {
                            self.start_isobox(id, *config).await;
                        }
                        SupervisorCmd::Freeze { id } => {
                            self.freeze_isobox(&id).await;
                        }
                        SupervisorCmd::Thaw { id } => {
                            self.thaw_isobox(&id).await;
                        }
                        SupervisorCmd::Snapshot { id, path } => {
                            self.snapshot_isobox(&id, &path).await;
                        }
                        SupervisorCmd::Stop { id } => {
                            self.stop_isobox(&id).await;
                        }
                        SupervisorCmd::Kill { id } => {
                            self.kill_isobox(&id).await;
                        }
                        SupervisorCmd::Shutdown => {
                            info!("supervisor: graceful shutdown initiated");
                            self.shutdown_all().await;
                            return;
                        }
                    }
                }

                // Send heartbeats to paladin
                _ = heartbeat.tick() => {
                    if let Some(ref socket) = paladin_socket {
                        self.send_heartbeat(socket).await;
                    }
                }
            }
        }
    }

    async fn start_isobox(&self, id: IsoboxId, config: IsoboxConfig) {
        info!(id = %id, "supervisor: starting isobox");
        match self.engine.create(config.clone()).await {
            Ok(_) => {
                let mut lock = self.isoboxes.lock().await;
                lock.insert(id.clone(), ManagedIsobox {
                    id,
                    config,
                    started_at: std::time::Instant::now(),
                    frozen: false,
                });
            }
            Err(e) => {
                error!(id = %id, err = %e, "supervisor: failed to start isobox");
            }
        }
    }

    async fn freeze_isobox(&self, id: &IsoboxId) {
        info!(id = %id, "supervisor: freezing isobox");
        if let Err(e) = self.engine.freeze(id).await {
            warn!(id = %id, err = %e, "supervisor: freeze failed");
        } else {
            let mut lock = self.isoboxes.lock().await;
            if let Some(m) = lock.get_mut(id) {
                m.frozen = true;
            }
        }
    }

    async fn thaw_isobox(&self, id: &IsoboxId) {
        info!(id = %id, "supervisor: thawing isobox");
        if let Err(e) = self.engine.thaw(id).await {
            warn!(id = %id, err = %e, "supervisor: thaw failed");
        } else {
            let mut lock = self.isoboxes.lock().await;
            if let Some(m) = lock.get_mut(id) {
                m.frozen = false;
            }
        }
    }

    async fn snapshot_isobox(&self, id: &IsoboxId, path: &std::path::Path) {
        info!(id = %id, path = %path.display(), "supervisor: snapshotting isobox");
        if let Err(e) = self.engine.snapshot(id, path).await {
            warn!(id = %id, err = %e, "supervisor: snapshot failed");
        }
    }

    async fn stop_isobox(&self, id: &IsoboxId) {
        info!(id = %id, "supervisor: stopping isobox");
        if let Err(e) = self.engine.stop(id).await {
            warn!(id = %id, err = %e, "supervisor: stop failed");
        }
        self.isoboxes.lock().await.remove(id);
    }

    async fn kill_isobox(&self, id: &IsoboxId) {
        info!(id = %id, "supervisor: KILLING isobox immediately");
        if let Err(e) = self.engine.kill_immediate(id).await {
            error!(id = %id, err = %e, "supervisor: kill failed");
        }
        self.isoboxes.lock().await.remove(id);
    }

    async fn shutdown_all(&self) {
        let ids: Vec<IsoboxId> = {
            let lock = self.isoboxes.lock().await;
            lock.keys().cloned().collect()
        };
        for id in ids {
            self.stop_isobox(&id).await;
        }
    }

    async fn send_heartbeat(&self, socket_path: &str) {
        use tokio::net::UnixStream;
        use tokio::io::AsyncWriteExt;

        let active = self.isoboxes.lock().await.len();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let msg = format!(
            "{{\"daemon_version\":\"{}\",\"active_isoboxes\":{},\"timestamp\":{}}}",
            env!("CARGO_PKG_VERSION"),
            active,
            ts,
        );

        match UnixStream::connect(socket_path).await {
            Ok(mut stream) => {
                let _ = stream.write_all(format!("{}\n", msg).as_bytes()).await;
            }
            Err(_) => {
                // Paladin may not be running; silently skip
            }
        }
    }

    /// Return count of active isoboxes (for REST /health endpoint).
    pub async fn active_count(&self) -> usize {
        self.isoboxes.lock().await.len()
    }
}

/// Cloneable handle to send commands to the supervisor.
#[derive(Clone)]
pub struct SupervisorHandle {
    tx: mpsc::UnboundedSender<SupervisorCmd>,
}

impl SupervisorHandle {
    pub fn start(&self, id: IsoboxId, config: IsoboxConfig) -> Result<()> {
        self.tx.send(SupervisorCmd::Start { id, config: Box::new(config) })?;
        Ok(())
    }
    pub fn freeze(&self, id: IsoboxId) -> Result<()> {
        self.tx.send(SupervisorCmd::Freeze { id })?;
        Ok(())
    }
    pub fn thaw(&self, id: IsoboxId) -> Result<()> {
        self.tx.send(SupervisorCmd::Thaw { id })?;
        Ok(())
    }
    pub fn snapshot(&self, id: IsoboxId, path: std::path::PathBuf) -> Result<()> {
        self.tx.send(SupervisorCmd::Snapshot { id, path })?;
        Ok(())
    }
    pub fn stop(&self, id: IsoboxId) -> Result<()> {
        self.tx.send(SupervisorCmd::Stop { id })?;
        Ok(())
    }
    pub fn kill(&self, id: IsoboxId) -> Result<()> {
        self.tx.send(SupervisorCmd::Kill { id })?;
        Ok(())
    }
    pub fn shutdown(&self) -> Result<()> {
        self.tx.send(SupervisorCmd::Shutdown)?;
        Ok(())
    }
}
