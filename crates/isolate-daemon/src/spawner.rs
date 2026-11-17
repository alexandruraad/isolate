//! Process spawner — launches the subprocess for a Process-target isobox.
//!
//! The engine (`isolate-sandbox`) sets up the isolation context (Seatbelt, eBPF, etc.)
//! but does NOT exec the workload. This module does the actual fork+exec and emits
//! lifecycle events (Exec on start, Raw lines from stdio, Process::Exit on completion).
//!
//! Stop/kill is handled by aborting the spawner task, which drops the `Child` handle
//! and triggers `kill_on_drop`.

use anyhow::{bail, Result};
use chrono::Utc;
use isolate_core::{
    types::{IsoboxConfig, IsoboxTarget},
    IsoboxId,
};
use isolate_events::{
    bus::EventBus,
    event::{EventBody, ExecEvent, IsolateEvent, ProcessEvent, ProcessEventType},
};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};
use tokio::{io::AsyncBufReadExt, task::AbortHandle};
use tracing::{info, warn};

// ── Registry ──────────────────────────────────────────────────────────────────

/// Maps IsoboxId → the abort handle of its spawner task.
/// Aborting the task drops the `Child`, which kills the process (kill_on_drop).
pub type SpawnRegistry = Arc<Mutex<HashMap<IsoboxId, AbortHandle>>>;

pub fn new_registry() -> SpawnRegistry {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Kill an isobox process by aborting its spawner task.
pub fn abort(id: &IsoboxId, registry: &SpawnRegistry) {
    if let Some(handle) = registry.lock().unwrap().remove(id) {
        handle.abort();
        info!(isobox_id = %id, "spawner task aborted — process killed");
    }
}

// ── Spawn ─────────────────────────────────────────────────────────────────────

/// Fork+exec the workload for a Process-target isobox.
///
/// Emits an `Exec` event immediately, relays stdout/stderr as `Raw` events,
/// and emits `Process::Exit` when the child exits.
///
/// Returns the OS PID of the spawned process (0 on error/non-process targets).
pub async fn spawn_process(
    id: IsoboxId,
    config: &IsoboxConfig,
    bus: EventBus,
    registry: SpawnRegistry,
) -> Result<u32> {
    let IsoboxTarget::Process {
        command,
        environment,
        working_dir,
        ..
    } = &config.target
    else {
        bail!("spawn_process: not a Process target");
    };

    if command.is_empty() {
        bail!("spawn_process: command is empty");
    }

    let mut cmd = tokio::process::Command::new(&command[0]);
    cmd.args(&command[1..])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);

    for (k, v) in environment {
        cmd.env(k, v);
    }
    if let Some(dir) = working_dir {
        cmd.current_dir(dir);
    }

    let mut child = cmd.spawn()?;
    let pid = child.id().unwrap_or(0);
    let ppid = std::process::id();

    info!(isobox_id = %id, pid, cmd = %command[0], "isobox process spawned");

    // Emit ExecEvent before the task takes ownership of everything
    bus.publish(IsolateEvent {
        seq: 1,
        timestamp: Utc::now(),
        isobox_id: id.clone(),
        backend: "spawner".into(),
        body: EventBody::Exec(ExecEvent {
            pid,
            ppid,
            uid: 0,
            gid: 0,
            path: std::path::PathBuf::from(&command[0]),
            argv: command.clone(),
            env: environment.iter().map(|(k, v)| format!("{k}={v}")).collect(),
            sha256: None,
            ioc_match: None,
            blocked: false,
        }),
    });

    // Shared monotonic sequence counter (starts at 2 — ExecEvent was seq 1)
    let seq_ctr = Arc::new(AtomicU64::new(2));

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    let id_task = id.clone();
    let bus_task = bus.clone();

    let jh = tokio::spawn(async move {
        // ── Relay stdout ──────────────────────────────────────────────────────
        if let Some(out) = stdout {
            let id2 = id_task.clone();
            let bus2 = bus_task.clone();
            let sc2 = seq_ctr.clone();
            tokio::spawn(async move {
                let mut lines = tokio::io::BufReader::new(out).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let seq = sc2.fetch_add(1, Ordering::Relaxed);
                    bus2.publish(IsolateEvent {
                        seq,
                        timestamp: Utc::now(),
                        isobox_id: id2.clone(),
                        backend: "spawner".into(),
                        body: EventBody::Raw {
                            source: "stdout".into(),
                            data: serde_json::json!({ "line": line }),
                        },
                    });
                }
            });
        }

        // ── Relay stderr ──────────────────────────────────────────────────────
        if let Some(err) = stderr {
            let id3 = id_task.clone();
            let bus3 = bus_task.clone();
            let sc3 = seq_ctr.clone();
            tokio::spawn(async move {
                let mut lines = tokio::io::BufReader::new(err).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let seq = sc3.fetch_add(1, Ordering::Relaxed);
                    bus3.publish(IsolateEvent {
                        seq,
                        timestamp: Utc::now(),
                        isobox_id: id3.clone(),
                        backend: "spawner".into(),
                        body: EventBody::Raw {
                            source: "stderr".into(),
                            data: serde_json::json!({ "line": line }),
                        },
                    });
                }
            });
        }

        // ── Wait for exit ─────────────────────────────────────────────────────
        match child.wait().await {
            Ok(status) => {
                let code = status.code().unwrap_or(-1);
                info!(isobox_id = %id_task, pid, exit_code = code, "isobox process exited");
                let seq = seq_ctr.fetch_add(1, Ordering::Relaxed);
                bus_task.publish(IsolateEvent {
                    seq,
                    timestamp: Utc::now(),
                    isobox_id: id_task.clone(),
                    backend: "spawner".into(),
                    body: EventBody::Process(ProcessEvent {
                        pid,
                        ppid,
                        uid: 0,
                        gid: 0,
                        comm: "isobox".into(),
                        event_type: ProcessEventType::Exit,
                    }),
                });
            }
            Err(e) => warn!(isobox_id = %id_task, pid, "wait error: {e}"),
        }
    });

    registry.lock().unwrap().insert(id, jh.abort_handle());
    Ok(pid)
}
