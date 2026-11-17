//! isolate-paladin — The Last Resort Guardian
//!
//! The paladin is a completely independent binary. It does NOT depend on
//! isolatd being alive or functional. When all else fails, the paladin acts.
//!
//! # Oath of the Sentinel
//!
//! The paladin operates under a strict code with 8 escalation levels:
//!
//!   Level 0: WATCHING     — Normal. All systems green. Heartbeat OK.
//!   Level 1: ALERT        — Anomaly detected. Notify operators via OOB channels.
//!   Level 2: CONTAIN      — Sever network at kernel level (nftables/pf, NOT eBPF).
//!   Level 3: FREEZE        — SIGSTOP entire cgroup / process group.
//!   Level 4: TERMINATE    — SIGKILL all processes. Destroy namespaces.
//!   Level 5: SCORCH       — Wipe volatile state. Zero memory pages. Destroy dirs.
//!   Level 6: RAMPART      — System-wide lockdown. All new connections blocked.
//!   Level 7: ABSOLUTION   — Kernel panic. Nothing escapes. No exfil possible.
//!
//! # Architecture
//!
//! The paladin runs as a separate process (not inside isolatd). It communicates
//! with isolatd via a dedicated Unix socket. If the heartbeat times out, the
//! paladin assumes isolatd is compromised and escalates independently.
//!
//! The paladin uses ONLY direct kernel interfaces for enforcement:
//!   - cgroup.kill / cgroup.freeze (not eBPF)
//!   - nftables / iptables (not eBPF network rules)
//!   - Direct kill(2) / tgkill(2) syscalls
//!   - /proc filesystem for process enumeration
//!   - sysrq for kernel panic (level 7 only, with hard confirmation)

mod escalation;
mod out_of_band;
mod sentinel;
mod watchdog;

use anyhow::Result;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("isolate_paladin=info".parse()?)
        )
        .with_target(true)
        .json()
        .init();

    info!("⚔  isolate-paladin starting — Oath of the Sentinel active");

    let config = PaladinDaemonConfig::from_env();

    // Start the watchdog (heartbeat listener from isolatd)
    let watchdog = watchdog::Watchdog::new(config.clone());

    // Start the sentinel (out-of-band monitor using /proc, cgroups, netlink)
    let sentinel = sentinel::Sentinel::new(config.clone());

    // Run both concurrently; either can trigger escalation
    tokio::select! {
        res = watchdog.run() => {
            error!(?res, "watchdog exited");
        }
        res = sentinel.run() => {
            error!(?res, "sentinel exited");
        }
    }

    error!("paladin main loop exited — this should never happen");
    Ok(())
}

/// Configuration for the paladin daemon itself.
#[derive(Debug, Clone)]
pub struct PaladinDaemonConfig {
    /// Unix socket path to receive heartbeats from isolatd
    pub socket_path: std::path::PathBuf,
    /// Heartbeat timeout in seconds before assuming isolatd is dead
    pub heartbeat_timeout_secs: u64,
    /// Maximum escalation level to apply autonomously (0–7)
    pub max_auto_level: u8,
    /// Escalation level that requires human approval
    pub require_approval_above: u8,
    /// Out-of-band notification channels (syslog, serial, webhook, SMS)
    pub notify_oob: Vec<String>,
    /// File to log all paladin actions (append-only, separate from isolatd logs)
    pub audit_log_path: std::path::PathBuf,
    /// Whether to actually execute level 7 (ABSOLUTION) — must be explicitly enabled
    pub absolution_enabled: bool,
}

impl PaladinDaemonConfig {
    pub fn from_env() -> Self {
        Self {
            socket_path: std::env::var("PALADIN_SOCKET")
                .map(Into::into)
                .unwrap_or_else(|_| "/run/isolate/paladin.sock".into()),
            heartbeat_timeout_secs: std::env::var("PALADIN_HEARTBEAT_TIMEOUT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            max_auto_level: std::env::var("PALADIN_MAX_AUTO_LEVEL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(4),
            require_approval_above: std::env::var("PALADIN_REQUIRE_APPROVAL_ABOVE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
            notify_oob: std::env::var("PALADIN_NOTIFY_OOB")
                .unwrap_or_else(|_| "syslog".into())
                .split(',')
                .map(|s| s.trim().to_owned())
                .collect(),
            audit_log_path: std::env::var("PALADIN_AUDIT_LOG")
                .map(Into::into)
                .unwrap_or_else(|_| "/var/log/isolate/paladin-audit.log".into()),
            absolution_enabled: std::env::var("PALADIN_ABSOLUTION_ENABLED")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false),
        }
    }
}
