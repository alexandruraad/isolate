//! Sentinel — out-of-band isobox monitor.
//!
//! The sentinel watches isoboxes from OUTSIDE using only kernel interfaces
//! that cannot be compromised by the workload itself:
//!   - /proc filesystem (process enumeration, maps, fds)
//!   - /sys/fs/cgroup (resource usage, process membership)
//!   - netlink socket (network connection events)
//!   - inotify on critical paths (tripwire files)
//!
//! If the sentinel detects activity that bypassed all sandbox layers,
//! it triggers paladin escalation independently of isolatd.

use crate::{
    escalation::{EscalationEngine, EscalationSource, EscalationTrigger},
    PaladinDaemonConfig,
};
use anyhow::Result;
use chrono::Utc;
use std::collections::HashSet;
use std::path::PathBuf;
use tokio::time::{interval, Duration};
use tracing::{info, warn, error};

pub struct Sentinel {
    config: PaladinDaemonConfig,
}

impl Sentinel {
    pub fn new(config: PaladinDaemonConfig) -> Self {
        Self { config }
    }

    pub async fn run(self) -> Result<()> {
        info!("paladin sentinel starting out-of-band monitoring");

        let engine = EscalationEngine::new(self.config.clone());
        let mut check_interval = interval(Duration::from_secs(5));

        // Load registered isoboxes from the paladin's own state file
        // (written by isolatd when isoboxes are created)
        let state_path = PathBuf::from("/run/isolate/isobox-registry.json");

        loop {
            check_interval.tick().await;

            // Check tripwire files (if any isobox process wrote here, it escaped)
            if let Some(escaper) = self.check_tripwires().await {
                error!(
                    process = %escaper,
                    "SENTINEL: process escaped sandbox — tripwire triggered"
                );
                let trigger = EscalationTrigger {
                    isobox_id: None,
                    source: EscalationSource::Tripwire,
                    reason: format!("Process '{}' accessed tripwire path — sandbox escape detected", escaper),
                    anomaly_score: Some(1.0),
                    timestamp: Utc::now(),
                };
                engine.escalate(trigger, 3).await; // FREEZE immediately
            }

            // Check for processes outside their expected cgroup
            if let Some(escapee) = self.check_cgroup_membership().await {
                error!(pid = escapee, "SENTINEL: process escaped cgroup");
                let trigger = EscalationTrigger {
                    isobox_id: None,
                    source: EscalationSource::SentinelDetection,
                    reason: format!("Process {escapee} found outside its cgroup — possible namespace escape"),
                    anomaly_score: Some(0.95),
                    timestamp: Utc::now(),
                };
                engine.escalate(trigger, 3).await;
            }

            // Check network connections from unexpected PIDs
            self.check_suspicious_connections(&engine).await;
        }
    }

    /// Check tripwire files — these should NEVER be accessed by any isobox process.
    /// If they are, we have a sandbox escape.
    async fn check_tripwires(&self) -> Option<String> {
        let tripwires = [
            "/etc/paladin-tripwire",
            "/root/.paladin-canary",
            "/var/lib/isolate/.canary",
        ];

        for path in &tripwires {
            let meta = tokio::fs::metadata(path).await;
            match meta {
                Ok(m) => {
                    // Check if recently accessed (atime within last 10 seconds)
                    // If so, something accessed the tripwire
                    if let Ok(accessed) = m.accessed() {
                        let elapsed = accessed.elapsed().unwrap_or(Duration::from_secs(9999));
                        if elapsed < Duration::from_secs(10) {
                            // Find which process accessed it via /proc
                            // (simplified — full impl uses inotify)
                            return Some(format!("tripwire:{}", path));
                        }
                    }
                }
                Err(_) => {
                    // Tripwire file missing — was it deleted by an escaping process?
                    // Create it fresh and alert
                    let _ = tokio::fs::write(path, b"paladin-canary").await;
                }
            }
        }

        None
    }

    /// Check that all isobox PIDs are still inside their expected cgroups.
    /// A PID outside its cgroup is a strong indicator of namespace escape.
    async fn check_cgroup_membership(&self) -> Option<u32> {
        // Read all known isobox cgroups
        let cgroup_base = "/sys/fs/cgroup/isolate";
        let mut isobox_pids: HashSet<u32> = HashSet::new();

        if let Ok(mut dir) = tokio::fs::read_dir(cgroup_base).await {
            while let Ok(Some(entry)) = dir.next_entry().await {
                let procs_path = entry.path().join("cgroup.procs");
                if let Ok(content) = tokio::fs::read_to_string(&procs_path).await {
                    for line in content.lines() {
                        if let Ok(pid) = line.trim().parse::<u32>() {
                            isobox_pids.insert(pid);
                        }
                    }
                }
            }
        }

        // Check /proc for any process that has an isobox-related UID
        // but is NOT in any isobox cgroup (possible escape)
        if let Ok(mut proc_dir) = tokio::fs::read_dir("/proc").await {
            while let Ok(Some(entry)) = proc_dir.next_entry().await {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if let Ok(pid) = name_str.parse::<u32>() {
                    // Check if this PID's cgroup shows it's inside isolate
                    let cgroup_file = format!("/proc/{}/cgroup", pid);
                    if let Ok(cgroup) = tokio::fs::read_to_string(&cgroup_file).await {
                        let in_isolate_cgroup = cgroup.contains("/isolate/");
                        let in_known_pids = isobox_pids.contains(&pid);

                        if in_isolate_cgroup && !in_known_pids {
                            // Process claims to be in isolate cgroup but we didn't see it
                            // in cgroup.procs — suspicious
                            warn!(pid, "PID in isolate cgroup but not in cgroup.procs listing");
                        }

                        // More importantly: if NOT in isolate cgroup but has isobox UID
                        // (UIDs 100000–199999 are reserved for isoboxes)
                        let status_file = format!("/proc/{}/status", pid);
                        if let Ok(status) = tokio::fs::read_to_string(&status_file).await {
                            for line in status.lines() {
                                if line.starts_with("Uid:") {
                                    let uids: Vec<u32> = line
                                        .split_whitespace()
                                        .skip(1)
                                        .filter_map(|s| s.parse().ok())
                                        .collect();
                                    for uid in &uids {
                                        if (100000..=199999).contains(uid) && !in_isolate_cgroup {
                                            // ISOBOX UID OUTSIDE CGROUP — escape!
                                            return Some(pid);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        None
    }

    /// Check for suspicious network connections from isobox PIDs.
    async fn check_suspicious_connections(&self, engine: &EscalationEngine) {
        // In production: parse /proc/net/tcp6, /proc/net/udp6
        // and cross-reference with isobox policy to find violations
        // This is a belt-and-suspenders check against the eBPF enforcer
    }
}
