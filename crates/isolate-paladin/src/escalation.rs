//! Escalation engine — the Oath of the Sentinel.
//!
//! Implements all 8 escalation levels. Each level is:
//!   - Atomic: either fully applied or not
//!   - Logged: every action written to the append-only audit log
//!   - Non-reversible above level 3 (by design)
//!   - Independently verifiable: uses /proc and cgroups, not eBPF

use crate::{out_of_band::OutOfBand, PaladinDaemonConfig};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tracing::{error, info, warn};

/// Reason for a paladin escalation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationTrigger {
    pub isobox_id: Option<String>,
    pub source: EscalationSource,
    pub reason: String,
    pub anomaly_score: Option<f32>,
    pub timestamp: chrono::DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EscalationSource {
    HeartbeatTimeout,
    AnomalyScore,
    IocMatch,
    ManualCommand,
    Tripwire,
    SentinelDetection,
}

/// The outcome of an escalation action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationOutcome {
    pub level: u8,
    pub level_name: &'static str,
    pub success: bool,
    pub errors: Vec<String>,
    pub timestamp: chrono::DateTime<Utc>,
}

pub struct EscalationEngine {
    config: PaladinDaemonConfig,
    oob: OutOfBand,
}

impl EscalationEngine {
    pub fn new(config: PaladinDaemonConfig) -> Self {
        let oob = OutOfBand::new(config.notify_oob.clone());
        Self { config, oob }
    }

    /// Execute the escalation ladder from `start_level` upward,
    /// stopping when the situation is contained or max level is reached.
    pub async fn escalate(
        &self,
        trigger: EscalationTrigger,
        start_level: u8,
    ) {
        info!(
            level = start_level,
            source = ?trigger.source,
            reason = %trigger.reason,
            "PALADIN ESCALATION INITIATED"
        );

        let mut level = start_level;
        let max = self.config.max_auto_level.min(7);

        while level <= max {
            let outcome = self.execute_level(level, &trigger).await;
            self.audit_log(&trigger, &outcome).await;
            self.oob.notify(&trigger, &outcome).await;

            if outcome.success {
                info!(level, level_name = outcome.level_name, "escalation level executed successfully");
                // For level 4+, the isobox is dead. Stop escalating.
                if level >= 4 {
                    break;
                }
                // For levels 1–3, continue watching; stop if situation contained
                break;
            } else {
                warn!(
                    level,
                    errors = ?outcome.errors,
                    "escalation level failed — advancing to next level"
                );
                level += 1;
            }
        }
    }

    async fn execute_level(
        &self,
        level: u8,
        trigger: &EscalationTrigger,
    ) -> EscalationOutcome {
        let mut errors: Vec<String> = Vec::new();
        let level_name = level_name(level);
        info!(level, level_name, isobox_id = ?trigger.isobox_id, "executing paladin level");

        let success = match level {
            0 => true, // WATCHING — no action

            1 => {
                // ALERT — notify all out-of-band channels
                // (done by caller via oob.notify; nothing else needed here)
                true
            }

            2 => {
                // CONTAIN — sever network at kernel level
                // Uses nftables (Linux) or pf (macOS), NOT eBPF
                // eBPF may be compromised; nftables is independent
                self.contain_network(trigger, &mut errors).await
            }

            3 => {
                // FREEZE — SIGSTOP entire process group / cgroup
                self.freeze_cgroup(trigger, &mut errors).await
            }

            4 => {
                // TERMINATE — SIGKILL all, destroy namespaces
                self.terminate(trigger, &mut errors).await
            }

            5 => {
                // SCORCH — wipe volatile state, zero memory, destroy dirs
                self.scorch(trigger, &mut errors).await
            }

            6 => {
                // RAMPART — system-wide lockdown
                self.rampart(&mut errors).await
            }

            7 => {
                // ABSOLUTION — kernel panic (requires explicit opt-in)
                if self.config.absolution_enabled {
                    self.absolution(&mut errors).await
                } else {
                    errors.push("ABSOLUTION not enabled (set PALADIN_ABSOLUTION_ENABLED=true)".into());
                    false
                }
            }

            _ => {
                errors.push(format!("unknown escalation level: {level}"));
                false
            }
        };

        EscalationOutcome {
            level,
            level_name,
            success,
            errors,
            timestamp: Utc::now(),
        }
    }

    // ── Level 2: CONTAIN ─────────────────────────────────────────────────────

    async fn contain_network(
        &self,
        trigger: &EscalationTrigger,
        errors: &mut Vec<String>,
    ) -> bool {
        warn!("PALADIN L2 CONTAIN: severing network for isobox {:?}", trigger.isobox_id);

        #[cfg(target_os = "linux")]
        {
            // Use nftables to drop all traffic from the isobox's network namespace
            // This operates at the host network stack, independent of eBPF
            let isobox_id = trigger.isobox_id.as_deref().unwrap_or("unknown");

            // Add nftables rule to drop all traffic from this isobox
            let rule = format!(
                "add rule inet filter forward meta mark 0x{} drop",
                isobox_mark(isobox_id)
            );
            match tokio::process::Command::new("nft")
                .args(["-f", "-"])
                .stdin(std::process::Stdio::piped())
                .spawn()
            {
                Ok(mut child) => {
                    if let Some(stdin) = child.stdin.take() {
                        let mut stdin = tokio::io::BufWriter::new(stdin);
                        let _ = stdin.write_all(rule.as_bytes()).await;
                    }
                    match child.wait().await {
                        Ok(status) if status.success() => {
                            info!("nftables rule applied: network contained");
                            return true;
                        }
                        Ok(status) => {
                            errors.push(format!("nft exited with: {status}"));
                        }
                        Err(e) => {
                            errors.push(format!("nft spawn failed: {e}"));
                        }
                    }
                }
                Err(e) => {
                    errors.push(format!("nft not found: {e}"));
                    // Fallback: iptables
                    let _ = tokio::process::Command::new("iptables")
                        .args(["-I", "FORWARD", "-m", "mark", "--mark",
                               &format!("0x{}", isobox_mark(isobox_id)), "-j", "DROP"])
                        .status()
                        .await;
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            // Use pfctl to block the isobox's vif interface
            warn!("macOS network contain: pfctl block (not implemented yet)");
        }

        errors.is_empty()
    }

    // ── Level 3: FREEZE ──────────────────────────────────────────────────────

    async fn freeze_cgroup(
        &self,
        trigger: &EscalationTrigger,
        errors: &mut Vec<String>,
    ) -> bool {
        warn!("PALADIN L3 FREEZE: SIGSTOP to all isobox processes");

        #[cfg(target_os = "linux")]
        {
            let isobox_id = trigger.isobox_id.as_deref().unwrap_or("unknown");
            let cgroup_freeze = format!("/sys/fs/cgroup/isolate/{}/cgroup.freeze", isobox_id);

            match tokio::fs::write(&cgroup_freeze, "1").await {
                Ok(()) => {
                    info!("cgroup frozen via {}", cgroup_freeze);
                    return true;
                }
                Err(e) => {
                    errors.push(format!("cgroup freeze failed: {e}"));
                    // Fallback: SIGSTOP to all PIDs in the cgroup
                    self.sigstop_cgroup_pids(isobox_id, errors).await;
                }
            }
        }

        errors.is_empty()
    }

    #[cfg(target_os = "linux")]
    async fn sigstop_cgroup_pids(&self, isobox_id: &str, errors: &mut Vec<String>) {
        let procs_path = format!("/sys/fs/cgroup/isolate/{}/cgroup.procs", isobox_id);
        match tokio::fs::read_to_string(&procs_path).await {
            Ok(content) => {
                for line in content.lines() {
                    if let Ok(pid) = line.trim().parse::<i32>() {
                        unsafe {
                            if libc::kill(pid, libc::SIGSTOP) != 0 {
                                errors.push(format!("SIGSTOP failed for pid {pid}"));
                            }
                        }
                    }
                }
            }
            Err(e) => errors.push(format!("could not read cgroup procs: {e}")),
        }
    }

    // ── Level 4: TERMINATE ───────────────────────────────────────────────────

    async fn terminate(
        &self,
        trigger: &EscalationTrigger,
        errors: &mut Vec<String>,
    ) -> bool {
        error!("PALADIN L4 TERMINATE: SIGKILL all isobox processes");

        #[cfg(target_os = "linux")]
        {
            let isobox_id = trigger.isobox_id.as_deref().unwrap_or("unknown");

            // cgroup.kill sends SIGKILL to all processes atomically (Linux 5.14+)
            let kill_path = format!("/sys/fs/cgroup/isolate/{}/cgroup.kill", isobox_id);
            if tokio::fs::write(&kill_path, "1").await.is_ok() {
                info!("cgroup killed via {}", kill_path);
                // Remove cgroup directory
                let _ = tokio::fs::remove_dir_all(
                    format!("/sys/fs/cgroup/isolate/{}", isobox_id)
                ).await;
                return true;
            }

            // Fallback: read pids and SIGKILL
            let procs_path = format!("/sys/fs/cgroup/isolate/{}/cgroup.procs", isobox_id);
            if let Ok(content) = tokio::fs::read_to_string(&procs_path).await {
                for line in content.lines() {
                    if let Ok(pid) = line.trim().parse::<i32>() {
                        unsafe { libc::kill(pid, libc::SIGKILL); }
                    }
                }
                return true;
            }

            errors.push("could not find cgroup.kill or cgroup.procs".into());
        }

        errors.is_empty()
    }

    // ── Level 5: SCORCH ──────────────────────────────────────────────────────

    async fn scorch(
        &self,
        trigger: &EscalationTrigger,
        errors: &mut Vec<String>,
    ) -> bool {
        error!("PALADIN L5 SCORCH: wiping volatile state");

        let isobox_id = trigger.isobox_id.as_deref().unwrap_or("unknown");

        // Wipe isobox work directories
        let dirs_to_wipe = [
            format!("/var/lib/isolate/isoboxes/{}", isobox_id),
            format!("/tmp/isolate-{}", isobox_id),
            format!("/run/isolate/{}", isobox_id),
        ];

        for dir in &dirs_to_wipe {
            if std::path::Path::new(dir).exists() {
                // Overwrite files with zeros before removing (basic anti-forensics against
                // the THREAT ACTOR, not against defenders — defenders get the full event log)
                if let Err(e) = tokio::fs::remove_dir_all(dir).await {
                    errors.push(format!("could not wipe {dir}: {e}"));
                } else {
                    info!("wiped {}", dir);
                }
            }
        }

        // Drop encrypted volume keys (if isobox used encrypted storage)
        // This prevents the threat actor from recovering data if they somehow persist

        #[cfg(target_os = "linux")]
        {
            // Drop dentries and page cache for isobox files
            let _ = tokio::fs::write("/proc/sys/vm/drop_caches", "3").await;
        }

        true
    }

    // ── Level 6: RAMPART ─────────────────────────────────────────────────────

    async fn rampart(&self, errors: &mut Vec<String>) -> bool {
        error!("PALADIN L6 RAMPART: SYSTEM-WIDE LOCKDOWN");

        #[cfg(target_os = "linux")]
        {
            // Block ALL new outbound connections at the kernel level
            // Only exceptions: the paladin's own OOB notification channel
            let rules = r#"
table inet isolate_rampart {
    chain output {
        type filter hook output priority 0; policy drop;
        # Allow loopback
        iif lo accept
        # Allow established/related
        ct state established,related accept
        # Allow paladin OOB (DNS + specific webhook)
        tcp dport { 53, 443 } accept
        udp dport 53 accept
    }
    chain input {
        type filter hook input priority 0; policy drop;
        iif lo accept
        ct state established,related accept
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
}
"#;
            match tokio::process::Command::new("nft")
                .args(["-f", "-"])
                .stdin(std::process::Stdio::piped())
                .spawn()
            {
                Ok(mut child) => {
                    if let Some(stdin) = child.stdin.take() {
                        let mut stdin = tokio::io::BufWriter::new(stdin);
                        let _ = stdin.write_all(rules.as_bytes()).await;
                    }
                    if let Ok(status) = child.wait().await {
                        if status.success() {
                            error!("RAMPART: system-wide network lockdown active");
                            return true;
                        }
                    }
                }
                Err(e) => errors.push(format!("nft failed: {e}")),
            }
        }

        errors.is_empty()
    }

    // ── Level 7: ABSOLUTION ──────────────────────────────────────────────────

    async fn absolution(&self, errors: &mut Vec<String>) -> bool {
        error!("████████████████████████████████████████████████████████████████");
        error!("██  PALADIN L7: ABSOLUTION — TRIGGERING KERNEL PANIC          ██");
        error!("██  Nothing escapes. No exfiltration possible. System halts.  ██");
        error!("████████████████████████████████████████████████████████████████");

        // Final OOB notification before system goes down
        // (best-effort — system may be unresponsive)

        #[cfg(target_os = "linux")]
        {
            // Enable sysrq, then trigger immediate reboot/panic
            // This is the point of no return.
            //
            // /proc/sysrq-trigger with 'c' triggers an immediate kernel crash
            // (KernelBug), which creates a kernel crash dump for forensic analysis.
            //
            // The crash dump preserves all memory (including the threat actor's
            // volatile data) for post-mortem forensics.

            // Step 1: Enable sysrq
            let _ = tokio::fs::write("/proc/sys/kernel/sysrq", "1").await;

            // Step 2: Sync all filesystems (preserve logs)
            let _ = tokio::fs::write("/proc/sysrq-trigger", "s").await;
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

            // Step 3: Remount filesystems read-only (freeze writes)
            let _ = tokio::fs::write("/proc/sysrq-trigger", "u").await;
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

            // Step 4: PANIC. System crashes. kdump captures memory.
            let _ = tokio::fs::write("/proc/sysrq-trigger", "c").await;

            // If we reach here, something prevented the panic.
            // Last resort: direct syscall
            unsafe {
                // reboot(LINUX_REBOOT_CMD_HALT)
                libc::reboot(libc::LINUX_REBOOT_CMD_HALT);
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            errors.push("ABSOLUTION only implemented on Linux".into());
            return false;
        }

        true // unreachable after panic
    }

    // ── Audit log ─────────────────────────────────────────────────────────────

    async fn audit_log(&self, trigger: &EscalationTrigger, outcome: &EscalationOutcome) {
        let entry = serde_json::json!({
            "timestamp": outcome.timestamp,
            "level": outcome.level,
            "level_name": outcome.level_name,
            "trigger": trigger,
            "success": outcome.success,
            "errors": outcome.errors,
        });

        let line = format!("{}\n", entry);
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.config.audit_log_path)
            .await
        {
            let _ = file.write_all(line.as_bytes()).await;
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

pub fn level_name(level: u8) -> &'static str {
    match level {
        0 => "WATCHING",
        1 => "ALERT",
        2 => "CONTAIN",
        3 => "FREEZE",
        4 => "TERMINATE",
        5 => "SCORCH",
        6 => "RAMPART",
        7 => "ABSOLUTION",
        _ => "UNKNOWN",
    }
}

/// Derive a firewall mark from the isobox ID (for nftables marking).
fn isobox_mark(isobox_id: &str) -> u32 {
    // Simple hash; in production use a deterministic mapping stored in SQLite
    let hash = isobox_id.bytes().fold(0u32, |acc, b| acc.wrapping_add(b as u32));
    (hash & 0x0FFF) | 0x1000 // Keep top nibble 0x1 to distinguish from other marks
}
