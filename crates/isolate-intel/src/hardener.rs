//! Policy auto-hardener — computes minimum-privilege policy from observations.
//!
//! After the baseline warm period, the hardener analyzes what the workload
//! actually used and generates a PolicyUpdate that tightens unused permissions.
//! Presented as a suggestion; applied automatically with auto_harden = true.

use crate::baseline::BaselineProfiler;
use isolate_core::types::{IsoboxConfig, PolicyChange, PolicyUpdate, PolicyUpdateAuthor, SyscallMode};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct PolicyHardener;

impl PolicyHardener {
    pub fn new() -> Self { Self }

    /// Generate a policy hardening suggestion if the baseline is warm.
    pub async fn suggest(
        &self,
        config: &IsoboxConfig,
        baseline: &BaselineProfiler,
    ) -> Option<PolicyUpdate> {
        if !baseline.is_warm(&config.workload_class) {
            return None; // Not enough data yet
        }

        // Only suggest if current policy isn't already at minimum privilege
        if config.policy.syscalls.mode == SyscallMode::Allowlist
            && !config.policy.syscalls.allow.is_empty()
        {
            return None; // Already filtered
        }

        let mut changes: Vec<PolicyChange> = Vec::new();

        // Suggest syscall allowlist from observed syscalls
        if let Some(stats) = baseline.stats(&config.workload_class, 60) {
            if !stats.syscall_counts.is_empty() {
                let observed_syscalls = get_syscall_names(&stats.syscall_counts);
                if !observed_syscalls.is_empty() {
                    changes.push(PolicyChange::SetSyscallMode(SyscallMode::Allowlist));
                    for name in &observed_syscalls {
                        changes.push(PolicyChange::AddSyscallAllow(name.clone()));
                    }
                }
            }
        }

        if changes.is_empty() {
            return None;
        }

        Some(PolicyUpdate {
            isobox_id: config.id.clone(),
            author: PolicyUpdateAuthor::AutoHardener,
            changes,
            reason: Some(format!(
                "Computed minimum-privilege policy from {} min baseline",
                60
            )),
        })
    }
}

/// Map Linux syscall numbers to names (subset of most common).
fn get_syscall_names(syscall_counts: &std::collections::HashMap<u32, u64>) -> Vec<String> {
    // In production: use a full syscall table from the `syscalls` crate
    // or generate from kernel headers at build time
    let table: std::collections::HashMap<u32, &str> = [
        (0, "read"), (1, "write"), (2, "open"), (3, "close"),
        (4, "stat"), (5, "fstat"), (6, "lstat"), (7, "poll"),
        (8, "lseek"), (9, "mmap"), (10, "mprotect"), (11, "munmap"),
        (12, "brk"), (13, "rt_sigaction"), (14, "rt_sigprocmask"),
        (17, "pread64"), (18, "pwrite64"), (19, "readv"), (20, "writev"),
        (21, "access"), (22, "pipe"), (23, "select"), (32, "dup"),
        (33, "dup2"), (35, "nanosleep"), (39, "getpid"),
        (41, "socket"), (42, "connect"), (43, "accept"), (44, "sendto"),
        (45, "recvfrom"), (46, "sendmsg"), (47, "recvmsg"),
        (48, "shutdown"), (49, "bind"), (50, "listen"),
        (56, "clone"), (57, "fork"), (58, "vfork"), (59, "execve"),
        (60, "exit"), (61, "wait4"), (62, "kill"), (63, "uname"),
        (72, "fcntl"), (202, "futex"), (231, "exit_group"),
        (257, "openat"), (262, "newfstatat"), (263, "unlinkat"),
        (269, "faccessat"),
    ].into_iter().collect();

    syscall_counts.keys()
        .filter_map(|nr| table.get(nr).map(|name| name.to_string()))
        .collect()
}
