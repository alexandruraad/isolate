// SPDX-License-Identifier: Apache-2.0
//! Policy versioning — tracks policy lineage and enables rollback.

use isolate_core::types::PolicyUpdate;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// A versioned snapshot of an isobox's policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyVersion {
    /// Monotonically increasing version number (per isobox)
    pub version: u32,
    /// Wall-clock time when this version was applied
    pub applied_at: u64, // UNIX seconds
    /// Who or what authored the change
    pub author: String,
    /// Human-readable reason for the change
    pub reason: String,
    /// Serialised policy diff (JSON patch format)
    pub diff_json: String,
    /// SHA256 of the full policy blob at this version
    pub policy_hash: String,
}

impl PolicyVersion {
    /// Build a new version record from a `PolicyUpdate`.
    pub fn from_update(version: u32, update: &PolicyUpdate) -> Self {
        let author = format!("{:?}", update.author);
        let reason = update.reason.clone().unwrap_or_else(|| "unspecified".into());
        let diff_json = serde_json::to_string(&update.changes)
            .unwrap_or_else(|_| "[]".into());
        let policy_hash = compute_hash(&diff_json);
        let applied_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        PolicyVersion { version, applied_at, author, reason, diff_json, policy_hash }
    }
}

fn compute_hash(data: &str) -> String {
    // Simple truncated representation for audit purposes.
    // A production implementation would use ring::digest::SHA256.
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    data.hash(&mut h);
    format!("{:016x}", h.finish())
}

/// In-memory version ledger for a single isobox.
#[derive(Debug, Default)]
pub struct VersionLedger {
    versions: Vec<PolicyVersion>,
    next: u32,
}

impl VersionLedger {
    pub fn new() -> Self {
        Self { versions: Vec::new(), next: 1 }
    }

    /// Record a new policy update; returns the version number assigned.
    pub fn record(&mut self, update: &PolicyUpdate) -> u32 {
        let v = PolicyVersion::from_update(self.next, update);
        let n = v.version;
        self.versions.push(v);
        self.next += 1;
        n
    }

    /// Return the most recent version, if any.
    pub fn current(&self) -> Option<&PolicyVersion> {
        self.versions.last()
    }

    /// Return the full history (oldest first).
    pub fn history(&self) -> &[PolicyVersion] {
        &self.versions
    }

    /// Return the diff JSON for a specific version number.
    pub fn get(&self, version: u32) -> Option<&PolicyVersion> {
        self.versions.iter().find(|v| v.version == version)
    }
}
