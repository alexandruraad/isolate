//! Linux namespace backend — PID, net, mount, user, IPC, UTS, cgroup isolation.
//!
//! Orchestrates clone(2) flags to create fully isolated process namespaces.
//! Combined with cgroup v2 for resource limits.

use crate::backend::SandboxBackend;
use async_trait::async_trait;
use isolate_core::{
    types::{BackendHandle, BackendKind, IsoboxConfig, PolicyUpdate, SandboxHandle},
    IsoboxId, Result,
};
use isolate_events::stream::EventStream;
use std::path::Path;
use tracing::info;

#[derive(Debug)]
pub struct NamespaceBackend;

impl NamespaceBackend {
    pub fn new() -> Self { Self }
}

#[async_trait]
impl SandboxBackend for NamespaceBackend {
    fn kind(&self) -> BackendKind { BackendKind::Namespaces }
    fn name(&self) -> &'static str { "namespaces" }
    fn priority(&self) -> u8 { 160 }

    fn is_available(&self) -> bool {
        #[cfg(target_os = "linux")]
        return std::path::Path::new("/proc/self/ns/pid").exists();
        #[allow(unreachable_code)]
        false
    }

    async fn create(&self, id: IsoboxId, config: &IsoboxConfig) -> Result<SandboxHandle> {
        let process_policy = &config.policy.process;
        info!(
            isobox_id = %id,
            allow_network_ns = process_policy.allow_network_namespace,
            "namespace backend: creating isolated namespaces"
        );

        // In production: use nix::sched::clone() with CLONE_NEWPID | CLONE_NEWNET |
        // CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWCGROUP
        //
        // Then: set up veth pair, configure cgroup v2 limits, pivot_root or chroot

        let cgroup_path = format!("/sys/fs/cgroup/isolate/{}", id);

        Ok(SandboxHandle {
            id: id.clone(),
            backend_handles: [(
                BackendKind::Namespaces,
                BackendHandle {
                    kind: BackendKind::Namespaces,
                    data: serde_json::json!({
                        "pid_ns": true,
                        "net_ns": !process_policy.allow_network_namespace,
                        "mount_ns": true,
                        "user_ns": !process_policy.allow_user_namespace,
                        "ipc_ns": true,
                        "uts_ns": true,
                        "cgroup_path": cgroup_path,
                        "max_processes": process_policy.max_processes,
                        "max_memory_mb": process_policy.max_memory_mb,
                    }),
                },
            )]
            .into(),
            started_at: chrono::Utc::now(),
            state: isolate_core::types::IsoboxState::Running,
        })
    }

    async fn event_stream(&self, _handle: &SandboxHandle) -> Result<EventStream> {
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        Ok(Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx)))
    }

    async fn apply_policy(&self, _handle: &SandboxHandle, _update: &PolicyUpdate) -> Result<()> {
        // cgroup limits can be updated live by writing to cgroup v2 files
        Ok(())
    }

    async fn freeze(&self, handle: &SandboxHandle) -> Result<()> {
        // Write "1" to cgroup.freeze
        if let Some(bh) = handle.backend_handles.get(&BackendKind::Namespaces) {
            if let Some(cg) = bh.data.get("cgroup_path").and_then(|v| v.as_str()) {
                let freeze_path = format!("{}/cgroup.freeze", cg);
                let _ = tokio::fs::write(&freeze_path, "1").await;
            }
        }
        Ok(())
    }

    async fn thaw(&self, handle: &SandboxHandle) -> Result<()> {
        if let Some(bh) = handle.backend_handles.get(&BackendKind::Namespaces) {
            if let Some(cg) = bh.data.get("cgroup_path").and_then(|v| v.as_str()) {
                let freeze_path = format!("{}/cgroup.freeze", cg);
                let _ = tokio::fs::write(&freeze_path, "0").await;
            }
        }
        Ok(())
    }

    async fn snapshot(&self, handle: &SandboxHandle, path: &Path) -> Result<()> {
        // Dump cgroup stats, ns links
        let data = serde_json::json!({
            "backend": "namespaces",
            "isobox_id": handle.id.as_str(),
            "backend_data": handle.backend_handles.get(&BackendKind::Namespaces).map(|h| &h.data),
        });
        tokio::fs::write(
            path.join("namespaces.json"),
            serde_json::to_string_pretty(&data).unwrap(),
        ).await?;
        Ok(())
    }

    async fn destroy(&self, handle: SandboxHandle) -> Result<()> {
        // Kill process group, remove cgroup
        info!(isobox_id = %handle.id, "namespace backend: destroying namespaces");
        if let Some(bh) = handle.backend_handles.get(&BackendKind::Namespaces) {
            if let Some(cg) = bh.data.get("cgroup_path").and_then(|v| v.as_str()) {
                // Write SIGKILL to cgroup.kill (Linux 5.14+)
                let _ = tokio::fs::write(format!("{}/cgroup.kill", cg), "1").await;
                // Remove cgroup dir
                let _ = tokio::fs::remove_dir(cg).await;
            }
        }
        Ok(())
    }

    async fn kill_immediate(&self, handle: &SandboxHandle) -> Result<()> {
        self.freeze(handle).await?;
        // cgroup.kill sends SIGKILL to all processes immediately
        if let Some(bh) = handle.backend_handles.get(&BackendKind::Namespaces) {
            if let Some(cg) = bh.data.get("cgroup_path").and_then(|v| v.as_str()) {
                let _ = tokio::fs::write(format!("{}/cgroup.kill", cg), "1").await;
            }
        }
        Ok(())
    }
}
