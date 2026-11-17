//! Virtualization.framework backend — macOS lightweight VM isolation.
//!
//! Uses Apple's Virtualization.framework (macOS 11+, Apple Silicon optimised)
//! to run isoboxes inside lightweight VMs with virtio devices.
//!
//! Status: Phase-2 skeleton — FFI to Virtualization.framework not yet wired.

use crate::backend::SandboxBackend;
use async_trait::async_trait;
use isolate_core::{
    types::{BackendHandle, BackendKind, IsoboxConfig, PolicyUpdate, SandboxHandle},
    IsoboxId, Result, IsolateError,
};
use isolate_events::stream::EventStream;
use std::path::Path;
use tracing::info;

#[derive(Debug)]
pub struct VirtBackend;

impl VirtBackend {
    pub fn new() -> Self { Self }
}

#[async_trait]
impl SandboxBackend for VirtBackend {
    fn kind(&self) -> BackendKind { BackendKind::VirtFramework }
    fn name(&self) -> &'static str { "virt-framework" }
    fn priority(&self) -> u8 { 50 }

    fn is_available(&self) -> bool {
        #[cfg(target_os = "macos")]
        {
            // Virtualization.framework requires macOS 11+ and Apple Silicon or Intel Mac
            let output = match std::process::Command::new("sw_vers")
                .arg("-productVersion")
                .output() {
                Ok(o) => o,
                Err(_) => return false,
            };
            let version = String::from_utf8_lossy(&output.stdout);
            let major: u32 = version.split('.').next()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0);
            return major >= 11;
        }
        #[allow(unreachable_code)]
        false
    }

    async fn create(&self, id: IsoboxId, _config: &IsoboxConfig) -> Result<SandboxHandle> {
        info!(isobox_id = %id, "VirtFramework backend: stub — not yet implemented");
        Err(IsolateError::backend_unavailable("virt-framework", "Phase-2 skeleton"))
    }

    async fn event_stream(&self, _handle: &SandboxHandle) -> Result<EventStream> {
        Err(IsolateError::backend_unavailable("virt-framework", "Phase-2 skeleton"))
    }

    async fn apply_policy(&self, _handle: &SandboxHandle, _update: &PolicyUpdate) -> Result<()> {
        Ok(())
    }

    async fn freeze(&self, _handle: &SandboxHandle) -> Result<()> {
        Err(IsolateError::backend_unavailable("virt-framework", "freeze not implemented"))
    }

    async fn thaw(&self, _handle: &SandboxHandle) -> Result<()> {
        Err(IsolateError::backend_unavailable("virt-framework", "thaw not implemented"))
    }

    async fn snapshot(&self, _handle: &SandboxHandle, _path: &Path) -> Result<()> {
        Err(IsolateError::backend_unavailable("virt-framework", "snapshot not implemented"))
    }

    async fn destroy(&self, _handle: SandboxHandle) -> Result<()> {
        Ok(())
    }
}
