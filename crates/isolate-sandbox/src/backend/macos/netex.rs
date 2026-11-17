//! Network Extension backend — macOS content filter for network isolation.
//!
//! Uses the Network Extension framework's content filter provider to intercept
//! and block/allow network flows at the socket layer, complementing ESF.
//!
//! Status: Phase-2 skeleton — requires a System Extension bundle.

use crate::backend::SandboxBackend;
use async_trait::async_trait;
use isolate_core::{
    types::{BackendKind, IsoboxConfig, PolicyUpdate, SandboxHandle},
    IsoboxId, Result, IsolateError,
};
use isolate_events::stream::EventStream;
use std::path::Path;
use tracing::info;

#[derive(Debug)]
pub struct NetExBackend;

impl NetExBackend {
    pub fn new() -> Self { Self }
}

#[async_trait]
impl SandboxBackend for NetExBackend {
    fn kind(&self) -> BackendKind { BackendKind::NetworkExtension }
    fn name(&self) -> &'static str { "network-extension" }
    fn priority(&self) -> u8 { 180 }

    fn is_available(&self) -> bool {
        // Network Extension requires a signed System Extension — not available in dev builds
        false
    }

    async fn create(&self, id: IsoboxId, _config: &IsoboxConfig) -> Result<SandboxHandle> {
        info!(isobox_id = %id, "NetEx backend: stub — requires System Extension entitlement");
        Err(IsolateError::backend_unavailable("network-extension", "Phase-2 skeleton"))
    }

    async fn event_stream(&self, _handle: &SandboxHandle) -> Result<EventStream> {
        Err(IsolateError::backend_unavailable("network-extension", "Phase-2 skeleton"))
    }

    async fn apply_policy(&self, _handle: &SandboxHandle, _update: &PolicyUpdate) -> Result<()> {
        Ok(())
    }

    async fn freeze(&self, _handle: &SandboxHandle) -> Result<()> {
        Ok(())
    }

    async fn thaw(&self, _handle: &SandboxHandle) -> Result<()> {
        Ok(())
    }

    async fn snapshot(&self, _handle: &SandboxHandle, _path: &Path) -> Result<()> {
        Err(IsolateError::backend_unavailable("network-extension", "snapshot not supported"))
    }

    async fn destroy(&self, _handle: SandboxHandle) -> Result<()> {
        Ok(())
    }
}
