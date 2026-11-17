//! `SandboxBackend` trait — the core abstraction for all isolation backends.
//!
//! Every platform primitive (eBPF, seccomp, Landlock, ESF, ETW, WASM, …)
//! implements this trait. The engine composes multiple backends per isobox.

use async_trait::async_trait;
use isolate_core::{
    types::{BackendKind, IsoboxConfig, PolicyUpdate, SandboxHandle},
    IsoboxId, IsolateError, Result,
};
use isolate_events::stream::EventStream;
use std::path::Path;

pub mod linux;
pub mod macos;
pub mod wasm;
pub mod windows;

/// The core trait that every isolation backend must implement.
///
/// # Design notes
/// - Backends are always async — kernel operations may block.
/// - `create` is idempotent within an isobox lifecycle.
/// - All methods must be cancellation-safe (tokio `select!` safe).
/// - Backends must handle their own resource cleanup in `destroy`.
#[async_trait]
pub trait SandboxBackend: Send + Sync + std::fmt::Debug {
    /// Machine-readable backend identifier (matches `BackendKind`).
    fn kind(&self) -> BackendKind;

    /// Human-readable backend name for logging.
    fn name(&self) -> &'static str;

    /// Priority ordering when multiple backends are composed.
    /// Higher priority backends are applied / queried first.
    /// Range: 0–255. Kernel-level backends should have higher priority.
    fn priority(&self) -> u8;

    /// Check if this backend is available on the current platform and kernel.
    /// Should be fast and non-panicking — called at startup to filter backends.
    fn is_available(&self) -> bool;

    /// Create the isolation context for a new isobox.
    /// Returns a `SandboxHandle` with backend-specific data stored inside.
    async fn create(
        &self,
        id: IsoboxId,
        config: &IsoboxConfig,
    ) -> Result<SandboxHandle>;

    /// Return a stream of raw events from this backend for the given isobox.
    /// The stream should be infinite until the isobox is destroyed.
    async fn event_stream(
        &self,
        handle: &SandboxHandle,
    ) -> Result<EventStream>;

    /// Apply an incremental policy update to a *running* isobox.
    /// Must be applied atomically from the workload's perspective.
    async fn apply_policy(
        &self,
        handle: &SandboxHandle,
        update: &PolicyUpdate,
    ) -> Result<()>;

    /// Pause all activity in the isobox (SIGSTOP / VM pause / Wasm yield).
    /// Must be reversible via `thaw`. Used for forensic snapshots.
    async fn freeze(&self, handle: &SandboxHandle) -> Result<()>;

    /// Resume a frozen isobox (SIGCONT / VM resume).
    async fn thaw(&self, handle: &SandboxHandle) -> Result<()>;

    /// Create a forensic snapshot at `path`.
    ///
    /// Contents depend on the backend:
    /// - eBPF: current BPF map state dump
    /// - Container/namespace: overlayfs diff
    /// - VM: full memory + disk image
    /// - WASM: linear memory dump
    async fn snapshot(
        &self,
        handle: &SandboxHandle,
        path: &Path,
    ) -> Result<()>;

    /// Destroy the isobox: kill all processes, release resources, clean up.
    /// Called exactly once per handle. Consumes the handle.
    async fn destroy(&self, handle: SandboxHandle) -> Result<()>;

    /// Emergency hard kill — fastest possible termination.
    /// Called by the paladin and policy enforcer for immediate action.
    /// Must not block longer than 100ms.
    async fn kill_immediate(&self, handle: &SandboxHandle) -> Result<()> {
        // Default: same as destroy
        self.destroy(handle.clone()).await
    }
}

/// Collect all available backends for the current platform.
/// Backends are sorted by priority (highest first).
pub fn available_backends(
    config: &isolate_core::types::BackendConfig,
) -> Vec<Box<dyn SandboxBackend>> {
    let mut backends: Vec<Box<dyn SandboxBackend>> = Vec::new();

    let requested: Vec<BackendKind> = config
        .enabled
        .clone()
        .unwrap_or_else(BackendKind::all_for_platform);

    for kind in &requested {
        let b: Option<Box<dyn SandboxBackend>> = match kind {
            #[cfg(target_os = "linux")]
            BackendKind::Ebpf => Some(Box::new(linux::ebpf::EbpfBackend::new(config))),
            #[cfg(target_os = "linux")]
            BackendKind::Seccomp => Some(Box::new(linux::seccomp::SeccompBackend::new())),
            #[cfg(target_os = "linux")]
            BackendKind::Landlock => Some(Box::new(linux::landlock::LandlockBackend::new())),
            #[cfg(target_os = "linux")]
            BackendKind::Namespaces => Some(Box::new(linux::namespace::NamespaceBackend::new())),
            #[cfg(target_os = "macos")]
            BackendKind::EndpointSecurity => Some(Box::new(macos::esf::EsfBackend::new())),
            #[cfg(target_os = "macos")]
            BackendKind::Seatbelt => Some(Box::new(macos::seatbelt::SeatbeltBackend::new())),
            BackendKind::Wasm => Some(Box::new(wasm::wasmtime::WasmtimeBackend::new())),
            _ => None,
        };

        if let Some(backend) = b {
            if backend.is_available() {
                backends.push(backend);
            }
        }
    }

    // Sort: highest priority first
    backends.sort_by(|a, b| b.priority().cmp(&a.priority()));
    backends
}
