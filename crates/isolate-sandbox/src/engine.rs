use crate::backend::{available_backends, SandboxBackend};
use isolate_core::{
    types::{IsoboxConfig, IsoboxState, PolicyUpdate, SandboxHandle},
    IsoboxId, IsolateError, Result,
};
use isolate_events::bus::EventBus;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

/// Registry of all active isoboxes. Shared across all callers.
type Registry = Arc<RwLock<HashMap<IsoboxId, ActiveIsobox>>>;

struct ActiveIsobox {
    config: IsoboxConfig,
    handle: SandboxHandle,
    backends: Vec<Box<dyn SandboxBackend>>,
}

/// The SandboxEngine coordinates multiple backends for each isobox.
/// It maintains the registry and routes lifecycle calls.
#[derive(Clone)]
pub struct SandboxEngine {
    registry: Registry,
    bus: EventBus,
}

impl SandboxEngine {
    pub fn new(bus: EventBus) -> Self {
        Self {
            registry: Arc::new(RwLock::new(HashMap::new())),
            bus,
        }
    }

    /// Create and start a new isobox with all configured backends.
    pub async fn create(&self, config: IsoboxConfig) -> Result<IsoboxId> {
        let id = config.id.clone();
        let backends = available_backends(&config.backends);

        if backends.is_empty() {
            return Err(IsolateError::backend_unavailable(
                "all",
                "no backends available on this platform for the requested configuration",
            ));
        }

        info!(
            isobox_id = %id,
            backends = ?backends.iter().map(|b| b.name()).collect::<Vec<_>>(),
            "creating isobox"
        );

        // Create isolation context in each backend (highest priority first)
        let mut combined_handle = SandboxHandle {
            id: id.clone(),
            backend_handles: HashMap::new(),
            started_at: chrono::Utc::now(),
            state: IsoboxState::Starting,
        };

        for backend in &backends {
            match backend.create(id.clone(), &config).await {
                Ok(handle) => {
                    // Merge backend-specific handles into combined handle
                    combined_handle.backend_handles.extend(handle.backend_handles);
                }
                Err(e) => {
                    error!(backend = backend.name(), error = %e, "backend create failed");
                    // Best-effort cleanup of already-started backends
                    combined_handle.state = IsoboxState::Error;
                    return Err(e);
                }
            }
        }

        combined_handle.state = IsoboxState::Running;

        // Spawn event collection tasks for each backend
        let bus = self.bus.clone();
        for backend in &backends {
            match backend.event_stream(&combined_handle).await {
                Ok(stream) => {
                    let bus = bus.clone();
                    let backend_name = backend.name();
                    tokio::spawn(async move {
                        use futures_util::StreamExt;
                        tokio::pin!(stream);
                        while let Some(event) = stream.next().await {
                            bus.publish(event);
                        }
                        info!(backend = backend_name, "event stream ended");
                    });
                }
                Err(e) => {
                    warn!(backend = backend.name(), error = %e, "could not get event stream");
                }
            }
        }

        let mut reg = self.registry.write().await;
        reg.insert(id.clone(), ActiveIsobox {
            config,
            handle: combined_handle,
            backends,
        });

        info!(isobox_id = %id, "isobox running");
        Ok(id)
    }

    /// Apply a policy update to a running isobox.
    pub async fn apply_policy(&self, id: &IsoboxId, update: PolicyUpdate) -> Result<()> {
        let reg = self.registry.read().await;
        let active = reg.get(id).ok_or_else(|| IsolateError::IsoboxNotFound(id.to_string()))?;

        for backend in &active.backends {
            backend.apply_policy(&active.handle, &update).await?;
        }
        Ok(())
    }

    /// Freeze all activity in an isobox.
    pub async fn freeze(&self, id: &IsoboxId) -> Result<()> {
        let mut reg = self.registry.write().await;
        let active = reg.get_mut(id).ok_or_else(|| IsolateError::IsoboxNotFound(id.to_string()))?;

        for backend in &active.backends {
            backend.freeze(&active.handle).await?;
        }
        active.handle.state = IsoboxState::Frozen;
        info!(isobox_id = %id, "isobox frozen");
        Ok(())
    }

    /// Thaw (resume) a frozen isobox.
    pub async fn thaw(&self, id: &IsoboxId) -> Result<()> {
        let mut reg = self.registry.write().await;
        let active = reg.get_mut(id).ok_or_else(|| IsolateError::IsoboxNotFound(id.to_string()))?;

        for backend in &active.backends {
            backend.thaw(&active.handle).await?;
        }
        active.handle.state = IsoboxState::Running;
        info!(isobox_id = %id, "isobox thawed");
        Ok(())
    }

    /// Snapshot an isobox to disk.
    pub async fn snapshot(&self, id: &IsoboxId, path: &std::path::Path) -> Result<()> {
        let reg = self.registry.read().await;
        let active = reg.get(id).ok_or_else(|| IsolateError::IsoboxNotFound(id.to_string()))?;

        tokio::fs::create_dir_all(path).await?;
        for backend in &active.backends {
            let backend_path = path.join(backend.name());
            tokio::fs::create_dir_all(&backend_path).await?;
            backend.snapshot(&active.handle, &backend_path).await?;
        }
        Ok(())
    }

    /// Gracefully stop an isobox.
    pub async fn stop(&self, id: &IsoboxId) -> Result<()> {
        let active = {
            let mut reg = self.registry.write().await;
            reg.remove(id).ok_or_else(|| IsolateError::IsoboxNotFound(id.to_string()))?
        };

        info!(isobox_id = %id, "stopping isobox");
        for backend in &active.backends {
            if let Err(e) = backend.destroy(active.handle.clone()).await {
                warn!(backend = backend.name(), error = %e, "backend destroy error during stop");
            }
        }
        Ok(())
    }

    /// Emergency immediate kill. Used by the paladin.
    pub async fn kill_immediate(&self, id: &IsoboxId) -> Result<()> {
        let active = {
            let mut reg = self.registry.write().await;
            reg.remove(id).ok_or_else(|| IsolateError::IsoboxNotFound(id.to_string()))?
        };

        info!(isobox_id = %id, "IMMEDIATE KILL by paladin");
        for backend in &active.backends {
            if let Err(e) = backend.kill_immediate(&active.handle).await {
                error!(backend = backend.name(), error = %e, "kill_immediate failed");
            }
        }
        Ok(())
    }

    /// List all active isobox IDs.
    pub async fn list(&self) -> Vec<IsoboxId> {
        self.registry.read().await.keys().cloned().collect()
    }

    /// Get state of a specific isobox.
    pub async fn state(&self, id: &IsoboxId) -> Option<IsoboxState> {
        self.registry.read().await.get(id).map(|a| a.handle.state)
    }

    /// Get config of a specific isobox.
    pub async fn config(&self, id: &IsoboxId) -> Option<IsoboxConfig> {
        self.registry.read().await.get(id).map(|a| a.config.clone())
    }
}
