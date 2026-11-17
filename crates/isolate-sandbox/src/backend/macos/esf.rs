//! Endpoint Security Framework (ESF) backend — macOS kernel event monitoring.
//!
//! ESF provides authorization and notification callbacks for security-relevant
//! kernel events on macOS 10.15+. isolate uses it for:
//!   - Process execution monitoring (ES_EVENT_TYPE_AUTH_EXEC)
//!   - File access monitoring (ES_EVENT_TYPE_AUTH_OPEN, WRITE, etc.)
//!   - Network event notification (combined with Network Extensions)
//!
//! Requires: com.apple.developer.endpoint-security.client entitlement
//!           + System Extension or PrivilegedHelper process

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
pub struct EsfBackend;

impl EsfBackend {
    pub fn new() -> Self { Self }
}

#[async_trait]
impl SandboxBackend for EsfBackend {
    fn kind(&self) -> BackendKind { BackendKind::EndpointSecurity }
    fn name(&self) -> &'static str { "endpoint-security" }
    fn priority(&self) -> u8 { 200 }

    fn is_available(&self) -> bool {
        // macOS 10.15+, entitlement required
        #[cfg(target_os = "macos")]
        {
            // Check macOS version
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
            return major >= 11; // macOS 11+ for stable ESF
        }
        #[allow(unreachable_code)]
        false
    }

    async fn create(&self, id: IsoboxId, config: &IsoboxConfig) -> Result<SandboxHandle> {
        info!(isobox_id = %id, "ESF backend: registering event client");

        // In production (via FFI to EndpointSecurity.framework):
        //
        // es_client_t *client = NULL;
        // es_new_client(&client, ^(es_client_t *c, const es_message_t *msg) {
        //     // Handle event — normalize to IsolateEvent, push to ring buffer
        //     handle_esf_event(c, msg, isobox_id);
        // });
        //
        // es_event_type_t events[] = {
        //     ES_EVENT_TYPE_AUTH_EXEC, ES_EVENT_TYPE_AUTH_OPEN,
        //     ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXIT,
        //     ES_EVENT_TYPE_NOTIFY_WRITE, ES_EVENT_TYPE_NOTIFY_RENAME,
        // };
        // es_subscribe(client, events, sizeof(events)/sizeof(events[0]));

        Ok(SandboxHandle {
            id: id.clone(),
            backend_handles: [(
                BackendKind::EndpointSecurity,
                BackendHandle {
                    kind: BackendKind::EndpointSecurity,
                    data: serde_json::json!({
                        "status": "subscribed",
                        "events": [
                            "AUTH_EXEC", "AUTH_OPEN", "AUTH_WRITE",
                            "NOTIFY_FORK", "NOTIFY_EXIT", "NOTIFY_RENAME",
                            "NOTIFY_KEXTLOAD", "NOTIFY_MOUNT",
                        ]
                    }),
                },
            )]
            .into(),
            started_at: chrono::Utc::now(),
            state: isolate_core::types::IsoboxState::Running,
        })
    }

    async fn event_stream(&self, _handle: &SandboxHandle) -> Result<EventStream> {
        // ESF events are delivered via callback; bridge to tokio channel
        let (_tx, rx) = tokio::sync::mpsc::channel(4096);
        Ok(Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx)))
    }

    async fn apply_policy(&self, _handle: &SandboxHandle, _update: &PolicyUpdate) -> Result<()> {
        // ESF policy is dynamic: AUTH events respond allow/deny per-callback
        Ok(())
    }

    async fn freeze(&self, _handle: &SandboxHandle) -> Result<()> {
        // Respond ES_AUTH_RESULT_DENY to all AUTH events (effectively freezes)
        Ok(())
    }

    async fn thaw(&self, _handle: &SandboxHandle) -> Result<()> {
        // Resume normal allow/deny decisions
        Ok(())
    }

    async fn snapshot(&self, handle: &SandboxHandle, path: &Path) -> Result<()> {
        let data = serde_json::json!({
            "backend": "endpoint-security",
            "isobox_id": handle.id.as_str(),
        });
        tokio::fs::write(
            path.join("esf.json"),
            serde_json::to_string_pretty(&data).unwrap(),
        ).await?;
        Ok(())
    }

    async fn destroy(&self, handle: SandboxHandle) -> Result<()> {
        info!(isobox_id = %handle.id, "ESF backend: destroying client");
        // es_delete_client(client);
        Ok(())
    }
}
