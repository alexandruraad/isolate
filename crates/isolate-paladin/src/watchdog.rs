//! Watchdog — dead-man's switch for isolatd.
//!
//! isolatd must send a heartbeat to the paladin's Unix socket every N seconds.
//! If the heartbeat stops (isolatd crashed, hung, or compromised), the watchdog
//! triggers escalation at the configured level.
//!
//! This is the primary mechanism ensuring the paladin acts even when
//! the main daemon is dead.

use crate::{
    escalation::{EscalationEngine, EscalationSource, EscalationTrigger},
    PaladinDaemonConfig,
};
use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::net::UnixListener;
use tracing::{error, info, warn};

/// A heartbeat message from isolatd.
#[derive(Debug, Serialize, Deserialize)]
pub struct Heartbeat {
    pub daemon_version: String,
    pub active_isoboxes: Vec<String>,
    pub timestamp: chrono::DateTime<Utc>,
    /// Optional: daemon-triggered escalation request
    pub escalate: Option<EscalationRequest>,
}

/// Escalation request sent from isolatd to paladin (for severe situations).
#[derive(Debug, Serialize, Deserialize)]
pub struct EscalationRequest {
    pub isobox_id: String,
    pub level: u8,
    pub reason: String,
    pub anomaly_score: Option<f32>,
}

pub struct Watchdog {
    config: PaladinDaemonConfig,
}

impl Watchdog {
    pub fn new(config: PaladinDaemonConfig) -> Self {
        Self { config }
    }

    pub async fn run(self) -> Result<()> {
        // Bind to Unix socket
        let socket_path = &self.config.socket_path;

        // Remove stale socket
        if socket_path.exists() {
            tokio::fs::remove_file(socket_path).await?;
        }

        // Ensure parent directory exists
        if let Some(parent) = socket_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let listener = UnixListener::bind(socket_path)?;
        info!(socket = %socket_path.display(), "paladin watchdog listening");

        let timeout = tokio::time::Duration::from_secs(self.config.heartbeat_timeout_secs);
        let engine = EscalationEngine::new(self.config.clone());

        loop {
            // Wait for a heartbeat with a deadline
            let accept_result = tokio::time::timeout(timeout, listener.accept()).await;

            match accept_result {
                Ok(Ok((stream, _addr))) => {
                    // Read heartbeat message
                    let mut buf = vec![0u8; 4096];
                    let n = tokio::io::AsyncReadExt::read(
                        &mut tokio::io::BufReader::new(stream),
                        &mut buf,
                    ).await.unwrap_or(0);

                    if let Ok(hb) = serde_json::from_slice::<Heartbeat>(&buf[..n]) {
                        info!(
                            daemon_version = %hb.daemon_version,
                            isoboxes = hb.active_isoboxes.len(),
                            "heartbeat received"
                        );

                        // Check if isolatd is requesting escalation
                        if let Some(req) = hb.escalate {
                            warn!(
                                isobox_id = %req.isobox_id,
                                level = req.level,
                                reason = %req.reason,
                                "isolatd requesting paladin escalation"
                            );
                            let trigger = EscalationTrigger {
                                isobox_id: Some(req.isobox_id),
                                source: EscalationSource::AnomalyScore,
                                reason: req.reason,
                                anomaly_score: req.anomaly_score,
                                timestamp: Utc::now(),
                            };
                            engine.escalate(trigger, req.level).await;
                        }
                    } else {
                        warn!("received malformed heartbeat — ignoring");
                    }
                }

                Ok(Err(e)) => {
                    error!(?e, "watchdog accept error");
                }

                Err(_timeout) => {
                    // HEARTBEAT TIMEOUT — isolatd is presumed dead or compromised
                    error!(
                        timeout_secs = self.config.heartbeat_timeout_secs,
                        "PALADIN: heartbeat timeout — isolatd presumed compromised"
                    );

                    let trigger = EscalationTrigger {
                        isobox_id: None, // Apply to all isoboxes
                        source: EscalationSource::HeartbeatTimeout,
                        reason: format!(
                            "No heartbeat from isolatd for {}s — daemon presumed compromised",
                            self.config.heartbeat_timeout_secs
                        ),
                        anomaly_score: None,
                        timestamp: Utc::now(),
                    };

                    // Start at level 2 (CONTAIN) on heartbeat timeout —
                    // isolatd may have crashed for non-malicious reasons
                    engine.escalate(trigger, 2).await;
                }
            }
        }
    }
}
