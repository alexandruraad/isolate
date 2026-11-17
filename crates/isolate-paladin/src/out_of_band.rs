//! Out-of-band notification channels.
//!
//! These channels work even when the main network is locked down (level 6+).
//! The paladin sends notifications via:
//!   - syslog (always available, kernel-logged)
//!   - serial port (if available — works even without network)
//!   - IPMI/BMC (hardware out-of-band management)
//!   - SMS via hardware modem (if configured)
//!   - Webhook (best-effort, may fail under RAMPART)

use crate::escalation::{EscalationOutcome, EscalationTrigger};
use tracing::{error, info, warn};

pub struct OutOfBand {
    channels: Vec<String>,
}

impl OutOfBand {
    pub fn new(channels: Vec<String>) -> Self {
        Self { channels }
    }

    pub async fn notify(&self, trigger: &EscalationTrigger, outcome: &EscalationOutcome) {
        let message = format!(
            "PALADIN L{} {} | isobox={} | reason={} | success={} | ts={}",
            outcome.level,
            outcome.level_name,
            trigger.isobox_id.as_deref().unwrap_or("all"),
            trigger.reason,
            outcome.success,
            outcome.timestamp.format("%Y-%m-%dT%H:%M:%SZ"),
        );

        for channel in &self.channels {
            match channel.as_str() {
                "syslog" => self.notify_syslog(&message),
                "stderr" => eprintln!("[PALADIN] {message}"),
                "log" => info!(target: "paladin::oob", "{}", message),
                ch if ch.starts_with("webhook:") => {
                    let url = &ch["webhook:".len()..];
                    self.notify_webhook(url, trigger, outcome).await;
                }
                ch if ch.starts_with("serial:") => {
                    let device = &ch["serial:".len()..];
                    self.notify_serial(device, &message).await;
                }
                unknown => {
                    warn!("unknown OOB channel: {}", unknown);
                }
            }
        }
    }

    fn notify_syslog(&self, message: &str) {
        // Write directly to /dev/log or use libc syslog
        // In production: use the `syslog` crate
        // For now: write to /dev/kmsg (kernel message ring buffer — always works)
        let kmsg_msg = format!("<2>isolate-paladin: {message}\n"); // priority 2 = critical
        let _ = std::fs::write("/dev/kmsg", kmsg_msg.as_bytes());
    }

    async fn notify_webhook(&self, url: &str, trigger: &EscalationTrigger, outcome: &EscalationOutcome) {
        let body = serde_json::json!({
            "paladin_alert": true,
            "level": outcome.level,
            "level_name": outcome.level_name,
            "isobox_id": trigger.isobox_id,
            "reason": trigger.reason,
            "source": format!("{:?}", trigger.source),
            "success": outcome.success,
            "errors": outcome.errors,
            "timestamp": outcome.timestamp,
        });

        // Best-effort — non-blocking, short timeout (network may be cut)
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_default();

        match client.post(url).json(&body).send().await {
            Ok(resp) => info!(status = %resp.status(), "OOB webhook sent"),
            Err(e) => warn!("OOB webhook failed (expected under RAMPART): {e}"),
        }
    }

    async fn notify_serial(&self, device: &str, message: &str) {
        // Write to serial port — works without any network
        if let Err(e) = tokio::fs::write(device, format!("[PALADIN] {message}\n").as_bytes()).await {
            warn!("serial OOB failed: {e}");
        }
    }
}
