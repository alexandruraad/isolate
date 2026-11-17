//! Intelligence pipeline — ingests events and routes through all plugins.

use crate::{
    anomaly::AnomalyScorer,
    baseline::BaselineProfiler,
    hardener::PolicyHardener,
    ioc::IocMatcher,
};
use isolate_core::{
    types::{IsoboxConfig, PolicyUpdate},
    id::IsoboxId,
};
use isolate_events::event::{Alert, AlertAction, AlertSeverity, IocMatch, IsolateEvent};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Actions emitted by the intelligence engine in response to events.
#[derive(Debug, Clone)]
pub enum IntelAction {
    /// Raise an alert (non-blocking)
    Alert(Alert),
    /// Suggest a policy hardening change (non-blocking)
    PolicyHardenSuggestion(PolicyUpdate),
    /// Immediately block/kill the isobox (triggers policy enforcer)
    BlockImmediate { isobox_id: IsoboxId, reason: String },
    /// Escalate to the paladin
    PaladinEscalate { isobox_id: IsoboxId, level: u8, reason: String },
}

/// The central intelligence engine. Holds all plugins and routes events.
#[derive(Clone)]
pub struct IntelEngine {
    baseline: Arc<RwLock<BaselineProfiler>>,
    anomaly: Arc<AnomalyScorer>,
    ioc: Arc<IocMatcher>,
    hardener: Arc<PolicyHardener>,
    /// Channel to send intel actions back to the daemon
    action_tx: tokio::sync::mpsc::UnboundedSender<IntelAction>,
}

impl IntelEngine {
    pub fn new(action_tx: tokio::sync::mpsc::UnboundedSender<IntelAction>) -> Self {
        Self {
            baseline: Arc::new(RwLock::new(BaselineProfiler::new())),
            anomaly: Arc::new(AnomalyScorer::new()),
            ioc: Arc::new(IocMatcher::new()),
            hardener: Arc::new(PolicyHardener::new()),
            action_tx,
        }
    }

    /// Process a single event through the full pipeline.
    pub async fn process(&self, event: &IsolateEvent, config: &IsoboxConfig) {
        // Stage 1: Update behavioral baseline
        self.baseline.write().await.ingest(event, &config.workload_class);

        // Stage 2: IOC matching
        if let Some(ioc_hit) = self.ioc.check_event(event) {
            if config.intelligence.alert_on_ioc_match {
                info!(
                    isobox_id = %event.isobox_id,
                    indicator = %ioc_hit.indicator_value,
                    feed = %ioc_hit.feed,
                    "IOC match"
                );
                let alert = Alert {
                    id: ulid::Ulid::new().to_string(),
                    timestamp: chrono::Utc::now(),
                    isobox_id: event.isobox_id.clone(),
                    severity: AlertSeverity::Critical,
                    title: format!("IOC match: {} ({})", ioc_hit.indicator_value, ioc_hit.feed),
                    detail: format!(
                        "Indicator '{}' type '{}' matched feed '{}' (confidence: {:.0}%)",
                        ioc_hit.indicator_value, ioc_hit.indicator_type,
                        ioc_hit.feed, ioc_hit.confidence * 100.0
                    ),
                    anomaly_score: None,
                    ioc_match: Some(ioc_hit.clone()),
                    triggering_event: Some(Box::new(event.clone())),
                    action_taken: AlertAction::Logged,
                    paladin_level: None,
                };
                let _ = self.action_tx.send(IntelAction::Alert(alert));
            }
        }

        // Stage 3: Anomaly scoring (async, may be slow — don't block pipeline)
        let baseline_guard = self.baseline.read().await;
        let anomaly_score = self.anomaly.score(event, &*baseline_guard).await;
        drop(baseline_guard);

        if let Some(score) = anomaly_score {
            debug!(
                isobox_id = %event.isobox_id,
                score,
                threshold = config.intelligence.anomaly_threshold,
                "anomaly score"
            );

            if score >= config.intelligence.anomaly_threshold {
                warn!(
                    isobox_id = %event.isobox_id,
                    score,
                    "anomaly threshold exceeded"
                );

                let alert = Alert {
                    id: ulid::Ulid::new().to_string(),
                    timestamp: chrono::Utc::now(),
                    isobox_id: event.isobox_id.clone(),
                    severity: if score >= 0.90 {
                        AlertSeverity::Critical
                    } else {
                        AlertSeverity::Warn
                    },
                    title: format!("Anomaly detected (score: {:.2})", score),
                    detail: format!(
                        "Behavioral anomaly score {:.2} exceeded threshold {:.2}",
                        score, config.intelligence.anomaly_threshold
                    ),
                    anomaly_score: Some(score),
                    ioc_match: None,
                    triggering_event: Some(Box::new(event.clone())),
                    action_taken: AlertAction::Logged,
                    paladin_level: None,
                };
                let _ = self.action_tx.send(IntelAction::Alert(alert));

                // Check paladin escalation threshold
                if score >= config.paladin.escalation_threshold && config.paladin.enabled {
                    let _ = self.action_tx.send(IntelAction::PaladinEscalate {
                        isobox_id: event.isobox_id.clone(),
                        level: 1, // Start at ALERT; paladin decides next steps
                        reason: format!("Anomaly score {:.2} exceeded paladin threshold {:.2}",
                            score, config.paladin.escalation_threshold),
                    });
                }
            }
        }

        // Stage 4: Hardening advisor (background, non-blocking)
        // Clone Arc to avoid holding a borrow across the spawn boundary
        {
            let baseline_arc = Arc::clone(&self.baseline);
            let hardener = self.hardener.clone();
            let config = config.clone();
            let tx = self.action_tx.clone();
            tokio::spawn(async move {
                let baseline_guard = baseline_arc.read().await;
                if let Some(suggestion) = hardener.suggest(&config, &*baseline_guard).await {
                    let _ = tx.send(IntelAction::PolicyHardenSuggestion(suggestion));
                }
            });
        }
    }

    /// Reload IOC tables from updated feeds (zero-downtime swap).
    pub async fn reload_ioc_tables(&self) {
        self.ioc.reload().await;
        info!("IOC tables reloaded");
    }
}
