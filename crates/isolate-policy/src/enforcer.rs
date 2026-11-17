//! Policy enforcer — acts on PolicyDecisions in real time.
//!
//! The enforcer receives decisions from the PolicyEngine and routes them
//! to the appropriate response: log, block (via backend), kill, or
//! escalate to paladin.

use super::engine::{PolicyDecision, PolicyEngine};
use isolate_core::{
    types::{EnforcementAction, IsoboxConfig},
    id::IsoboxId,
};
use isolate_events::event::IsolateEvent;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, warn, error};

/// Actions the enforcer can request from the daemon.
#[derive(Debug)]
pub enum EnforcerAction {
    Log { isobox_id: IsoboxId, reason: String },
    Block { isobox_id: IsoboxId, reason: String },
    Kill { isobox_id: IsoboxId, reason: String },
    PaladinEscalate { isobox_id: IsoboxId, level: u8, reason: String },
}

pub struct PolicyEnforcer {
    engine: PolicyEngine,
    action_tx: mpsc::UnboundedSender<EnforcerAction>,
}

impl PolicyEnforcer {
    pub fn new(action_tx: mpsc::UnboundedSender<EnforcerAction>) -> Self {
        Self {
            engine: PolicyEngine::new(),
            action_tx,
        }
    }

    /// Process an event: evaluate policy, emit enforcement action.
    pub fn process(&self, event: &IsolateEvent, config: &IsoboxConfig) {
        let decision = self.engine.evaluate(event, config);

        match decision.action {
            EnforcementAction::Audit => {
                debug!(
                    isobox_id = %event.isobox_id,
                    reason = %decision.reason,
                    "policy: audit"
                );
            }

            EnforcementAction::Block => {
                warn!(
                    isobox_id = %event.isobox_id,
                    rule = ?decision.matched_rule,
                    reason = %decision.reason,
                    "policy: BLOCK"
                );
                let _ = self.action_tx.send(EnforcerAction::Block {
                    isobox_id: event.isobox_id.clone(),
                    reason: decision.reason,
                });
            }

            EnforcementAction::Kill => {
                error!(
                    isobox_id = %event.isobox_id,
                    rule = ?decision.matched_rule,
                    reason = %decision.reason,
                    "policy: KILL"
                );
                let _ = self.action_tx.send(EnforcerAction::Kill {
                    isobox_id: event.isobox_id.clone(),
                    reason: decision.reason,
                });
            }
        }
    }
}
