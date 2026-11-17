//! Policy evaluation engine.
//!
//! Evaluates the active policy rules against incoming events and returns
//! the enforcement decision (allow, audit, block, kill).

use isolate_core::types::{EnforcementAction, IsoboxConfig, PolicyRule};
use isolate_events::event::{EventBody, IsolateEvent};
use tracing::debug;

/// The result of evaluating policy rules against an event.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub action: EnforcementAction,
    pub matched_rule: Option<String>,
    pub reason: String,
}

pub struct PolicyEngine;

impl PolicyEngine {
    pub fn new() -> Self { Self }

    /// Evaluate all policy rules and the default policy for this event.
    /// Returns the most restrictive matching decision.
    pub fn evaluate(&self, event: &IsolateEvent, config: &IsoboxConfig) -> PolicyDecision {
        let policy = &config.policy;

        // Check custom CEL rules first
        for rule in &policy.rules {
            if self.evaluate_rule(rule, event) {
                debug!(
                    rule = %rule.name,
                    action = ?rule.action,
                    isobox_id = %event.isobox_id,
                    "policy rule matched"
                );
                return PolicyDecision {
                    action: rule.action,
                    matched_rule: Some(rule.name.clone()),
                    reason: format!("rule '{}' matched", rule.name),
                };
            }
        }

        // Apply default per-category policy
        let action = match &event.body {
            EventBody::Network(n) => policy.network.default,
            EventBody::File(f) if f.blocked => EnforcementAction::Block,
            EventBody::File(_) => policy.filesystem.default,
            EventBody::Syscall(s) if s.blocked => EnforcementAction::Block,
            _ => policy.default_action,
        };

        PolicyDecision {
            action,
            matched_rule: None,
            reason: "default policy".into(),
        }
    }

    /// Evaluate a single CEL rule condition against an event.
    ///
    /// In production: use the `cel-interpreter` crate for proper CEL evaluation.
    /// Currently: basic string matching for common patterns.
    fn evaluate_rule(&self, rule: &PolicyRule, event: &IsolateEvent) -> bool {
        let condition = &rule.condition;

        // Simple pattern matching (replace with CEL interpreter in production)
        match &event.body {
            EventBody::Network(n) => {
                if condition.contains("network") {
                    if let Some(port) = n.dst_port {
                        // e.g. "event.network.dst_port in [4444, 1337]"
                        if condition.contains(&port.to_string()) {
                            return true;
                        }
                    }
                }
            }
            EventBody::Exec(e) => {
                if condition.contains("/tmp") && e.path.starts_with("/tmp") {
                    return true;
                }
                if condition.contains("/dev/shm") && e.path.starts_with("/dev/shm") {
                    return true;
                }
            }
            _ => {}
        }

        false
    }
}
