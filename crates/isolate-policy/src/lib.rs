//! isolate-policy — Policy engine: evaluation, live enforcement, versioning.
//!
//! The policy engine:
//!   1. Evaluates CEL (Common Expression Language) rules against events
//!   2. Routes events to the correct enforcement action
//!   3. Stores all policy changes in an append-only audit log
//!   4. Applies PolicyUpdates from the auto-hardener or operators

pub mod engine;
pub mod enforcer;
pub mod versions;

pub use engine::{PolicyEngine, PolicyDecision};
pub use enforcer::PolicyEnforcer;
