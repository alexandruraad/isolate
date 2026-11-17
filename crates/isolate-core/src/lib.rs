//! isolate-core — Shared types, traits, error hierarchy, and IDs
//!
//! Every crate in the isolate workspace depends on this crate.
//! No platform-specific code lives here.

pub mod error;
pub mod id;
pub mod types;

pub use error::{IsolateError, Result};
pub use id::{IsoboxId, TraceId};
pub use types::{
    BackendKind, IsoboxConfig, IsoboxState, IsoboxTarget, PolicyUpdate, SandboxHandle,
    WorkloadClass,
};
