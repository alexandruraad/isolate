//! isolate-sandbox — Sandbox engine with trait-based, platform-agnostic backends
//!
//! The `SandboxEngine` orchestrates multiple backends simultaneously on a
//! single isobox, composing their isolation primitives layer by layer.

pub mod backend;
pub mod engine;

pub use backend::SandboxBackend;
pub use engine::SandboxEngine;
