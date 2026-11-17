//! isolate-events — Unified event schema, EventBus, and fan-out routing
//!
//! All platform backends emit events. This crate normalizes them into a
//! single `IsolateEvent` enum and fans them out via the `EventBus`.

pub mod bus;
pub mod event;
pub mod stream;

pub use bus::EventBus;
pub use event::{
    Alert, AlertSeverity, ExecEvent, FileEvent, FileOp, IsolateEvent, NetworkDirection,
    NetworkEvent, ProcessEvent, SyscallEvent,
};
pub use stream::EventStream;
