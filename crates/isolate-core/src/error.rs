use thiserror::Error;

pub type Result<T, E = IsolateError> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum IsolateError {
    // ── Configuration ───────────────────────────────────────────────────────
    #[error("configuration error: {0}")]
    Config(String),

    #[error("policy validation error: {0}")]
    PolicyValidation(String),

    // ── Backend / sandbox ────────────────────────────────────────────────────
    #[error("backend '{backend}' not available on this platform: {reason}")]
    BackendUnavailable { backend: String, reason: String },

    #[error("sandbox creation failed: {0}")]
    SandboxCreate(String),

    #[error("sandbox enforcement failed: {0}")]
    SandboxEnforce(String),

    #[error("isobox not found: {0}")]
    IsoboxNotFound(String),

    #[error("isobox already exists: {0}")]
    IsoboxAlreadyExists(String),

    #[error("operation not supported in current isobox state: {0}")]
    InvalidState(String),

    // ── Intelligence ─────────────────────────────────────────────────────────
    #[error("intelligence engine error: {0}")]
    Intel(String),

    #[error("ONNX runtime error: {0}")]
    Onnx(String),

    #[error("threat feed error: {0}")]
    Feed(String),

    // ── Storage ──────────────────────────────────────────────────────────────
    #[error("storage error: {0}")]
    Store(String),

    // ── I/O ──────────────────────────────────────────────────────────────────
    #[error("I/O error: {source}")]
    Io {
        #[from]
        source: std::io::Error,
    },

    #[error("serialization error: {0}")]
    Serialization(String),

    // ── IPC / RPC ────────────────────────────────────────────────────────────
    #[error("daemon communication error: {0}")]
    DaemonComm(String),

    #[error("authentication error: {0}")]
    Auth(String),

    // ── Paladin ──────────────────────────────────────────────────────────────
    #[error("paladin escalation: level {level} — {reason}")]
    PaladinEscalation { level: u8, reason: String },

    #[error("paladin heartbeat timeout after {secs}s")]
    PaladinHeartbeatTimeout { secs: u64 },

    // ── Generic ──────────────────────────────────────────────────────────────
    #[error("internal error: {0}")]
    Internal(String),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl IsolateError {
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }
    pub fn backend_unavailable(backend: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::BackendUnavailable {
            backend: backend.into(),
            reason: reason.into(),
        }
    }
}
