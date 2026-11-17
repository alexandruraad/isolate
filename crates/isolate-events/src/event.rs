use chrono::{DateTime, Utc};
use isolate_core::id::IsoboxId;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// The unified event type emitted by all isolate backends.
/// Every platform-specific raw event is normalized to this enum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolateEvent {
    /// Monotonically increasing sequence number within an isobox
    pub seq: u64,
    pub timestamp: DateTime<Utc>,
    pub isobox_id: IsoboxId,
    pub backend: String,
    pub body: EventBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventBody {
    Syscall(SyscallEvent),
    Network(NetworkEvent),
    File(FileEvent),
    Process(ProcessEvent),
    Exec(ExecEvent),
    Alert(Alert),
    /// Raw / unstructured event from a backend that doesn't fit above
    Raw { source: String, data: serde_json::Value },
}

// ── Syscall ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallEvent {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub syscall_nr: u32,
    pub syscall_name: String,
    /// Syscall arguments (up to 6), as hex strings
    pub args: [u64; 6],
    /// Return value (filled in on sys_exit)
    pub ret: Option<i64>,
    /// Whether this syscall was blocked by policy
    pub blocked: bool,
    pub comm: String, // process name (15 chars)
}

// ── Network ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub pid: u32,
    pub comm: String,
    pub direction: NetworkDirection,
    pub protocol: NetworkProtocol,
    pub src_addr: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_addr: Option<IpAddr>,
    pub dst_port: Option<u16>,
    /// Packet/segment payload length (no payload content captured)
    pub length: u32,
    /// Whether this connection was allowed or blocked by policy
    pub verdict: NetworkVerdict,
    /// IOC match info if this triggered an IOC hit
    pub ioc_match: Option<IocMatch>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkDirection { Ingress, Egress }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkProtocol { Tcp, Udp, Icmp, Icmpv6, Other }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkVerdict { Allow, Block, Drop }

// ── File ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvent {
    pub pid: u32,
    pub comm: String,
    pub op: FileOp,
    pub path: std::path::PathBuf,
    pub flags: u32,
    pub mode: Option<u32>,
    /// Whether this access was blocked by policy
    pub blocked: bool,
    /// SHA256 of the file if it was executed (from file_monitor)
    pub sha256: Option<String>,
    /// IOC match if hash matched a known malicious file
    pub ioc_match: Option<IocMatch>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileOp {
    Open,
    Read,
    Write,
    Create,
    Delete,
    Rename,
    Chmod,
    Chown,
    Execute,
    MmapExec,
}

// ── Process ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub event_type: ProcessEventType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessEventType { Fork, Clone, Exit, Signal }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub path: std::path::PathBuf,
    pub argv: Vec<String>,
    pub env: Vec<String>,
    pub sha256: Option<String>,
    pub ioc_match: Option<IocMatch>,
    pub blocked: bool,
}

// ── IOC match ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocMatch {
    pub feed: String,
    pub indicator_type: String, // "hash" | "domain" | "ip" | "url"
    pub indicator_value: String,
    pub confidence: f32,
    pub threat_type: Option<String>,
    pub reference: Option<String>,
}

// ── Alert ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub isobox_id: IsoboxId,
    pub severity: AlertSeverity,
    pub title: String,
    pub detail: String,
    pub anomaly_score: Option<f32>,
    pub ioc_match: Option<IocMatch>,
    pub triggering_event: Option<Box<IsolateEvent>>,
    pub action_taken: AlertAction,
    pub paladin_level: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity { Info, Warn, Critical, Emergency }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertAction {
    Logged,
    Blocked,
    Frozen,
    Killed,
    PaladinEscalated,
}
