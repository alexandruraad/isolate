use crate::id::IsoboxId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Workload class ────────────────────────────────────────────────────────────

/// Semantic grouping of workloads for shared behavioral baselines.
/// Isoboxes with the same WorkloadClass share a baseline model.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkloadClass(pub String);

impl WorkloadClass {
    pub fn malware_analysis() -> Self { Self("malware-analysis".into()) }
    pub fn dev_environment() -> Self { Self("dev-environment".into()) }
    pub fn zero_trust_service() -> Self { Self("zero-trust-service".into()) }
    pub fn compromised_containment() -> Self { Self("compromised-containment".into()) }
    pub fn custom(s: impl Into<String>) -> Self { Self(s.into()) }
}

impl std::fmt::Display for WorkloadClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── Target ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum IsoboxTarget {
    Process {
        command: Vec<String>,
        environment: HashMap<String, String>,
        user: Option<String>,
        group: Option<String>,
        working_dir: Option<std::path::PathBuf>,
    },
    Container {
        image: String,
        command: Option<Vec<String>>,
        environment: HashMap<String, String>,
    },
    Vm {
        image: std::path::PathBuf,
        vcpus: u8,
        memory_mb: u32,
        command: Option<Vec<String>>,
    },
    WasmModule {
        module: std::path::PathBuf,
        args: Vec<String>,
        preopens: Vec<std::path::PathBuf>,
    },
}

// ── Backend kinds ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BackendKind {
    // Linux
    Ebpf,
    Seccomp,
    Landlock,
    Namespaces,
    Container,
    Kvm,
    Firecracker,
    // macOS
    EndpointSecurity,
    Seatbelt,
    VirtFramework,
    NetworkExtension,
    // Windows
    Etw,
    HyperV,
    WindowsSandbox,
    // Universal
    Wasm,
}

impl BackendKind {
    pub fn all_for_platform() -> Vec<BackendKind> {
        #[cfg(target_os = "linux")]
        return vec![
            BackendKind::Ebpf,
            BackendKind::Seccomp,
            BackendKind::Landlock,
            BackendKind::Namespaces,
        ];

        #[cfg(target_os = "macos")]
        return vec![
            BackendKind::EndpointSecurity,
            BackendKind::Seatbelt,
        ];

        #[cfg(target_os = "windows")]
        return vec![
            BackendKind::Etw,
        ];

        #[allow(unreachable_code)]
        vec![]
    }
}

impl std::fmt::Display for BackendKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            BackendKind::Ebpf => "ebpf",
            BackendKind::Seccomp => "seccomp",
            BackendKind::Landlock => "landlock",
            BackendKind::Namespaces => "namespaces",
            BackendKind::Container => "container",
            BackendKind::Kvm => "kvm",
            BackendKind::Firecracker => "firecracker",
            BackendKind::EndpointSecurity => "endpoint-security",
            BackendKind::Seatbelt => "seatbelt",
            BackendKind::VirtFramework => "virt-framework",
            BackendKind::NetworkExtension => "network-extension",
            BackendKind::Etw => "etw",
            BackendKind::HyperV => "hyperv",
            BackendKind::WindowsSandbox => "windows-sandbox",
            BackendKind::Wasm => "wasm",
        };
        write!(f, "{s}")
    }
}

// ── IsoboxConfig ──────────────────────────────────────────────────────────────

/// The complete runtime configuration for an isobox.
/// Derived from isobox.toml + CLI flags + defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsoboxConfig {
    pub id: IsoboxId,
    pub name: String,
    pub workload_class: WorkloadClass,
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub target: IsoboxTarget,
    pub backends: BackendConfig,
    pub policy: PolicyConfig,
    pub intelligence: IntelConfig,
    pub export: ExportConfig,
    pub paladin: PaladinConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    /// `None` = auto-select all available
    pub enabled: Option<Vec<BackendKind>>,
    pub ebpf: EbpfBackendConfig,
    pub vm: VmBackendConfig,
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self {
            enabled: None,
            ebpf: EbpfBackendConfig::default(),
            vm: VmBackendConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbpfBackendConfig {
    pub ringbuf_size_mb: u32,
    pub capture_syscall_args: bool,
}

impl Default for EbpfBackendConfig {
    fn default() -> Self {
        Self { ringbuf_size_mb: 8, capture_syscall_args: true }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VmBackendConfig {
    pub enabled: bool,
    pub vmm: Option<String>,
    pub vcpus: Option<u8>,
    pub memory_mb: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub version: String,
    pub default_action: EnforcementAction,
    pub auto_harden: bool,
    pub network: NetworkPolicy,
    pub filesystem: FilesystemPolicy,
    pub syscalls: SyscallPolicy,
    pub process: ProcessPolicy,
    pub rules: Vec<PolicyRule>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            version: "1.0".into(),
            default_action: EnforcementAction::Audit,
            auto_harden: false,
            network: NetworkPolicy::default(),
            filesystem: FilesystemPolicy::default(),
            syscalls: SyscallPolicy::default(),
            process: ProcessPolicy::default(),
            rules: vec![],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum EnforcementAction {
    #[default]
    Audit,
    Block,
    Kill,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkPolicy {
    pub default: EnforcementAction,
    pub log_allowed: bool,
    pub log_denied: bool,
    pub dns_over_https: bool,
    pub allow: Vec<NetworkRule>,
    pub deny: Vec<NetworkRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkRule {
    pub dst: Option<String>,
    pub port: Option<u16>,
    pub proto: Option<String>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FilesystemPolicy {
    pub default: EnforcementAction,
    pub read_only: Vec<std::path::PathBuf>,
    pub read_write: Vec<std::path::PathBuf>,
    pub deny: Vec<std::path::PathBuf>,
    pub no_exec: Vec<std::path::PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SyscallPolicy {
    pub mode: SyscallMode,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SyscallMode {
    #[default]
    Denylist,
    Allowlist,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessPolicy {
    pub allow_fork: bool,
    pub allow_exec: bool,
    pub allow_network_namespace: bool,
    pub allow_user_namespace: bool,
    pub allow_ptrace: bool,
    pub max_processes: Option<u32>,
    pub max_open_files: Option<u32>,
    pub max_memory_mb: Option<u32>,
    pub max_cpu_percent: Option<f32>,
}

impl Default for ProcessPolicy {
    fn default() -> Self {
        Self {
            allow_fork: true,
            allow_exec: false,
            allow_network_namespace: false,
            allow_user_namespace: false,
            allow_ptrace: false,
            max_processes: Some(64),
            max_open_files: Some(1024),
            max_memory_mb: Some(512),
            max_cpu_percent: Some(50.0),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub name: String,
    pub condition: String, // CEL expression
    pub action: EnforcementAction,
    pub notify: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelConfig {
    pub enabled: bool,
    pub anomaly_threshold: f32,
    pub alert_on_ioc_match: bool,
    pub baseline_warmup_minutes: u32,
    pub threat_feeds: Vec<String>,
    pub on_anomaly: AnomalyResponse,
}

impl Default for IntelConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            anomaly_threshold: 0.75,
            alert_on_ioc_match: true,
            baseline_warmup_minutes: 10,
            threat_feeds: vec![],
            on_anomaly: AnomalyResponse::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AnomalyResponse {
    pub action: EnforcementAction,
    pub notify: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExportConfig {
    pub formats: Vec<String>,
    pub output_dir: Option<std::path::PathBuf>,
    pub auto_export_on_alert: bool,
}

/// Paladin-specific configuration embedded in each isobox config.
/// Controls when the paladin takes autonomous action for this isobox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaladinConfig {
    /// Enable paladin oversight for this isobox
    pub enabled: bool,
    /// Anomaly score that triggers automatic paladin escalation (bypasses isolatd)
    pub escalation_threshold: f32,
    /// Maximum escalation level paladin may apply autonomously (0–7)
    pub max_auto_level: u8,
    /// Require human approval for escalation beyond this level
    pub require_approval_above: u8,
    /// Out-of-band notification channels (used even if network is cut)
    pub notify_oob: Vec<String>,
    /// Dead-man's switch: if no heartbeat for this many seconds, escalate
    pub heartbeat_timeout_secs: u64,
}

impl Default for PaladinConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            escalation_threshold: 0.90,
            max_auto_level: 4, // TERMINATE by default
            require_approval_above: 5,
            notify_oob: vec!["syslog".into()],
            heartbeat_timeout_secs: 30,
        }
    }
}

// ── SandboxHandle ─────────────────────────────────────────────────────────────

/// A live reference to a running isobox's sandbox context.
/// Passed to backends for all lifecycle operations.
#[derive(Debug, Clone)]
pub struct SandboxHandle {
    pub id: IsoboxId,
    /// OS-level process group / cgroup path / VM ID per backend
    pub backend_handles: HashMap<BackendKind, BackendHandle>,
    pub started_at: DateTime<Utc>,
    pub state: IsoboxState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendHandle {
    pub kind: BackendKind,
    /// Backend-specific opaque data (e.g., cgroup path, VM UUID, BPF prog fd)
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IsoboxState {
    Starting,
    Running,
    Frozen,
    Stopping,
    Stopped,
    Killed,
    Error,
}

impl std::fmt::Display for IsoboxState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Starting  => "starting",
            Self::Running   => "running",
            Self::Frozen    => "frozen",
            Self::Stopping  => "stopping",
            Self::Stopped   => "stopped",
            Self::Killed    => "killed",
            Self::Error     => "error",
        };
        write!(f, "{s}")
    }
}

// ── PolicyUpdate ──────────────────────────────────────────────────────────────

/// An incremental policy change, applied to a running isobox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyUpdate {
    pub isobox_id: IsoboxId,
    pub author: PolicyUpdateAuthor,
    pub changes: Vec<PolicyChange>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyUpdateAuthor {
    Human { user: String },
    AutoHardener,
    Paladin { level: u8 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyChange {
    SetDefaultAction(EnforcementAction),
    AddNetworkRule(NetworkRule),
    RemoveNetworkRule(NetworkRule),
    AddFilesystemDeny(std::path::PathBuf),
    AddSyscallAllow(String),
    SetSyscallMode(SyscallMode),
    SetMaxMemoryMb(u32),
    SetMaxCpuPercent(f32),
}
