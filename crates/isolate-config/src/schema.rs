use isolate_core::types::*;
use isolate_core::IsoboxConfig;
use isolate_core::id::IsoboxId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// The raw deserialized form of `isobox.toml`.
/// Field names match the TOML keys exactly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsoboxToml {
    pub isobox: IsoboxMeta,
    pub target: Option<TargetToml>,
    pub backends: Option<BackendsToml>,
    pub policy: Option<PolicyToml>,
    pub intelligence: Option<IntelToml>,
    pub export: Option<ExportToml>,
    pub paladin: Option<PaladinToml>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsoboxMeta {
    pub name: String,
    pub workload_class: Option<String>,
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum TargetToml {
    Process {
        command: Vec<String>,
        #[serde(default)]
        environment: HashMap<String, String>,
        user: Option<String>,
        group: Option<String>,
        working_dir: Option<PathBuf>,
    },
    Container {
        image: String,
        command: Option<Vec<String>>,
        #[serde(default)]
        environment: HashMap<String, String>,
    },
    Vm {
        image: PathBuf,
        #[serde(default = "default_vcpus")]
        vcpus: u8,
        #[serde(default = "default_memory_mb")]
        memory_mb: u32,
        command: Option<Vec<String>>,
    },
    WasmModule {
        module: PathBuf,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        preopens: Vec<PathBuf>,
    },
}

fn default_vcpus() -> u8 { 2 }
fn default_memory_mb() -> u32 { 1024 }

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BackendsToml {
    /// "auto" | list of backend names
    pub enabled: Option<BackendsEnabled>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BackendsEnabled {
    Auto(String), // "auto"
    List(Vec<String>),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyToml {
    pub version: Option<String>,
    pub default_action: Option<String>,
    pub auto_harden: Option<bool>,
    pub network: Option<NetworkPolicyToml>,
    pub filesystem: Option<FilesystemPolicyToml>,
    pub syscalls: Option<SyscallPolicyToml>,
    pub process: Option<ProcessPolicyToml>,
    #[serde(default)]
    pub rules: Vec<PolicyRuleToml>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkPolicyToml {
    pub default: Option<String>,
    pub log_allowed: Option<bool>,
    pub log_denied: Option<bool>,
    pub dns_over_https: Option<bool>,
    #[serde(default)]
    pub allow: Vec<NetworkRuleToml>,
    #[serde(default)]
    pub deny: Vec<NetworkRuleToml>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkRuleToml {
    pub dst: Option<String>,
    pub port: Option<u16>,
    pub proto: Option<String>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FilesystemPolicyToml {
    pub default: Option<String>,
    #[serde(default)]
    pub read_only: Vec<PathBuf>,
    #[serde(default)]
    pub read_write: Vec<PathBuf>,
    #[serde(default)]
    pub deny: Vec<PathBuf>,
    #[serde(default)]
    pub no_exec: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SyscallPolicyToml {
    pub mode: Option<String>,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProcessPolicyToml {
    pub allow_fork: Option<bool>,
    pub allow_exec: Option<bool>,
    pub allow_network_namespace: Option<bool>,
    pub allow_user_namespace: Option<bool>,
    pub allow_ptrace: Option<bool>,
    pub max_processes: Option<u32>,
    pub max_open_files: Option<u32>,
    pub max_memory_mb: Option<u32>,
    pub max_cpu_percent: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRuleToml {
    pub name: String,
    pub condition: String,
    pub action: String,
    #[serde(default)]
    pub notify: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IntelToml {
    pub enabled: Option<bool>,
    pub anomaly_threshold: Option<f32>,
    pub alert_on_ioc_match: Option<bool>,
    pub baseline_warmup_minutes: Option<u32>,
    #[serde(default)]
    pub threat_feeds: Vec<String>,
    pub on_anomaly: Option<AnomalyResponseToml>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AnomalyResponseToml {
    pub action: Option<String>,
    #[serde(default)]
    pub notify: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExportToml {
    #[serde(default)]
    pub formats: Vec<String>,
    pub output_dir: Option<PathBuf>,
    pub auto_export_on_alert: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PaladinToml {
    pub enabled: Option<bool>,
    pub escalation_threshold: Option<f32>,
    pub max_auto_level: Option<u8>,
    pub require_approval_above: Option<u8>,
    #[serde(default)]
    pub notify_oob: Vec<String>,
    pub heartbeat_timeout_secs: Option<u64>,
}

// ── Conversion to IsoboxConfig ────────────────────────────────────────────────

fn default_isobox_config(id: IsoboxId, name: &str) -> IsoboxConfig {
    IsoboxConfig {
        id,
        name: name.to_owned(),
        workload_class: WorkloadClass::custom("generic"),
        description: None,
        tags: vec![],
        target: IsoboxTarget::Process {
            command: vec![],
            environment: HashMap::new(),
            user: None,
            group: None,
            working_dir: None,
        },
        backends: BackendConfig::default(),
        policy: PolicyConfig::default(),
        intelligence: IntelConfig::default(),
        export: ExportConfig::default(),
        paladin: PaladinConfig::default(),
    }
}

impl IsoboxToml {
    pub fn into_config(self, id: IsoboxId) -> IsoboxConfig {
        let defaults = default_isobox_config(id.clone(), &self.isobox.name);

        IsoboxConfig {
            id,
            name: self.isobox.name,
            workload_class: WorkloadClass::custom(
                self.isobox.workload_class.unwrap_or_else(|| "generic".into()),
            ),
            description: self.isobox.description,
            tags: self.isobox.tags,
            target: self.target.map(Into::into).unwrap_or(defaults.target),
            backends: self.backends.map(Into::into).unwrap_or(defaults.backends),
            policy: self.policy.map(Into::into).unwrap_or(defaults.policy),
            intelligence: self.intelligence.map(Into::into).unwrap_or(defaults.intelligence),
            export: self.export.map(Into::into).unwrap_or(defaults.export),
            paladin: self.paladin.map(Into::into).unwrap_or(defaults.paladin),
        }
    }
}

impl From<TargetToml> for IsoboxTarget {
    fn from(t: TargetToml) -> Self {
        match t {
            TargetToml::Process { command, environment, user, group, working_dir } =>
                IsoboxTarget::Process { command, environment, user, group, working_dir },
            TargetToml::Container { image, command, environment } =>
                IsoboxTarget::Container { image, command, environment },
            TargetToml::Vm { image, vcpus, memory_mb, command } =>
                IsoboxTarget::Vm { image, vcpus, memory_mb, command },
            TargetToml::WasmModule { module, args, preopens } =>
                IsoboxTarget::WasmModule { module, args, preopens },
        }
    }
}

impl From<BackendsToml> for BackendConfig {
    fn from(b: BackendsToml) -> Self {
        let enabled = b.enabled.and_then(|e| match e {
            BackendsEnabled::Auto(s) if s == "auto" => None,
            BackendsEnabled::Auto(_) => None,
            BackendsEnabled::List(names) => Some(
                names.iter().filter_map(|n| parse_backend_kind(n)).collect()
            ),
        });
        BackendConfig { enabled, ..Default::default() }
    }
}

fn parse_backend_kind(s: &str) -> Option<BackendKind> {
    match s {
        "ebpf" => Some(BackendKind::Ebpf),
        "seccomp" => Some(BackendKind::Seccomp),
        "landlock" => Some(BackendKind::Landlock),
        "namespaces" => Some(BackendKind::Namespaces),
        "container" => Some(BackendKind::Container),
        "kvm" => Some(BackendKind::Kvm),
        "firecracker" => Some(BackendKind::Firecracker),
        "esf" | "endpoint-security" => Some(BackendKind::EndpointSecurity),
        "seatbelt" => Some(BackendKind::Seatbelt),
        "virt-framework" => Some(BackendKind::VirtFramework),
        "network-extension" => Some(BackendKind::NetworkExtension),
        "etw" => Some(BackendKind::Etw),
        "hyperv" => Some(BackendKind::HyperV),
        "windows-sandbox" => Some(BackendKind::WindowsSandbox),
        "wasm" => Some(BackendKind::Wasm),
        _ => None,
    }
}

impl From<PolicyToml> for PolicyConfig {
    fn from(p: PolicyToml) -> Self {
        let mut cfg = PolicyConfig::default();
        if let Some(v) = p.version { cfg.version = v; }
        if let Some(a) = p.default_action { cfg.default_action = parse_action(&a); }
        if let Some(h) = p.auto_harden { cfg.auto_harden = h; }
        if let Some(n) = p.network { cfg.network = n.into(); }
        if let Some(f) = p.filesystem { cfg.filesystem = f.into(); }
        if let Some(s) = p.syscalls { cfg.syscalls = s.into(); }
        if let Some(pr) = p.process { cfg.process = pr.into(); }
        cfg.rules = p.rules.into_iter().map(Into::into).collect();
        cfg
    }
}

fn parse_action(s: &str) -> EnforcementAction {
    match s {
        "block" => EnforcementAction::Block,
        "kill" => EnforcementAction::Kill,
        _ => EnforcementAction::Audit,
    }
}

impl From<NetworkPolicyToml> for NetworkPolicy {
    fn from(n: NetworkPolicyToml) -> Self {
        NetworkPolicy {
            default: n.default.map(|s| parse_action(&s)).unwrap_or_default(),
            log_allowed: n.log_allowed.unwrap_or(true),
            log_denied: n.log_denied.unwrap_or(true),
            dns_over_https: n.dns_over_https.unwrap_or(false),
            allow: n.allow.into_iter().map(|r| NetworkRule {
                dst: r.dst, port: r.port, proto: r.proto, comment: r.comment,
            }).collect(),
            deny: n.deny.into_iter().map(|r| NetworkRule {
                dst: r.dst, port: r.port, proto: r.proto, comment: r.comment,
            }).collect(),
        }
    }
}

impl From<FilesystemPolicyToml> for FilesystemPolicy {
    fn from(f: FilesystemPolicyToml) -> Self {
        FilesystemPolicy {
            default: f.default.map(|s| parse_action(&s)).unwrap_or_default(),
            read_only: f.read_only,
            read_write: f.read_write,
            deny: f.deny,
            no_exec: f.no_exec,
        }
    }
}

impl From<SyscallPolicyToml> for SyscallPolicy {
    fn from(s: SyscallPolicyToml) -> Self {
        SyscallPolicy {
            mode: match s.mode.as_deref() {
                Some("allowlist") => SyscallMode::Allowlist,
                _ => SyscallMode::Denylist,
            },
            allow: s.allow,
            deny: s.deny,
        }
    }
}

impl From<ProcessPolicyToml> for ProcessPolicy {
    fn from(p: ProcessPolicyToml) -> Self {
        let d = ProcessPolicy::default();
        ProcessPolicy {
            allow_fork: p.allow_fork.unwrap_or(d.allow_fork),
            allow_exec: p.allow_exec.unwrap_or(d.allow_exec),
            allow_network_namespace: p.allow_network_namespace.unwrap_or(d.allow_network_namespace),
            allow_user_namespace: p.allow_user_namespace.unwrap_or(d.allow_user_namespace),
            allow_ptrace: p.allow_ptrace.unwrap_or(d.allow_ptrace),
            max_processes: p.max_processes.or(d.max_processes),
            max_open_files: p.max_open_files.or(d.max_open_files),
            max_memory_mb: p.max_memory_mb.or(d.max_memory_mb),
            max_cpu_percent: p.max_cpu_percent.or(d.max_cpu_percent),
        }
    }
}

impl From<PolicyRuleToml> for PolicyRule {
    fn from(r: PolicyRuleToml) -> Self {
        PolicyRule {
            name: r.name,
            condition: r.condition,
            action: parse_action(&r.action),
            notify: r.notify,
        }
    }
}

impl From<IntelToml> for IntelConfig {
    fn from(i: IntelToml) -> Self {
        let d = IntelConfig::default();
        IntelConfig {
            enabled: i.enabled.unwrap_or(d.enabled),
            anomaly_threshold: i.anomaly_threshold.unwrap_or(d.anomaly_threshold),
            alert_on_ioc_match: i.alert_on_ioc_match.unwrap_or(d.alert_on_ioc_match),
            baseline_warmup_minutes: i.baseline_warmup_minutes.unwrap_or(d.baseline_warmup_minutes),
            threat_feeds: i.threat_feeds,
            on_anomaly: i.on_anomaly.map(|a| AnomalyResponse {
                action: a.action.map(|s| parse_action(&s)).unwrap_or_default(),
                notify: a.notify,
            }).unwrap_or_default(),
        }
    }
}

impl From<ExportToml> for ExportConfig {
    fn from(e: ExportToml) -> Self {
        ExportConfig {
            formats: e.formats,
            output_dir: e.output_dir,
            auto_export_on_alert: e.auto_export_on_alert.unwrap_or(false),
        }
    }
}

impl From<PaladinToml> for PaladinConfig {
    fn from(p: PaladinToml) -> Self {
        let d = PaladinConfig::default();
        PaladinConfig {
            enabled: p.enabled.unwrap_or(d.enabled),
            escalation_threshold: p.escalation_threshold.unwrap_or(d.escalation_threshold),
            max_auto_level: p.max_auto_level.unwrap_or(d.max_auto_level),
            require_approval_above: p.require_approval_above.unwrap_or(d.require_approval_above),
            notify_oob: if p.notify_oob.is_empty() { d.notify_oob } else { p.notify_oob },
            heartbeat_timeout_secs: p.heartbeat_timeout_secs.unwrap_or(d.heartbeat_timeout_secs),
        }
    }
}

/// Daemon-level configuration (isolatd)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    pub daemon: DaemonSection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonSection {
    #[serde(default = "default_grpc_addr")]
    pub grpc_addr: String,
    #[serde(default = "default_rest_addr")]
    pub rest_addr: String,
    #[serde(default = "default_ws_addr")]
    pub ws_addr: String,
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub paladin_socket: Option<PathBuf>,
}

fn default_grpc_addr() -> String { "127.0.0.1:7777".into() }
fn default_rest_addr() -> String { "127.0.0.1:7778".into() }
fn default_ws_addr() -> String { "127.0.0.1:7779".into() }
fn default_data_dir() -> PathBuf { PathBuf::from("/var/lib/isolate") }
