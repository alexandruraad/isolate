# isobox.toml — Complete Configuration Reference

This document is the authoritative reference for all fields in `isobox.toml`.
For annotated examples see `isobox.toml.example` and the `policy/` directory.

---

## `[isobox]`

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `name` | string | yes | — | Human-readable name. Appears in logs, TUI, and REST API |
| `workload_class` | string | no | `"custom"` | Groups baselines. Use one of the built-ins or a custom tag |
| `description` | string | no | `""` | Free-text note stored in SQLite |

Built-in workload classes: `malware-analysis`, `microservice`, `dev-environment`,
`build-tool`, `browser`, `database`, `compromised`.

---

## `[isobox.target]`

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `type` | enum | yes | `"process"` | `process` \| `container` \| `vm` \| `wasm-module` |
| `command` | `[string]` | for process/wasm | — | Argv; first element is the executable path |
| `user` | string | no | caller | User to run as |
| `group` | string | no | caller | Group to run as |
| `working_dir` | string | no | `/` | CWD inside the isobox |
| `env` | `{string: string}` | no | `{}` | Environment variables |
| `inherit_env` | bool | no | `false` | If true, inherit parent env before applying `env` overrides |
| `image` | string | for container | — | OCI image reference (e.g. `ubuntu:24.04`) |
| `kernel` | string | for vm | — | Path to guest kernel binary |
| `rootfs` | string | for vm | — | Path to guest rootfs ext4 image |
| `vcpus` | uint | for vm | `1` | vCPU count |
| `memory_mb` | uint | for vm | `256` | Guest memory in MiB |
| `module_path` | string | for wasm | — | Path to `.wasm` file |
| `wasi_preopens` | `[string]` | for wasm | `[]` | Host→guest path mappings (`host:guest`) |

---

## `[isobox.backends]`

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `enabled` | `[string]` | no | auto | Backends to layer. If unset, all available backends are used |

Available backend names (platform-dependent):

**Linux**: `ebpf`, `seccomp`, `landlock`, `namespace`, `container`, `kvm`
**macOS**: `esf`, `seatbelt`, `virt-framework`, `netex`
**Windows**: `etw`, `hyperv`, `winsandbox`, `wsl2`
**Cross-platform**: `wasm`

---

## `[isobox.policy]`

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `version` | string | no | `"1.0"` | Policy schema version |
| `default_action` | enum | no | `"audit"` | `audit` \| `block` \| `kill` |
| `auto_harden` | bool | no | `false` | Auto-apply hardening suggestions after baseline warmup |

---

## `[isobox.policy.network]`

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `default` | enum | no | `"audit"` | `audit` \| `block` |
| `dns_over_https` | bool | no | `false` | Force all DNS via DoH; block raw UDP/53 |
| `allow` | `[NetworkRule]` | no | `[]` | Outbound allowlist entries |
| `inbound_allow` | `[NetworkRule]` | no | `[]` | Inbound allowlist entries |

**NetworkRule fields:**

| Field | Type | Description |
|-------|------|-------------|
| `dst` | string | CIDR (e.g. `"8.8.8.8/32"`, `"10.0.0.0/8"`, `"0.0.0.0/0"`) |
| `src` | string | Source CIDR (for inbound rules) |
| `port` | uint16 | Port number (0 = any) |
| `proto` | string | `"tcp"` \| `"udp"` \| `"icmp"` \| `"any"` |
| `comment` | string | Optional note |

---

## `[isobox.policy.filesystem]`

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `default` | enum | no | `"audit"` | `audit` \| `deny` |
| `read_only` | `[string]` | no | `[]` | Paths the isobox may read but not write |
| `read_write` | `[string]` | no | `[]` | Paths with full read/write access |
| `deny` | `[string]` | no | `[]` | Paths that are explicitly blocked (overrides allow rules) |

Paths support glob patterns on macOS Seatbelt; exact prefix matching on Linux Landlock.

---

## `[isobox.policy.syscalls]`

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `mode` | enum | no | `"denylist"` | `allowlist` \| `denylist` |
| `allow` | `[string]` | for allowlist | `[]` | Syscall names to permit |
| `deny` | `[string]` | for denylist | `[]` | Syscall names to block |

Syscall names follow Linux `man 2` naming (e.g. `openat`, `socket`, `ptrace`).
For allowlist mode, a minimal safe set is pre-seeded by `seccomp::minimal_allowlist()`.

---

## `[isobox.policy.process]`

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `allow_fork` | bool | no | `true` | Allow child process creation (fork/clone) |
| `allow_exec` | bool | no | `true` | Allow `execve` / `execveat` |
| `allow_network_namespace` | bool | no | `false` | Allow `unshare(CLONE_NEWNET)` |

---

## `[isobox.intelligence]`

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `anomaly_threshold` | float | no | `0.75` | Score [0.0–1.0] above which an alert fires |
| `alert_on_ioc_match` | bool | no | `true` | Emit alert when IOC is matched |
| `threat_feeds` | `[string]` | no | all built-ins | Feed names to use for IOC matching |
| `baseline_warmup_minutes` | uint | no | `10` | Minutes before baseline is "warm" |

**Built-in feed names:** `abusech-urlhaus`, `abusech-malwarebazaar`, `abusech-threatfox`

---

## `[isobox.intelligence.on_anomaly]`

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `action` | enum | no | `"alert"` | `alert` \| `freeze` \| `kill` |
| `notify` | `[string]` | no | `["log"]` | Notification channels |

**Notification channel formats:**
- `"log"` — isolatd structured log (tracing/JSON)
- `"syslog"` — kernel ring buffer via `/dev/kmsg`
- `"stderr"` — isolatd's stderr
- `"webhook:<url>"` — HTTP POST JSON payload to `<url>` (5s timeout)
- `"serial:<device>"` — write to serial port (e.g. `"serial:/dev/ttyS0"`)

---

## `[isobox.export]`

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `formats` | `[string]` | no | `["json"]` | `json` \| `pcap` \| `stix` \| `zip` |
| `output_dir` | string | no | `/tmp/isolate-exports` | Directory for exported bundles |

---

## `[isobox.paladin]`

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `enabled` | bool | no | `false` | Enable paladin watchdog for this isobox |
| `escalation_threshold` | float | no | `0.90` | Score above which paladin escalates |
| `max_auto_level` | uint8 | no | `3` | Highest level paladin reaches without human approval (0–7) |
| `require_approval_above` | uint8 | no | `4` | Levels above this require human sign-off |
| `heartbeat_timeout_secs` | uint64 | no | `15` | Seconds before dead-man's switch triggers |
| `notify_oob` | `[string]` | no | `["log"]` | Out-of-band channels (same format as `on_anomaly.notify`) |

**Escalation levels:**

| Level | Name | Action |
|-------|------|--------|
| 0 | WATCHING | No action |
| 1 | ALERT | OOB notification |
| 2 | CONTAIN | nftables DROP all isobox traffic |
| 3 | FREEZE | `cgroup.freeze = "1"` |
| 4 | TERMINATE | `cgroup.kill = "1"` |
| 5 | SCORCH | Wipe state dirs + drop page caches |
| 6 | RAMPART | System-wide nftables lockdown |
| 7 | ABSOLUTION | Kernel panic + kdump (requires `PALADIN_ABSOLUTION_ENABLED=true`) |
