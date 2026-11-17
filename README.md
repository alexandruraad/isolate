# isolate

> **A cross-platform, multi-layer sandboxing system. Wrap any process, container, or VM in an
> isobox — an always-watching, always-learning isolation environment that sees everything,
> enforces everything, and hardens itself over time.**

---

```
 ██╗███████╗ ██████╗ ██╗      █████╗ ████████╗███████╗
 ██║██╔════╝██╔═══██╗██║     ██╔══██╗╚══██╔══╝██╔════╝
 ██║███████╗██║   ██║██║     ███████║   ██║   █████╗
 ██║╚════██║██║   ██║██║     ██╔══██║   ██║   ██╔══╝
 ██║███████║╚██████╔╝███████╗██║  ██║   ██║   ███████╗
 ╚═╝╚══════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝
```

---

## Table of Contents

1. [What is isolate?](#what-is-isolate)
2. [What is an isobox?](#what-is-an-isobox)
3. [Feature Matrix](#feature-matrix)
4. [Quick Start](#quick-start)
5. [Architecture](#architecture)
   - [System Overview](#system-overview)
   - [Isolation Layer Stack](#isolation-layer-stack)
   - [Intelligence Pipeline](#intelligence-pipeline)
   - [Event Flow](#event-flow)
   - [Privilege Separation](#privilege-separation)
6. [Isolation Backends](#isolation-backends)
   - [Linux Backends](#linux-backends)
   - [macOS Backends](#macos-backends)
   - [Windows Backends](#windows-backends)
   - [Universal Backends](#universal-backends)
7. [Intelligence Engine](#intelligence-engine)
   - [Behavioral Baseline](#behavioral-baseline)
   - [Anomaly Detection](#anomaly-detection)
   - [IOC Matching](#ioc-matching)
   - [Threat Feed Integration](#threat-feed-integration)
   - [Policy Auto-Hardening](#policy-auto-hardening)
8. [Configuration Reference](#configuration-reference)
   - [isobox.toml Schema](#isoboxtoml-schema)
   - [Policy DSL](#policy-dsl)
   - [Backend Selection](#backend-selection)
9. [CLI Reference](#cli-reference)
10. [TUI Dashboard](#tui-dashboard)
11. [REST & gRPC API](#rest--grpc-api)
12. [Forensics & Export](#forensics--export)
13. [Building from Source](#building-from-source)
14. [Development Roadmap](#development-roadmap)
15. [Security Model](#security-model)
16. [Contributing](#contributing)
17. [Security Disclosure](#security-disclosure)
18. [License](#license)

---

## What is isolate?

**isolate** is a security-first sandboxing platform that wraps arbitrary workloads — processes,
containers, VMs, or WebAssembly modules — inside a composable isolation environment called an
**isobox**. Every available OS and hardware isolation primitive is stacked together automatically.

It solves four real problems:

| Problem | What isolate does |
|---------|------------------|
| You need to run a suspicious binary | Wraps it in full isolation, records every syscall, alerts on IOC hits |
| A host may be compromised | Containment isobox prevents lateral movement and exfiltration |
| Your dev environment is a supply-chain risk | Isolates builds so a poisoned dep can't touch your system |
| Your microservices talk too freely | Per-process zero-trust network and filesystem policy |

isolate is **not** a simple container runtime. It layers **every** applicable isolation primitive
simultaneously (eBPF + seccomp + Landlock + namespaces + Seatbelt + ESF + Virtualization.framework
+ ETW + Hyper-V + WASI), watches at kernel depth, and uses ML-assisted behavioral analysis to
detect and respond to anomalies in real time.

---

## What is an isobox?

An **isobox** is a composable isolation unit. Think of it as a security onion wrapped around a
workload:

```
┌──────────────────────────────────────────────────────────────┐
│                        isobox                                │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │               Intelligence Layer                       │  │
│  │  Behavioral baseline · Anomaly scoring · IOC matching  │  │
│  │  Threat feeds · Policy auto-hardening                  │  │
│  │                                                        │  │
│  │  ┌──────────────────────────────────────────────────┐  │  │
│  │  │              Policy Enforcement Layer            │  │  │
│  │  │  Network policy · FS policy · Syscall policy     │  │  │
│  │  │  Process policy · Resource limits                │  │  │
│  │  │                                                  │  │  │
│  │  │  ┌────────────────────────────────────────────┐  │  │  │
│  │  │  │           Isolation Backend Stack          │  │  │  │
│  │  │  │                                            │  │  │  │
│  │  │  │  Linux:   eBPF · seccomp-BPF · Landlock    │  │  │  │
│  │  │  │           namespaces · OCI · KVM/Firecracker│  │  │  │
│  │  │  │  macOS:   ESF · Seatbelt · Virt.framework  │  │  │  │
│  │  │  │           Network Extensions               │  │  │  │
│  │  │  │  Windows: ETW · Hyper-V · Windows Sandbox  │  │  │  │
│  │  │  │  Any:     WASI/Wasmtime                    │  │  │  │
│  │  │  │                                            │  │  │  │
│  │  │  │  ┌──────────────────────────────────────┐  │  │  │  │
│  │  │  │  │         YOUR WORKLOAD                │  │  │  │  │
│  │  │  │  │  process / container / VM / wasm     │  │  │  │  │
│  │  │  │  └──────────────────────────────────────┘  │  │  │  │
│  │  │  └────────────────────────────────────────────┘  │  │  │
│  │  └──────────────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

Each layer is independent and composable. You can run just eBPF monitoring with no policy
enforcement (observation-only mode), or you can stack all layers for maximum isolation.

---

## Feature Matrix

### Isolation Backends

| Backend | Linux | macOS | Windows | Capability |
|---------|:-----:|:-----:|:-------:|-----------|
| eBPF syscall monitor | ✓ | — | ✓ (eBPF for Windows) | Zero-overhead kernel tracing |
| eBPF network tap | ✓ | — | ✓ | Per-packet metadata, connection tracking |
| eBPF LSM enforcer | ✓ | — | — | Kernel-level block/allow via BPF-LSM |
| seccomp-BPF | ✓ | — | — | Syscall allowlist/denylist filter |
| Landlock | ✓ | — | — | Unprivileged filesystem path control |
| Linux namespaces | ✓ | — | — | PID/net/mount/user/IPC isolation |
| OCI containers | ✓ | ✓ | ✓ | Docker/OCI-compatible runtime wrapping |
| KVM/QEMU VMs | ✓ | — | — | Full hardware-isolated VMs |
| Firecracker microVMs | ✓ | — | — | Sub-second boot, minimal attack surface |
| Endpoint Security (ESF) | — | ✓ | — | Deep macOS event monitoring + auth |
| Seatbelt profiles | — | ✓ | — | macOS sandbox profiles (TCC-aware) |
| Virtualization.framework | — | ✓ | — | Native Apple Silicon VMs |
| Network Extensions | — | ✓ | — | Per-app network content filtering |
| Event Tracing (ETW) | — | — | ✓ | Windows kernel event collection |
| Hyper-V partitions | — | — | ✓ | Hardware VM isolation |
| Windows Sandbox | — | — | ✓ | Disposable Windows environment |
| WASI/Wasmtime | ✓ | ✓ | ✓ | Portable capability-based isolation |

### Intelligence Capabilities

| Capability | Description |
|------------|-------------|
| Behavioral baseline | Sliding-window syscall/network/file histograms per workload class |
| ONNX anomaly detection | Isolation forest model, online fine-tuning, configurable threshold |
| IOC matching | SHA256/MD5 hashes, domains (Aho-Corasick), IP CIDRs — zero-downtime reload |
| STIX 2.1 / TAXII 2.1 | Industry-standard threat intelligence ingestion |
| Abuse.ch feeds | URLhaus, MalwareBazaar, ThreatFox — auto-refresh |
| Custom feeds | CSV/JSON/YAML local or remote feeds |
| Policy auto-hardening | Observes then recommends minimum-privilege policy |
| Anomaly → action | Alert / freeze / kill on threshold breach |
| Forensic export | STIX bundle / PCAP / JSON event dump |

### Interfaces

| Interface | Description |
|-----------|-------------|
| `isobox` CLI | Primary control surface — scriptable, composable |
| TUI dashboard | Live ratatui interface — syscall graphs, anomaly meters, alerts |
| gRPC API | Typed streaming API for integrations (tonic) |
| REST API | OpenAPI-documented HTTP API (axum) |
| WebSocket | Real-time event/alert stream for web clients |
| `isobox.toml` | Declarative config-as-code, gitops-friendly |

---

## Quick Start

### 1. Install

```bash
# From source (requires Rust 1.79+)
git clone https://github.com/your-org/isolate
cd isolate
cargo install --path crates/isolate-cli --bin isobox
cargo install --path crates/isolate-daemon --bin isolatd

# Start the daemon (requires elevated privileges for eBPF/ESF/ETW)
sudo isolatd --config /etc/isolate/daemon.toml
```

### 2. Wrap a suspicious binary

```bash
# Audit mode — observe everything, block nothing
isobox run --policy malware-analysis -- ./suspicious_binary

# Block mode — enforce strict policy, kill on violation
isobox run --policy malware-analysis --action block -- ./suspicious_binary

# Use your own policy file
isobox run --policy-file ./my-policy.toml -- ./target
```

### 3. Watch it live

```bash
# List running isoboxes
isobox ps

# Attach TUI dashboard to a running isobox
isobox attach <isobox-id>

# Follow alerts in real-time
isobox alert --follow --isobox <isobox-id>
```

### 4. Inspect and export

```bash
# Deep inspection
isobox inspect <isobox-id>

# Export forensic bundle
isobox export <isobox-id> --format stix --output ./forensics/
isobox export <isobox-id> --format pcap --output ./capture.pcap
isobox export <isobox-id> --format json --output ./events.jsonl
```

### 5. Freeze a running isobox

```bash
# Freeze all activity (memory, network, processes preserved)
isobox freeze <isobox-id>

# Snapshot to disk, then destroy
isobox snapshot <isobox-id> --output /forensics/snapshot-$(date +%s)/
isobox stop <isobox-id>
```

---

## Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              isolate system                                 │
│                                                                             │
│  ┌──────────┐  ┌──────────┐  ┌───────────────────┐  ┌──────────────────┐  │
│  │  isobox  │  │isolate-  │  │    Web Browser     │  │  External CI/CD  │  │
│  │   CLI    │  │   tui    │  │  (React / Tauri)   │  │  / Integrations  │  │
│  └────┬─────┘  └────┬─────┘  └────────┬───────────┘  └────────┬─────────┘  │
│       │             │                 │                        │            │
│       └─────────────┴─────────────────┴────────────────────────┘            │
│                                       │                                     │
│                            Unix socket / gRPC+mTLS / REST+JWT               │
│                                       │                                     │
│                         ┌─────────────▼──────────────┐                     │
│                         │          isolatd            │                     │
│                         │   (privileged daemon)       │                     │
│                         │                             │                     │
│                         │  gRPC :7777  REST :7778     │                     │
│                         │  WS   :7779  Unix /run/...  │                     │
│                         └──────────────┬──────────────┘                     │
│                                        │                                    │
│              ┌─────────────────────────┼──────────────────────┐            │
│              │                         │                      │            │
│    ┌─────────▼──────────┐   ┌──────────▼─────────┐  ┌────────▼────────┐  │
│    │   Sandbox Engine   │   │ Intelligence Engine │  │  Policy Engine  │  │
│    │                    │   │                     │  │                 │  │
│    │  Backend registry  │   │  Event pipeline     │  │  CEL evaluator  │  │
│    │  Lifecycle mgmt    │   │  Baseline profiler  │  │  Live enforcer  │  │
│    │  Event collection  │   │  ONNX anomaly scorer│  │  Auto-hardener  │  │
│    │                    │   │  IOC matcher        │  │  Version store  │  │
│    │  ┌──────────────┐  │   │  Feed ingest        │  │                 │  │
│    │  │   Backends   │  │   └──────────┬──────────┘  └────────┬────────┘  │
│    │  │  (platform-  │  │              │                      │           │
│    │  │   specific)  │  │              └──────────────────────┘           │
│    │  └──────────────┘  │                        │                        │
│    └────────────────────┘                        │                        │
│                                                  ▼                        │
│                                        ┌─────────────────┐               │
│                                        │  isolate-store  │               │
│                                        │  (SQLite)       │               │
│                                        │  Events, alerts │               │
│                                        │  Baselines      │               │
│                                        │  Policy versions│               │
│                                        └─────────────────┘               │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Isolation Layer Stack

When you create an isobox, isolate automatically detects the current platform and enables every
applicable backend:

**On Linux:**
```
┌─ isobox ─────────────────────────────────────────────────────────────────────┐
│  [7] eBPF LSM enforcer    — kernel-level block/allow (BPF-LSM)               │
│  [6] eBPF monitors        — syscall/network/file/process tracing to ringbuf   │
│  [5] seccomp-BPF filter   — syscall allowlist enforced at kernel boundary     │
│  [4] Landlock ruleset     — filesystem path restriction (no root required)    │
│  [3] Linux namespaces     — PID/net/mount/IPC/user isolation (clone flags)    │
│  [2] cgroup v2            — resource limits (CPU, memory, pids, IO)           │
│  [1] OCI runtime wrapper  — optional: use runc/crun for container semantics   │
│       OR KVM/Firecracker  — optional: full VM isolation                       │
│  ─────────────────────────────────────────────────────────────────────────── │
│                           YOUR WORKLOAD                                       │
└───────────────────────────────────────────────────────────────────────────────┘
```

**On macOS:**
```
┌─ isobox ─────────────────────────────────────────────────────────────────────┐
│  [4] Endpoint Security    — ESF event authorization (process/file/network)   │
│  [3] Network Extension    — per-app network content filtering                │
│  [2] Seatbelt profile     — sandbox(7) SBPL profile (TCC + filesystem)       │
│  [1] Virtualization.fw    — optional: Apple Silicon VM with full isolation    │
│  ─────────────────────────────────────────────────────────────────────────── │
│                           YOUR WORKLOAD                                       │
└───────────────────────────────────────────────────────────────────────────────┘
```

**Universal (any platform):**
```
┌─ isobox ─────────────────────────────────────────────────────────────────────┐
│  WASI/Wasmtime            — capability-based isolation for Wasm workloads    │
│  ─────────────────────────────────────────────────────────────────────────── │
│                           YOUR WASM MODULE                                   │
└───────────────────────────────────────────────────────────────────────────────┘
```

### Intelligence Pipeline

Every event from every backend flows through a multi-stage intelligence pipeline:

```
  Raw kernel event
       │
       ▼
  ┌──────────────────────────────────────────────────────────────────────────┐
  │ Stage 1: Normalization                                                   │
  │   Platform-specific event → IsolateEvent enum (unified schema)           │
  └────────────────────────────────────────┬─────────────────────────────────┘
                                           │
       ┌────────────────────────────┬──────┴──────┬────────────────────────┐
       │                            │             │                        │
       ▼                            ▼             ▼                        ▼
  ┌──────────┐              ┌──────────────┐  ┌────────┐           ┌──────────────┐
  │ Stage 2: │              │  Stage 3:    │  │ Store  │           │  WebSocket   │
  │ Baseline │              │  IOC Match   │  │ (write)│           │  broadcast   │
  │ Profiler │              │              │  └────────┘           └──────────────┘
  │          │              │ Aho-Corasick │
  │ Histogram│              │ Hash lookup  │
  │ update   │              │ CIDR match   │
  └────┬─────┘              └──────┬───────┘
       │                           │
       ▼                           ▼
  ┌──────────────────┐      ┌─────────────┐
  │ Stage 4:         │      │  IOC Alert  │──→ Notification / Block
  │ Anomaly Scoring  │      └─────────────┘
  │                  │
  │ Feature vector   │
  │ → ONNX model     │
  │ → score [0,1]    │
  └────────┬─────────┘
           │
           ├── score < threshold → record only
           │
           └── score ≥ threshold →
                    ┌─────────────────────────────┐
                    │ Stage 5: Response Selector   │
                    │ alert / freeze / kill        │
                    └─────────────────────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────────┐
                    │ Stage 6: Policy Hardener     │
                    │ (background, non-blocking)   │
                    │ Compute min-privilege policy │
                    │ → PolicyHardenSuggestion     │
                    └─────────────────────────────┘
```

### Event Flow

```
Kernel (eBPF ring buffer / ESF callback / ETW session)
    │
    │  zero-copy typed structs
    ▼
isolate-sandbox backend
    │
    │  IsolateEvent (normalized)
    ▼
EventBus (crossbeam lock-free MPSC)
    │
    ├──→ isolate-store     (SQLite persistence, indexed by time + isobox_id)
    ├──→ isolate-intel     (pipeline: baseline → anomaly → IOC → hardener)
    ├──→ isolate-policy    (live CEL evaluation → enforce/block/kill)
    └──→ WebSocket relay   (broadcast to TUI / web clients)
```

### Privilege Separation

isolate uses a strict privilege separation model:

```
 ┌─────────────────────────────────────────────────────────────────┐
 │  isolatd  [root / CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_BPF]       │
 │                                                                 │
 │  • Loads eBPF programs (requires CAP_BPF + CAP_SYS_ADMIN)      │
 │  • Creates Linux namespaces (CAP_SYS_ADMIN)                    │
 │  • Registers ESF client (com.apple.developer.endpoint-security) │
 │  • Allocates unprivileged UIDs per isobox                       │
 │  • Drops to minimum caps immediately after init                 │
 │  • All IPC authenticated (mTLS, cert rotated on restart)        │
 │  • Audit log of all policy changes (append-only table)          │
 └──────────────────────────────┬──────────────────────────────────┘
                                │
              Unix socket (mode 0660) / gRPC+mTLS
                                │
          ┌─────────────────────┼──────────────────────┐
          ▼                     ▼                      ▼
    isobox CLI            isolate-tui           Web UI / API
    (no special privs)    (no special privs)    (JWT, local only by default)
```

Each workload runs under a **dedicated unprivileged UID** allocated from a pool (`isolate-uid-*`),
so even if a workload escapes its sandbox, it has no privileges on the host.

---

## Isolation Backends

### Linux Backends

#### eBPF (`crates/isolate-sandbox/src/backend/linux/ebpf.rs`)

The primary monitoring backend on Linux. Uses `aya` (pure Rust eBPF loader) to load CO-RE
(Compile Once, Run Everywhere) BPF programs compiled with BTF support.

**Programs:**

| Program | Hook | What it captures |
|---------|------|-----------------|
| `syscall_monitor` | `tracepoint/syscalls/sys_enter_*` | All syscall entries with args, PID, TGID, container ID |
| `network_monitor` | `tc/egress`, `tc/ingress`, `xdp` | Packet metadata (src/dst IP/port, protocol, length) |
| `file_monitor` | `lsm/file_open`, `lsm/inode_create`, `lsm/path_rename` | File access events with path and flags |
| `process_monitor` | `sched_process_exec`, `sched_process_fork` | Process/thread lifecycle events |
| `net_enforcer` | `lsm/socket_connect`, `lsm/socket_bind` | Real-time network connection enforcement |

All events flow to userspace via **BPF ring buffer** — zero-copy, in-order, no dropped events.

**Requirements:** Linux kernel ≥ 5.13 (for BPF-LSM + ring buffer). Older kernels fall back to
perf event arrays and tracepoints only (enforcement disabled).

#### seccomp-BPF (`crates/isolate-sandbox/src/backend/linux/seccomp.rs`)

Generates and applies seccomp BPF filters using `seccompiler`. Operates in two modes:

- **allowlist**: Only the listed syscalls are permitted. All others are killed with `SIGSYS`.
- **denylist**: All syscalls permitted except the listed ones.

The auto-hardener computes a minimum allowlist from observed syscalls after the baseline period.

#### Landlock (`crates/isolate-sandbox/src/backend/linux/landlock.rs`)

Linux's unprivileged filesystem access control (kernel ≥ 5.13). Creates a Landlock ruleset
with fine-grained path access rights. No root required — any process can restrict itself.

Layered on top of DAC/MAC: Landlock is additive restriction, never expansion.

#### Linux Namespaces (`crates/isolate-sandbox/src/backend/linux/namespace.rs`)

Orchestrates `clone(2)` with the following namespace flags by default:

| Namespace | Flag | Isolation |
|-----------|------|-----------|
| PID | `CLONE_NEWPID` | Process tree invisible to host |
| Network | `CLONE_NEWNET` | Isolated network stack (veth pair to host) |
| Mount | `CLONE_NEWNS` | Private filesystem view |
| User | `CLONE_NEWUSER` | UID/GID mapping (rootless by default) |
| IPC | `CLONE_NEWIPC` | Private SysV IPC / POSIX MQ |
| UTS | `CLONE_NEWUTS` | Private hostname |
| Cgroup | `CLONE_NEWCGROUP` | Private cgroup view |

#### OCI Containers (`crates/isolate-sandbox/src/backend/linux/container.rs`)

Wraps existing OCI-compatible runtimes (`runc`, `crun`, `youki`) via the OCI Runtime Spec.
Generates a full `config.json` bundle from the `isobox.toml` configuration. Supports:
- Rootless containers (preferred)
- Read-only root filesystem
- Custom mount overlays
- Integrated with namespace backend

#### KVM / Firecracker (`crates/isolate-sandbox/src/backend/linux/kvm.rs`)

For maximum isolation, wraps workloads in a minimal virtual machine:

- **QEMU/KVM**: Full VM with configurable hardware, disk images, memory. Use for comprehensive
  malware analysis that requires running an entire OS.
- **Firecracker**: Sub-second boot MicroVM (Amazon's open source VMM). Ideal for function-level
  isolation with minimal overhead. No BIOS, no PCI, no legacy devices.

VM event monitoring is bridged to the eBPF backend running inside the guest (requires a guest
agent) or via QEMU's gdbstub and memory introspection (agentless).

---

### macOS Backends

#### Endpoint Security Framework (`crates/isolate-sandbox/src/backend/macos/esf.rs`)

Apple's Endpoint Security Framework provides kernel-level event monitoring and authorization
for macOS. isolate registers as an ESF client to:

- **Monitor**: `ES_EVENT_TYPE_NOTIFY_*` — observe process exec, file reads/writes, network connections
- **Authorize**: `ES_EVENT_TYPE_AUTH_*` — approve or deny events in real-time

Authorization events are used for live enforcement (block mode). Notification events populate
the event pipeline.

**Requirements:**
- macOS 10.15+
- `com.apple.developer.endpoint-security.client` entitlement
- System Extension or privileged helper process

#### Seatbelt (`crates/isolate-sandbox/src/backend/macos/seatbelt.rs`)

Generates macOS sandbox profiles (SBPL — Sandbox Profile Language) and applies them via
`sandbox_init_with_parameters(3)`. Profiles define allow/deny rules for:
- Filesystem access (read, write, execute)
- Network operations (outbound by family/port, inbound)
- IPC (Mach ports, POSIX shared memory)
- Process operations (fork, exec)
- System operations (sysctl, ioctl)

isolate generates profiles dynamically from `isobox.toml` policy and the auto-hardener's
suggestions.

#### Virtualization.framework (`crates/isolate-sandbox/src/backend/macos/virt.rs`)

Apple's native hypervisor framework for macOS. Used to create lightweight Linux VMs on
Apple Silicon (and Intel). Features:
- Sub-second VM boot with rosetta image sharing
- Shared filesystem (virtio-fs)
- Paravirtualized network (virtio-net)
- Native performance via Hypervisor.framework underneath

Ideal for running Linux-targeted malware samples in a fully isolated VM on macOS.

#### Network Extensions (`crates/isolate-sandbox/src/backend/macos/netex.rs`)

Uses macOS Network Extension framework (NEFilterDataProvider) to implement per-app network
filtering. Unlike ESF network events (metadata only), Network Extensions can inspect and
modify network content at the TCP/UDP level.

---

### Windows Backends

#### Event Tracing for Windows (`crates/isolate-sandbox/src/backend/windows/etw.rs`)

ETW is Windows' kernel-level event collection mechanism. isolate creates a real-time ETW
session subscribed to:
- Microsoft-Windows-Kernel-Process (process/thread events)
- Microsoft-Windows-Kernel-File (file I/O)
- Microsoft-Windows-Kernel-Network (network connections)
- Microsoft-Windows-Kernel-Registry (registry operations)

Events are consumed via `tdh` (Trace Data Helper) and normalized to `IsolateEvent`.

#### Hyper-V (`crates/isolate-sandbox/src/backend/windows/hyperv.rs`)

Creates isolated Hyper-V partitions via the WMI/Hyper-V WMI API or the newer
`HCS API` (Host Compute Service). Provides:
- Hardware-level VM isolation
- Snapshotting and memory inspection
- Nested virtualization support

#### Windows Sandbox (`crates/isolate-sandbox/src/backend/windows/winsandbox.rs`)

Wraps `WindowsSandbox.exe` via its configuration API for disposable, isolated Windows
desktop sessions. Simpler than Hyper-V; ideal for testing Windows applications.

---

### Universal Backends

#### WASI / Wasmtime (`crates/isolate-sandbox/src/backend/wasm/wasmtime.rs`)

Runs WebAssembly modules in a capability-based sandbox using Wasmtime:
- No filesystem access unless explicitly granted via WASI `preopens`
- No network access unless WASI socket APIs are enabled
- No process spawning
- Memory isolated from host
- Cross-platform: same `.wasm` runs on Linux, macOS, Windows
- Near-native performance (AOT compilation)

Ideal for isolating plugin systems, build tools, or any workload that can be compiled to WASM.

---

## Intelligence Engine

### Behavioral Baseline

For each `workload_class` (configured in `isobox.toml`), isolate builds a behavioral
baseline using sliding time windows:

```
Baseline per workload class
    │
    ├── Syscall frequency histogram   (counts per syscall number, per window)
    ├── File path bloom filter        (probabilistic set of accessed paths)
    ├── Network connection entropy    (dst IP/port distribution)
    ├── Child process spawn rate      (forks/execs per minute)
    └── Memory growth rate            (RSS delta over time)

Windows: [ 5 minutes ] [ 1 hour ] [ 24 hours ]
```

Baselines are stored as compressed msgpack in SQLite and shared across all isoboxes of
the same `workload_class`. The baseline is considered "warm" after `baseline_warmup_minutes`
(default: 10) of accumulated activity.

### Anomaly Detection

The anomaly scorer uses an ONNX Runtime model (`models/behavior_classifier_v1.onnx`) —
an isolation forest trained on a diverse corpus of process behaviors. Input is a feature
vector derived from the current window's delta against the warm baseline.

**Scoring:**
- Score ∈ [0.0, 1.0]; higher = more anomalous
- `anomaly_threshold` (default: 0.75) triggers the configured action
- False positive rate tunable via `anomaly_threshold`

**Online learning:**
- New labeled samples (confirmed malicious or benign) are queued
- Periodic out-of-process fine-tuning job (`isolate-trainer`) improves the model
- Fine-tuned model is swapped atomically (zero downtime)

### IOC Matching

Every event is checked against loaded IOC (Indicator of Compromise) data:

| IOC type | Structure | Match |
|----------|-----------|-------|
| File hashes (SHA256, MD5) | `DashMap` (lockless concurrent) | Exact |
| Domains / URLs | Aho-Corasick automaton | Substring / pattern |
| IP addresses / CIDRs | `ipnet` prefix trie | CIDR containment |
| File paths | Aho-Corasick automaton | Glob pattern |

IOC tables are reloaded atomically using `ArcSwap` — no downtime, no locks during reload.

### Threat Feed Integration

isolate ships with built-in feed connectors:

| Feed | Protocol | Update freq | Coverage |
|------|----------|-------------|---------|
| Abuse.ch URLhaus | JSON/HTTP | 6h (configurable) | Malware URLs, hosts |
| Abuse.ch MalwareBazaar | JSON/HTTP | 6h | File hashes |
| Abuse.ch ThreatFox | JSON/HTTP | 6h | IOCs, TTPs |
| MISP instances | MISP REST | configurable | Full MISP IOCs |
| STIX 2.1 / TAXII 2.1 | TAXII HTTP | configurable | Industry standard |
| Custom (local) | CSV/JSON/YAML | on-demand | Any IOC type |

Feeds support:
- ETag / Last-Modified delta updates (don't re-download unchanged feeds)
- Cryptographic feed signing verification (optional)
- Feed-level priority and confidence scoring

### Policy Auto-Hardening

After the baseline warm period, the hardener computes the minimum-privilege policy that
covers all *observed* behavior:

```
Observed syscalls    → seccomp allowlist (only what was actually used)
Observed file paths  → Landlock ruleset / Seatbelt paths (only what was accessed)
Observed network dst → Firewall allowlist (only what was connected to)
Observed forks/execs → process policy (allow/deny based on observed)
```

The result is presented as a `PolicyHardenSuggestion`:

```
isobox policy suggest <isobox-id>

  Suggested hardening for isobox my-sandbox (workload_class: build-tool):

  syscalls:
    current:  default-allow (no filter)
    suggested: allowlist [read, write, open, close, stat, mmap, mprotect,
                          brk, futex, clone, execve, wait4, exit_group]
    reduction: 99.4% of Linux syscalls blocked

  filesystem:
    current:  no restriction
    suggested: read-only [/usr, /lib, /home/user/project]
               read-write [/tmp/build-output]
               deny [everything else]

  network:
    current:  no restriction
    suggested: allow [10.0.0.1:443 (registry.npmjs.org), 1.1.1.1:53 UDP]
               deny [all other outbound]

  Apply? [y/N]
```

With `auto_harden = true` in the policy, suggestions are applied automatically after a
configurable quiet period.

---

## Configuration Reference

### isobox.toml Schema

```toml
# ─── Identity ──────────────────────────────────────────────────────────────────
[isobox]
name            = "my-sandbox"
workload_class  = "malware-analysis"   # Groups baselines. Use the same class for
                                       # similar workloads (e.g. "web-server")
description     = "Analyze suspicious binary"
tags            = ["malware", "untrusted"]

# ─── Target workload ──────────────────────────────────────────────────────────
[isobox.target]
type        = "process"                # "process" | "container" | "vm" | "wasm-module"
command     = ["/bin/suspicious", "--arg1"]
environment = { PATH = "/usr/bin", HOME = "/tmp/sandbox" }
user        = "nobody"
group       = "nobody"
working_dir = "/tmp/sandbox"

# For container targets:
# image     = "ubuntu:22.04"
# For VM targets:
# image     = "/images/ubuntu-22.04.qcow2"
# For WASM targets:
# module    = "./target.wasm"

# ─── Backend selection ────────────────────────────────────────────────────────
[isobox.backends]
# Which backends to enable. "auto" picks all applicable for the current platform.
enabled = "auto"
# Or explicitly:
# enabled = ["ebpf", "seccomp", "landlock", "namespaces"]  # Linux
# enabled = ["esf", "seatbelt"]                             # macOS
# enabled = ["etw", "winsandbox"]                          # Windows
# enabled = ["wasm"]                                        # Any platform

# ─── Policy ───────────────────────────────────────────────────────────────────
[isobox.policy]
version        = "1.0"
default_action = "audit"              # "audit" | "block" | "kill"
auto_harden    = false                # Apply hardening suggestions automatically

# Network policy
[isobox.policy.network]
default        = "block"              # Default for unmatched connections
log_allowed    = true
log_denied     = true
dns_over_https = true                 # Force all DNS through DoH (prevents DNS exfil)
allow = [
  { dst = "8.8.8.8/32",   port = 53,  proto = "udp",  comment = "DNS" },
  { dst = "0.0.0.0/0",    port = 443, proto = "tcp",  comment = "HTTPS egress" },
]
deny = [
  { dst = "169.254.0.0/16", comment = "Block IMDS (cloud metadata)" },
  { dst = "10.0.0.0/8",     comment = "Block internal network" },
]

# Filesystem policy
[isobox.policy.filesystem]
default    = "deny"
read_only  = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"]
read_write = ["/tmp/sandbox", "/var/tmp"]
deny       = ["/etc/shadow", "/etc/sudoers", "/root/.ssh", "/home"]
no_exec    = ["/tmp", "/var/tmp"]     # W^X: deny execute in writable dirs

# Syscall policy (Linux)
[isobox.policy.syscalls]
mode  = "allowlist"                   # "allowlist" | "denylist"
allow = [
  "read", "write", "open", "openat", "close",
  "stat", "fstat", "lstat", "mmap", "mprotect",
  "munmap", "brk", "pread64", "pwrite64",
  "readv", "writev", "access", "pipe",
  "dup", "dup2", "nanosleep", "getpid",
  "socket", "connect", "sendto", "recvfrom",
  "shutdown", "bind", "listen", "accept",
  "getsockname", "getpeername", "setsockopt",
  "clone", "fork", "vfork", "execve", "wait4",
  "exit", "exit_group", "kill", "sigaction",
  "sigprocmask", "futex", "set_tid_address",
]
# When mode = "denylist", list dangerous syscalls to block:
# deny = ["ptrace", "process_vm_readv", "process_vm_writev", "kexec_load", ...]

# Process policy
[isobox.policy.process]
allow_fork                 = true
allow_exec                 = false    # Prevent spawning new processes
allow_network_namespace    = false    # Prevent network namespace escape
allow_user_namespace       = false    # Prevent UID manipulation
allow_ptrace               = false    # Prevent memory inspection of other processes
max_processes              = 16
max_open_files             = 256
max_memory_mb              = 512
max_cpu_percent            = 50

# ─── Intelligence ──────────────────────────────────────────────────────────────
[isobox.intelligence]
enabled                 = true
anomaly_threshold       = 0.75        # 0.0 (never alert) – 1.0 (always alert)
alert_on_ioc_match      = true
baseline_warmup_minutes = 10
threat_feeds            = ["abusech-urlhaus", "abusech-malwarebazaar"]

[isobox.intelligence.on_anomaly]
action  = "alert"                     # "alert" | "freeze" | "kill"
notify  = [
  "log",                              # Write to isolatd log
  "webhook:https://hooks.example.com/isolate-alerts",
  # "slack:T.../B.../...",
  # "pagerduty:integration-key",
]

# ─── Export / Forensics ────────────────────────────────────────────────────────
[isobox.export]
formats    = ["json", "pcap", "stix"]
output_dir = "/var/isolate/forensics"
auto_export_on_alert = false          # Automatically export when alert fires
```

### Policy DSL

Policies can also be expressed programmatically using the gRPC API or as CEL expressions
for complex conditions:

```toml
[[isobox.policy.rules]]
name      = "block-crypto-mining"
condition = "event.network.dst_port in [3333, 4444, 14444, 45560]"
action    = "kill"
notify    = ["log", "webhook:..."]

[[isobox.policy.rules]]
name      = "alert-on-suspicious-exec"
condition = """
  event.process.exec_path startsWith "/tmp" ||
  event.process.exec_path startsWith "/dev/shm"
"""
action    = "alert"
```

### Backend Selection

```toml
[isobox.backends]
# Auto-select all applicable backends (recommended)
enabled = "auto"

# Or fine-tune per backend:
[isobox.backends.ebpf]
enabled          = true
ringbuf_size_mb  = 8          # BPF ring buffer size
capture_syscall_args = true   # Include syscall arguments (increases volume)

[isobox.backends.seccomp]
enabled          = true
action_on_deny   = "kill"     # "kill" | "trap" | "errno"

[isobox.backends.landlock]
enabled          = true

[isobox.backends.namespaces]
enabled          = true
network          = true
pid              = true
mount            = true
user             = true

[isobox.backends.vm]
enabled          = false       # Set true for VM-level isolation
vmm              = "firecracker"  # "firecracker" | "qemu" | "virt-framework"
vcpus            = 2
memory_mb        = 1024
disk_image       = "/images/ubuntu.ext4"
```

---

## CLI Reference

```
isobox <COMMAND> [OPTIONS]

COMMANDS:
  run       Wrap a workload in an isobox and start it
  ps        List active isoboxes
  inspect   Show detailed state of an isobox
  attach    Attach TUI dashboard to an isobox
  stop      Gracefully stop an isobox
  freeze    Freeze all activity in an isobox
  thaw      Resume a frozen isobox
  snapshot  Take a forensic snapshot
  export    Export forensic data
  policy    Show, edit, or apply isobox policy
  alert     View or follow alerts
  feed      Manage threat intelligence feeds
  version   Show isolate version

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

isobox run [OPTIONS] -- <COMMAND>...

  -p, --policy <PRESET>           Use a built-in policy preset
                                  [values: malware-analysis, dev-environment,
                                           zero-trust-service, compromised-containment]
  -f, --policy-file <FILE>        Use a custom isobox.toml policy file
      --name <NAME>               Name for this isobox
      --class <CLASS>             Workload class (for baseline grouping)
      --action <ACTION>           Default enforcement action [audit|block|kill]
      --auto-harden               Apply hardening suggestions automatically
      --no-intel                  Disable intelligence engine (monitoring only)
      --backend <BACKEND>...      Force specific backends (overrides auto-select)
      --env <KEY=VAL>...          Additional environment variables
      --no-network                Block all network (shorthand)
      --read-only-root            Mount root filesystem read-only
      --timeout <SECS>            Kill isobox after N seconds
  -d, --detach                    Run in background, print isobox ID
  -v, --verbose                   Verbose output

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

isobox ps [OPTIONS]

      --format <FORMAT>           Output format [table|json|yaml] (default: table)
      --filter <EXPR>             Filter expression
      --watch                     Refresh every second

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

isobox inspect <ISOBOX_ID> [OPTIONS]

      --format <FORMAT>           Output format [text|json|yaml] (default: text)
      --section <SECTION>...      Show specific section only
                                  [values: policy, backends, stats, events,
                                           alerts, baseline, suggestions]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

isobox alert [OPTIONS]

  -i, --isobox <ID>               Filter to specific isobox
  -f, --follow                    Follow alert stream (like tail -f)
      --severity <LEVEL>          Minimum severity [info|warn|critical]
      --since <TIMESTAMP>         Show alerts since timestamp
      --format <FORMAT>           Output format [text|json|ndjson]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

isobox export <ISOBOX_ID> [OPTIONS]

      --format <FORMAT>           Export format [json|stix|pcap|all]
  -o, --output <PATH>             Output file or directory
      --since <TIMESTAMP>         Export events since timestamp
      --until <TIMESTAMP>         Export events until timestamp
      --include-memory            Include memory dump (requires freeze first)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

isobox policy <SUBCOMMAND> <ISOBOX_ID>

  show                            Print current policy
  suggest                         Show auto-hardening suggestions
  apply                           Apply a policy file or hardening suggestions
  diff <POLICY_FILE>              Diff current policy against a file
  history                         Show policy change history (audit log)
  rollback <VERSION>              Roll back to a previous policy version

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

isobox feed <SUBCOMMAND>

  list                            List configured feeds and their status
  update [FEED_NAME]              Trigger immediate update (all feeds or named)
  add <URL> [OPTIONS]             Add a new feed
  remove <FEED_NAME>              Remove a feed
  status                          Show IOC counts per feed
```

---

## TUI Dashboard

Launch with `isobox attach <id>` or `isolate-tui` (standalone).

```
╔══════════════════════════════════════════════════════════════════════════════╗
║  isolate  v0.1.0          2 isoboxes active          [q]quit  [?]help       ║
╠═══════════════════════════════════════╦══════════════════════════════════════╣
║  ISOBOXES                             ║  SYSCALL GRAPH  my-sandbox           ║
║  ──────────────────────────────────── ║  ────────────────────────────────── ║
║  ● my-sandbox         RUNNING  2m 14s ║                                      ║
║    malware-analysis   anomaly: 0.82 ! ║  open  ████████████████  1,240/s    ║
║    backends: ebpf seccomp landlock    ║  read  ███████████       892/s      ║
║                                       ║  write ████              310/s      ║
║  ● dev-env-01         RUNNING 18m 32s ║  stat  ████████          640/s      ║
║    dev-environment    anomaly: 0.12   ║  mmap  ██                152/s      ║
║    backends: ebpf seccomp             ║  ...                                 ║
║                                       ║                                      ║
╠═══════════════════════════════════════╬══════════════════════════════════════╣
║  ANOMALY SCORE  my-sandbox            ║  NETWORK CONNECTIONS  my-sandbox     ║
║  ────────────────────────────────     ║  ────────────────────────────────── ║
║                                       ║  192.168.1.100:4444  [BLOCKED] !    ║
║  0.82  [▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░]  !    ║  8.8.8.8:53/UDP      [ALLOWED]      ║
║        threshold: 0.75                ║  104.21.1.1:443       [ALLOWED]      ║
║                                       ║                                      ║
║  Feature contributions:               ║  BLOCKED (policy): 3                 ║
║  • execve spike  +0.41               ║  IOC HITS: 1 (4444 C2 port)          ║
║  • open /tmp     +0.22               ║                                      ║
║  • new connect   +0.19               ║                                      ║
╠═══════════════════════════════════════╩══════════════════════════════════════╣
║  ALERT FEED                                                                  ║
║  ──────────────────────────────────────────────────────────────────────────  ║
║  [CRITICAL] 14:32:01  my-sandbox  IOC match: dst 192.168.1.100:4444         ║
║             Known C2 port (ThreatFox confidence: 92%). Connection BLOCKED.   ║
║  [WARN]     14:31:58  my-sandbox  Anomaly score 0.82 (threshold 0.75)        ║
║             execve spike: 47 new processes in 10s. Action: alert             ║
║  [INFO]     14:28:03  dev-env-01  Baseline warm (10 min). Hardening ready.   ║
╚══════════════════════════════════════════════════════════════════════════════╝

  [Tab] switch panel  [Enter] drill-down  [f] freeze  [k] kill  [e] export
```

**Keyboard shortcuts:**

| Key | Action |
|-----|--------|
| `Tab` | Switch between panels |
| `Enter` / `Space` | Drill into selected isobox |
| `f` | Freeze selected isobox |
| `t` | Thaw (resume) selected isobox |
| `k` | Kill selected isobox |
| `e` | Export forensic bundle |
| `p` | Show / apply policy suggestions |
| `F5` | Force refresh |
| `q` | Quit |
| `?` | Help |

---

## REST & gRPC API

### gRPC

isolatd exposes a gRPC service on port 7777 (configurable). See [`proto/isolate.proto`](proto/isolate.proto)
for the full service definition.

**Key RPCs:**

```
IsolateService:
  CreateIsobox(CreateIsoboxRequest) → CreateIsoboxResponse
  ListIsoboxes(ListIsoboxesRequest) → ListIsoboxesResponse
  GetIsobox(GetIsoboxRequest) → Isobox
  StopIsobox(StopIsoboxRequest) → Empty
  FreezeIsobox(FreezeRequest) → Empty
  ThawIsobox(ThawRequest) → Empty
  SnapshotIsobox(SnapshotRequest) → SnapshotResponse

  GetPolicy(GetPolicyRequest) → Policy
  ApplyPolicy(ApplyPolicyRequest) → Empty
  GetHardeningSuggestions(GetIsoboxRequest) → stream PolicySuggestion

  StreamEvents(StreamEventsRequest) → stream IsolateEvent
  StreamAlerts(StreamAlertsRequest) → stream Alert
  QueryEvents(EventQueryRequest) → EventQueryResponse

  UpdateFeeds(UpdateFeedsRequest) → UpdateFeedsResponse
  ExportForensics(ExportRequest) → stream ExportChunk
```

All gRPC connections are authenticated with mTLS.

### REST API

isolatd also exposes a REST API on port 7778 with OpenAPI documentation at `/api/openapi.json`.

```
GET    /api/v1/isoboxes                     List all isoboxes
POST   /api/v1/isoboxes                     Create a new isobox
GET    /api/v1/isoboxes/{id}                Get isobox details
DELETE /api/v1/isoboxes/{id}                Stop and destroy
POST   /api/v1/isoboxes/{id}/freeze         Freeze
POST   /api/v1/isoboxes/{id}/thaw           Thaw
POST   /api/v1/isoboxes/{id}/snapshot       Snapshot

GET    /api/v1/isoboxes/{id}/policy         Get current policy
PUT    /api/v1/isoboxes/{id}/policy         Replace policy
PATCH  /api/v1/isoboxes/{id}/policy         Update policy fields
GET    /api/v1/isoboxes/{id}/policy/suggest Hardening suggestions

GET    /api/v1/isoboxes/{id}/events         Query events (paginated)
GET    /api/v1/isoboxes/{id}/alerts         Query alerts

GET    /api/v1/feeds                        List feeds
POST   /api/v1/feeds                        Add feed
POST   /api/v1/feeds/{name}/update          Trigger feed update
DELETE /api/v1/feeds/{name}                 Remove feed

GET    /api/v1/isoboxes/{id}/export         Export forensic bundle

WS     /ws/v1/events                        Live event stream
WS     /ws/v1/alerts                        Live alert stream
```

**Authentication:** JWT bearer token. Obtain via `isobox auth login`.
REST API is local-only by default; set `daemon.api.bind = "0.0.0.0:7778"` with TLS to expose.

---

## Forensics & Export

When a suspicious behavior or IOC hit is detected, isolate can produce a complete forensic
bundle:

### JSON Event Log (NDJSON)
```
isobox export <id> --format json --output events.jsonl
```
Each line is a JSON `IsolateEvent` with full context (timestamp, isobox_id, backend, pid, etc.).

### PCAP Network Capture
```
isobox export <id> --format pcap --output capture.pcap
```
All network metadata captured by eBPF network monitor, exported as PCAP for Wireshark.

### STIX 2.1 Bundle
```
isobox export <id> --format stix --output threat-report.json
```
Produces a STIX 2.1 bundle containing:
- `threat-actor` (inferred from behavior)
- `malware` (if malware class detected)
- `indicator` (observed IOCs)
- `observed-data` (network connections, file accesses)
- `attack-pattern` (MITRE ATT&CK technique mapping if detected)

### Memory Snapshot
```
isobox freeze <id>
isobox snapshot <id> --include-memory --output /forensics/snapshot/
isobox stop <id>
```
Creates a full disk+memory snapshot directory:
```
snapshot/
├── memory.dmp         # Raw memory dump (Linux: /proc/<pid>/mem, VM: full RAM)
├── disk.img           # Disk image (VM mode) or overlayfs diff (container)
├── events.jsonl       # All events up to freeze point
├── network.pcap       # All network traffic
└── metadata.json      # isobox config, backend state, timestamps
```

---

## Building from Source

### Prerequisites

```bash
# Rust toolchain (1.79+)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# For eBPF programs (Linux)
sudo apt install clang llvm libelf-dev linux-headers-$(uname -r)
# or on macOS (for cross-compiling eBPF):
brew install llvm

# For protobuf compilation
cargo install protoc-gen-prost protoc-gen-tonic
# or: apt install protobuf-compiler

# For ONNX Runtime
# Download from https://github.com/microsoft/onnxruntime/releases
# Set ORT_DYLIB_PATH=/path/to/libonnxruntime.so
```

### Build

```bash
# Build all crates (no eBPF)
cargo build --workspace --release

# Build with eBPF programs (Linux only, requires clang)
cargo build --workspace --release --features ebpf

# Build and run tests
cargo test --workspace

# Build the CLI binary only
cargo build --release --bin isobox

# Build the daemon only
cargo build --release --bin isolatd
```

### Platform-specific notes

**Linux (full feature set):**
```bash
# Install kernel headers for your running kernel
sudo apt install linux-headers-$(uname -r)

# Build eBPF programs
cd ebpf && make

# Run isolatd with full eBPF support
sudo ./target/release/isolatd
```

**macOS (ESF + Seatbelt):**
```bash
# ESF requires an entitlement (for development, use a System Extension)
# Seatbelt works without special entitlements
# Virtualization.framework requires macOS 12+ on Apple Silicon

cargo build --workspace --release --target aarch64-apple-darwin
```

**Windows (ETW + Hyper-V):**
```powershell
# Install Visual Studio Build Tools
# Install LLVM for clang-cl
cargo build --workspace --release --target x86_64-pc-windows-msvc
```

---

## Development Roadmap

### Phase 1 — Foundation (current)
- [x] Cargo workspace structure
- [ ] `isolate-core`: types, traits, error hierarchy
- [ ] `isolate-events`: EventBus, IsolateEvent enum
- [ ] `isolate-config`: isobox.toml parser and validator
- [ ] `isolate-store`: SQLite event store with migrations
- [ ] `isolate-sandbox`: SandboxBackend trait + Linux eBPF backend
- [ ] `ebpf/syscall_monitor.bpf.c`: syscall tracepoints → ring buffer
- [ ] `isolate-daemon`: gRPC skeleton
- [ ] `isolate-cli`: `run`, `ps`, `stop` commands
- **Milestone**: `isobox run -- ls` records syscalls to SQLite

### Phase 2 — Platform Depth
- [ ] seccomp-BPF filter builder
- [ ] Landlock ruleset builder
- [ ] Linux namespace orchestration
- [ ] OCI container backend
- [ ] KVM/Firecracker backend
- [ ] macOS ESF backend
- [ ] macOS Seatbelt backend
- [ ] macOS Virtualization.framework backend
- [ ] Windows ETW stub
- [ ] WASM/Wasmtime backend
- [ ] eBPF network + file + process monitors
- [ ] eBPF LSM enforcer (policy enforcement)
- **Milestone**: Full layered isolation; malware cannot escape

### Phase 3 — Intelligence
- [ ] Behavioral baseline profiler
- [ ] ONNX anomaly scorer + pre-trained model
- [ ] IOC matcher (Aho-Corasick + hash + CIDR)
- [ ] Threat feed ingest (URLhaus, MalwareBazaar, ThreatFox, STIX/TAXII)
- [ ] Policy auto-hardener
- [ ] Full REST API
- **Milestone**: Detects known malware hashes; flags anomalous behavior

### Phase 4 — Interfaces
- [ ] ratatui TUI dashboard (all widgets)
- [ ] WebSocket event relay
- [ ] Tauri desktop app (optional)
- [ ] OpenAPI documentation
- [ ] Built-in policy templates
- **Milestone**: Operator can watch a sample run in real-time

### Phase 5 — Production Hardening
- [ ] mTLS between all components
- [ ] JWT auth for REST API
- [ ] STIX/PCAP/JSON forensic export
- [ ] Integration test suite
- [ ] E2E test suite (GitHub Actions: Linux + macOS + Windows)
- [ ] Performance benchmarks
- [ ] docs/threat-model.md (isolate's own threat model)
- [ ] docs/cpp-migration.md (C/C++ re-implementation guide)

---

## Security Model

### Threat Model for the Sandbox

isolate protects against workloads that attempt to:
- Escape via syscall-level exploits (mitigated by seccomp, eBPF-LSM, Landlock)
- Exfiltrate data via network (mitigated by network policy enforcement at kernel level)
- Manipulate the filesystem of the host (mitigated by namespace isolation + Landlock)
- Spawn privileged processes (mitigated by user namespace UID mapping + process policy)
- Detect the sandbox and lay dormant (mitigated by configurable timing, reduced fingerprinting)

### Threat Model for isolate Itself

isolate is a security tool and is itself a target. We mitigate:

| Threat | Mitigation |
|--------|------------|
| Compromised CLI deceives daemon | mTLS client authentication |
| Daemon tampered with | Code signing, systemd `ReadOnlyPaths=` |
| Policy modified without audit | Append-only policy audit log in SQLite |
| Threat feed injection | Feed signing (optional), confidence scoring |
| ONNX model poisoning | Model hash verification, out-of-process inference |
| isolatd privesc | Capability drop after init, seccomp on daemon itself |
| Daemon → isobox escalation | Each isobox runs as dedicated unprivileged UID |

### Reporting Security Issues

See [SECURITY.md](SECURITY.md). Please do **not** open public GitHub issues for security
vulnerabilities. Email `security@your-org.com` with a description and reproduction steps.
We aim to respond within 48 hours.

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Follow Rust conventions: `cargo fmt` + `cargo clippy -- -D warnings`
4. Add tests for new functionality
5. Submit a pull request

### Code Organization Principles

- **No platform-specific code in `isolate-core`** — all platform backends in `isolate-sandbox`
- **Trait-first design** — every isolation mechanism implements `SandboxBackend`
- **Async-first** — all I/O is async (tokio); blocking operations go to `spawn_blocking`
- **Zero unsafe unless necessary** — justify every `unsafe` block with a safety comment
- **Denial of service resistance** — all event ingestion paths are bounded (ring buffers,
  backpressure, drop strategies under load)

---

## Security Disclosure

**Do not file public issues for security vulnerabilities.**

Contact: `security@your-org.com`
PGP key: available at `https://your-org.com/.well-known/security.txt`

We follow responsible disclosure: fixes are developed privately and coordinated with a 90-day
disclosure deadline.

---

## License

Apache License 2.0. See [LICENSE](LICENSE).

---

*isolate is not affiliated with any commercial sandbox product. It is an open-source security
research and operational tool. Use responsibly and only on systems you own or have explicit
authorization to monitor.*
