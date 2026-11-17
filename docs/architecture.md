# isolate — Architecture

## Overview

isolate is a multi-layer sandboxing system that creates **isoboxes** — composable
isolation environments combining every available OS-level and hardware-level primitive
into a single, unified, observable unit.

The system is structured as a set of Rust crates, each with a single responsibility,
connected by well-defined interfaces (traits and event types).

---

## Component Map

```
┌───────────────────────────────────────────────────────────────────────────────┐
│  USER INTERFACES                                                              │
│                                                                               │
│  isobox CLI          isolate-tui (ratatui)      isolate-ui (Tauri)           │
│  (isolate-cli)       terminal dashboard          desktop GUI (React/TS)       │
└──────────┬───────────────────┬──────────────────────────┬────────────────────┘
           │                   │                          │
           │  REST / gRPC (mTLS)                          │
           ▼                   ▼                          ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│  isolatd (isolate-daemon)                                                     │
│                                                                               │
│   axum REST :7778     tonic gRPC :7777     WebSocket :7779                   │
│   (isolate-proto)                                                             │
│                                                                               │
│   supervisor.rs ──── manages ────► SandboxEngine (isolate-sandbox)           │
│   ├─ heartbeat → paladin (Unix socket)                                       │
│   └─ event routing → EventBus (isolate-events)                               │
└─────────────────────────────┬─────────────────────────────────────────────────┘
                              │ IsolateEvent (crossbeam channel + broadcast)
              ┌───────────────┼───────────────────────┐
              ▼               ▼                       ▼
   ┌──────────────┐  ┌─────────────────┐   ┌──────────────────┐
   │isolate-store │  │ isolate-intel   │   │ isolate-policy   │
   │(SQLite/sqlx) │  │                 │   │(PolicyEngine +   │
   │              │  │ pipeline.rs     │   │ PolicyEnforcer)  │
   │events        │  │ baseline.rs     │   │                  │
   │alerts        │  │ anomaly.rs(ONNX)│   │ live enforcement │
   │baselines     │  │ ioc.rs (AC+DM) │   │ per-isobox       │
   │policy_audit  │  │ feeds.rs (STIX) │   └────────┬─────────┘
   │ioc_matches   │  │ hardener.rs     │            │
   └──────────────┘  └────────┬────────┘            │
                              │ IntelAction          │ PolicyUpdate
                              └──────────────────────►
                                           SandboxEngine (live policy push)
```

---

## Crate Dependency Graph

```
isolate-core        (no workspace deps)
     │
     ├── isolate-events  (core)
     ├── isolate-config  (core)
     ├── isolate-store   (core, events)
     ├── isolate-policy  (core, events)
     ├── isolate-sandbox (core, events, config, policy)
     ├── isolate-intel   (core, events, store, policy)
     ├── isolate-proto   (tonic/prost only)
     ├── isolate-daemon  (all of the above + proto)
     ├── isolate-cli     (core, config, events, proto)
     ├── isolate-tui     (core, events, proto)
     └── isolate-paladin (core — minimal deps, independent)
```

`isolate-paladin` deliberately has minimal dependencies so it can operate even
when the main daemon is compromised or unresponsive.

---

## Event Flow

All observable activity flows through the `EventBus`:

```
Kernel / OS
  │
  │  Linux: eBPF tracepoints + LSM hooks → aya ring buffer reader
  │  macOS:  ESF authorization handler → Rust FFI callback
  │  Windows: ETW real-time session → Rust callback
  │
  ▼
EventBus (isolate-events)
  ├── crossbeam bounded MPSC (65 536 capacity) — ingest
  └── tokio::broadcast (4 096 capacity) — fan-out
        │
        ├── isolate-store: insert_event() → SQLite WAL
        │
        ├── isolate-intel: IntelEngine.process()
        │     ├── BaselineProfiler.update()
        │     ├── AnomalyScorer.score()  (ONNX inference)
        │     ├── IocMatcher.check_event()
        │     └── PolicyHardener.observe()
        │
        ├── isolate-policy: PolicyEnforcer.evaluate()
        │     └── Enforcement action → SandboxBackend.apply_policy()
        │
        └── WebSocket broadcast → TUI / web UI
```

---

## Sandbox Backend Priority Stack

When multiple backends are active, they are applied in priority order (highest first).
Each backend operates independently; a blocked action at a higher-priority layer
does not prevent lower-priority layers from logging it.

| Priority | Backend         | Layer |
|----------|-----------------|-------|
| 200      | eBPF / ESF / ETW | Kernel observation + enforcement |
| 180      | seccomp-BPF     | Kernel ABI boundary |
| 170      | Landlock        | Filesystem (unprivileged) |
| 160      | Namespaces      | Process/network/mount isolation |
| 150      | OCI container   | Filesystem + capability isolation |
| 100      | KVM / Virt.framework | Full hardware isolation |
|  50      | Wasmtime WASI   | WASM module isolation |

---

## Intelligence Pipeline

```
IsolateEvent
     │
     ▼
BaselineProfiler
  sliding-window histograms (5 min / 1 hr / 24 hr)
  per workload_class: syscall rates, file bloom, net entropy, fork rate
     │
     ▼ feature delta vector
AnomalyScorer (ONNX Runtime)
  behavior_classifier_v1.onnx (isolation forest)
  score ∈ [0.0, 1.0]
     │
     ├─ score < threshold  ──► continue
     └─ score ≥ threshold  ──► Alert + (optional) PolicyHardenSuggestion
                                        │
                                        └─► paladin if score ≥ paladin.escalation_threshold
     │
     ▼
IocMatcher
  Aho-Corasick automaton (string/domain/URL)
  DashMap<String, IocEntry> (hash lookup — O(1))
  Vec<(IpNet, IocEntry)> (CIDR — O(n_entries))
  Reload via ArcSwap (zero downtime on feed update)
     │
     └─ hit ──► IocMatch event + Alert
     │
     ▼
PolicyHardener
  After baseline warm, compute minimum-privilege policy:
    observed syscalls → seccomp allowlist
    observed paths    → Landlock / Seatbelt rules
    observed net dsts → firewall rules
  Emits PolicyHardenSuggestion (non-destructive)
```

---

## Paladin Escalation Levels

The paladin (`isolate-paladin`) is a privileged daemon that runs **independently**
of `isolatd`. It monitors isoboxes via:

1. **Watchdog** — receives heartbeats from `isolatd` on a Unix socket.
   If the heartbeat stops (dead-man's switch), paladin escalates.
2. **Sentinel** — polls `/proc` and `/sys/fs/cgroup` every 5 seconds.
   Detects cgroup membership violations, tripwire files, suspicious `/proc/net` state.
3. **Out-of-band notifications** — writes to `syslog`, `stderr`, `webhooks`, `serial port`.

Escalation levels (MUST be executed in order; each level is idempotent):

| Level | Name       | Action |
|-------|-----------|--------|
| 0     | WATCHING  | No action; monitor only |
| 1     | ALERT     | Out-of-band notification only |
| 2     | CONTAIN   | `nft` rules drop all isobox traffic (NOT eBPF) |
| 3     | FREEZE    | `cgroup.freeze = "1"` (fallback: SIGSTOP all PIDs) |
| 4     | TERMINATE | `cgroup.kill = "1"` (fallback: SIGKILL all PIDs) |
| 5     | SCORCH    | Wipe volatile state dirs; drop page caches |
| 6     | RAMPART   | System-wide nftables lockdown (loopback + established only) |
| 7     | ABSOLUTION| Sysrq sync → remount RO → kernel panic (requires env var) |

The paladin uses `nftables` (not eBPF) for network containment because eBPF
may itself be compromised or tampered with by the threat actor.

---

## Privilege Separation

```
isolatd (root / CAP_SYS_ADMIN, CAP_NET_ADMIN)
  - Loads eBPF programs
  - Creates namespaces + cgroups
  - Listens on Unix socket (0660) + gRPC/REST on 127.0.0.1

isolate-paladin (root, minimal caps: CAP_NET_ADMIN, CAP_SYS_BOOT)
  - Runs as a separate process / systemd service
  - Communicates via dedicated Unix socket
  - Does NOT use eBPF (avoids kernel module trust chain)

isobox CLI / TUI / Web UI (user privileges)
  - Connects to isolatd via gRPC/REST with mTLS
  - Never touches kernel objects directly
```

Each isobox workload runs under a dedicated UID from the range 100 000–199 999,
auto-allocated from a pool managed by `isolatd`.

---

## Data Storage Schema

SQLite database at `/var/lib/isolate/isolate.db` (WAL mode):

| Table | Purpose |
|-------|---------|
| `events` | All raw `IsolateEvent` records (indexed by isobox_id, timestamp) |
| `alerts` | Deduplicated alert records with severity and action |
| `baselines` | Compressed msgpack behavioral baseline snapshots |
| `policy_audit` | Append-only log of all policy changes with author + reason |
| `ioc_matches` | IOC hits with confidence, feed source, and triggering event |
| `isoboxes` | Active and historical isobox records |
| `paladin_log` | Paladin escalation audit log (append-only) |

All writes use SQLite WAL mode for concurrent read access from the TUI/REST API.

---

## gRPC + REST API Summary

See `proto/isolate.proto` for the complete gRPC definition.

| Method | Endpoint | Description |
|--------|---------|-------------|
| `POST` | `/api/v1/isoboxes` | Create a new isobox |
| `GET`  | `/api/v1/isoboxes` | List all isoboxes |
| `GET`  | `/api/v1/isoboxes/:id` | Get isobox details |
| `POST` | `/api/v1/isoboxes/:id/freeze` | Freeze an isobox |
| `POST` | `/api/v1/isoboxes/:id/thaw` | Thaw a frozen isobox |
| `POST` | `/api/v1/isoboxes/:id/snapshot` | Create forensic snapshot |
| `DELETE` | `/api/v1/isoboxes/:id` | Stop and destroy |
| `GET`  | `/api/v1/isoboxes/:id/policy` | Get current policy |
| `PUT`  | `/api/v1/isoboxes/:id/policy` | Apply policy update |
| `GET`  | `/api/v1/isoboxes/:id/events` | Query events (paginated) |
| `GET`  | `/api/v1/alerts` | Query alerts |
| `WS`   | `/ws/events?isobox_id=<id>` | Live event stream |
| `GET`  | `/health` | Daemon health check |
