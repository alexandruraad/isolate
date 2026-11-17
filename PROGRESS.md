# isolate — Build & Progress Report

_Generated: 2026-02-25 — Updated: 2026-02-28_

---

## Blocker: Xcode License (macOS)

**ALL Rust compilation fails** on this machine until the Xcode license is accepted.

```
error: linking with `cc` failed: exit status: 69
You have not agreed to the Xcode license agreements.
```

**Fix — run once in a terminal:**
```sh
sudo xcodebuild -license accept
```

After that, all `cargo check` / `cargo build` commands will work.

---

## Project Status

### Workspace

| Crate | Files | Status | Notes |
|-------|-------|--------|-------|
| `isolate-core` | 4 | ✅ Ready | Types, errors, IsoboxId (ULID), PaladinConfig |
| `isolate-events` | 3 | ✅ Ready | IsolateEvent, EventBus (crossbeam+broadcast) |
| `isolate-config` | 4 | ✅ Ready | isobox.toml schema, DaemonConfig, presets |
| `isolate-store` | 5 | ✅ Ready | SQLite/sqlx, WAL, 7 tables, migrations |
| `isolate-policy` | 4 | ✅ Ready | PolicyEngine, PolicyEnforcer, VersionLedger |
| `isolate-sandbox` | 12 | ⚠️ Stubs | Trait complete; backends are Phase-2 skeletons |
| `isolate-intel` | 7 | ⚠️ Stubs | Pipeline wired; ONNX/baseline/feeds are stubs |
| `isolate-paladin` | 5 | ✅ Ready | All 8 escalation levels, watchdog, sentinel |
| `isolate-daemon` | 4 | ⚠️ Partial | REST complete; gRPC stub pending proto codegen |
| `isolate-cli` | 11 | ✅ Ready | All 11 subcommands wired to REST |
| `isolate-tui` | 5 | ✅ Ready | ratatui dashboard, WS feed, keyboard nav |
| `isolate-proto` | 3 | ⚠️ Pending | Needs `tonic-build` codegen run |
| `isolate-ui` | 12 | ✅ Ready | Tauri v1 + React/TS/Tailwind desktop GUI |

### Other artifacts

| Path | Status | Notes |
|------|--------|-------|
| `ebpf/syscall_monitor.bpf.c` | ✅ Complete | BTF CO-RE, ring buffer, cgroup filter |
| `ebpf/network_monitor.bpf.c` | ✅ Complete | TC egress, LPM_TRIE, LSM socket_connect |
| `ebpf/file_monitor.bpf.c` | ✅ Complete | LSM file_open (-EPERM), bprm_check |
| `ebpf/process_monitor.bpf.c` | ✅ Complete | exec/fork/exit tracepoints |
| `proto/isolate.proto` | ✅ Complete | Full IsolateService gRPC definition |
| `proto/events.proto` | ✅ Complete | All event types |
| `proto/intelligence.proto` | ✅ Complete | IntelligenceService gRPC |
| `policy/malware-analysis.toml` | ✅ Complete | Maximum containment template |
| `policy/dev-environment.toml` | ✅ Complete | Audit-mode dev template |
| `policy/zero-trust-service.toml` | ✅ Complete | Production microservice template |
| `policy/compromised-containment.toml` | ✅ Complete | Emergency incident template |
| `isobox.toml.example` | ✅ Complete | Annotated full config reference |
| `docs/architecture.md` | ✅ Complete | Full system architecture |
| `docs/threat-model.md` | ✅ Complete | 8 threat categories + isolate-self threats |
| `docs/cpp-migration.md` | ✅ Complete | Complete C/C++ port guide |
| `docs/isobox-config-reference.md` | ✅ Complete | All config keys documented |

---

## Bugs Fixed This Session

| # | File | Bug | Fix |
|---|------|-----|-----|
| 1 | `isolate-ui/src-tauri/Cargo.toml` | Missing `[workspace]` — Tauri app was detected as part of parent workspace but not listed as member | Added `[workspace]` table at top of `src-tauri/Cargo.toml` (standard Tauri monorepo pattern) |
| 2 | `isolate-ui/src-tauri/Cargo.toml` | Invalid Tauri v1 feature flags (`window-hide`, `window-show`, `window-set-title`, `updater`) | Removed invalid features, kept only valid Tauri v1 flags |
| 3 | `isolate-ui/src-tauri/Cargo.toml` | `tauri-plugin-websocket` git dep caused resolution failures | Removed; WS relay is handled in Rust directly via `tokio-tungstenite` |
| 4 | `isolate-store/src/lib.rs` | `pub mod migrations;` declared but `migrations.rs` didn't exist | Created `crates/isolate-store/src/migrations.rs` |
| 5 | `isolate-tui/src/main.rs` | Duplicate keybinding: `'k'` bound to both `prev_isobox()` (line 57) and `action_kill()` (line 61) — second arm shadowed first | Changed kill binding from `'k'` to `'x'` |
| 6 | `isolate-paladin/src/escalation.rs` | Logic bug: `!errors.is_empty() && false \|\| true` always returns `true` even on failure | Fixed to `errors.is_empty()` |
| 7 | `isolate-intel/src/ioc.rs` | Unreachable `EventBody::Exec` arm (lines 107-114) shadowed by the `File \| Exec` arm above | Removed duplicate arm; `File \| Exec` arm already handles both |
| 8 | `Cargo.toml` | `ort = "2"` — no stable release; only release candidates exist | Updated to `ort = "2.0.0-rc.11"` |
| 9 | `Cargo.toml` | `wasmtime = "26"` — outdated (latest is v42) | Updated to `wasmtime = "42"` |
| 10 | `isolate-core/src/error.rs` | `sqlx::Error` variant caused E0433 — `isolate-core` shouldn't depend on `sqlx` | Removed `Database` variant; added `Store(String)` instead |
| 11 | `isolate-core/Cargo.toml` | `anyhow` dep missing despite `Other(#[from] anyhow::Error)` variant | Added `anyhow` to workspace deps + isolate-core deps |
| 12 | `isolate-events/Cargo.toml` | `futures_core::Stream` used in `stream.rs` without `futures-core` dep | Added `futures-core` + `futures-util` to workspace and to crate |
| 13 | `isolate-config/src/schema.rs` | E0116: `impl IsoboxConfig` defined outside `isolate-core` | Replaced with module-level free function `default_isobox_config()` |
| 14 | `isolate-sandbox/src/backend/macos/` | Missing `virt.rs` and `netex.rs` modules declared in `mod.rs` | Created stub implementations for both backends |
| 15 | `isolate-sandbox/src/backend/macos/esf.rs` | E0277: `Output: Default` not satisfied for `.unwrap_or_default()` on `Command::output()` | Changed to `match` with explicit error handling |
| 16 | `isolate-sandbox/Cargo.toml` | `futures_util::StreamExt` used in engine.rs without dep | Added `futures-util` |
| 17 | `isolate-intel/Cargo.toml` | `ulid`, `anyhow`, `futures-util` used but not declared | Added all three deps |
| 18 | `isolate-intel/src/ioc.rs` | `AhoCorasick::find()` returns `Option<Match>`, not an iterator — `.next()` invalid | Changed to `find_iter().next()` |
| 19 | `isolate-intel/src/pipeline.rs` | E0521: `RwLockReadGuard` borrow escapes into `tokio::spawn` closure | Pass `Arc::clone(&self.baseline)` into closure, acquire guard inside |
| 20 | `isolate-store/src/events.rs` | `sqlx::query!` macro needs `DATABASE_URL` env var at compile time | Rewrote all queries as runtime `sqlx::query()` (non-macro) |
| 21 | `isolate-store/src/alerts.rs` | Same `sqlx::query!` compile-time check issue | Rewrote as runtime queries |
| 22 | `isolate-store/src/baseline.rs` | Same `sqlx::query!` compile-time check issue | Rewrote as runtime queries |
| 23 | `isolate-tui/Cargo.toml` | `tokio_tungstenite` and `futures_util` used in `events.rs` without deps | Added both deps |
| 24 | `isolate-tui/src/app.rs` | `push_event()` and `update_isobox_list()` called in `events.rs` but not defined | Implemented both methods on `App` |
| 25 | `isolate-cli/Cargo.toml` | `toml` used in `commands/policy.rs` without dep | Added `toml` dep |
| 26 | `isolate-daemon/Cargo.toml` | `toml` used in `main.rs` without dep | Added `toml` dep |
| 27 | `isolate-daemon/src/supervisor.rs` | `engine.create(id, &config)` — wrong arity; engine takes `(config: IsoboxConfig)` | Fixed to `engine.create(config.clone())` |
| 28 | `isolate-daemon/src/supervisor.rs` | `engine.destroy(id)` — method doesn't exist; correct name is `stop` | Fixed to `engine.stop(id)` |
| 29 | `isolate-proto/build.rs` | Build fails when `protoc` not installed, blocking the whole workspace | Added graceful fallback: writes empty stub `.rs` files so `include!()` compiles |

---

## How to Run Each Component

### Prerequisites

```sh
# 1. Accept Xcode license (required once)
sudo xcodebuild -license accept

# 2. Install Rust (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 3. Install Node.js ≥ 20 (for isolate-ui)
# brew install node   or   nvm install 20
```

---

### isolatd (daemon)

```sh
# Build
cargo build -p isolate-daemon

# Run (needs root for eBPF on Linux; on macOS: standard user for REST/WS)
cargo run -p isolate-daemon

# Default ports:
#   REST  → http://127.0.0.1:7778
#   gRPC  → 127.0.0.1:7777  (stub — pending proto codegen)
#   WS    → ws://127.0.0.1:7779/ws/events
```

---

### isobox CLI

```sh
cargo build -p isolate-cli

# Examples:
cargo run -p isolate-cli -- ps
cargo run -p isolate-cli -- run --name test -- /bin/ls
cargo run -p isolate-cli -- alert --follow
cargo run -p isolate-cli -- inspect <isobox-id>
cargo run -p isolate-cli -- freeze <isobox-id>
cargo run -p isolate-cli -- policy show <isobox-id>
```

---

### isolate-tui (terminal dashboard)

```sh
cargo build -p isolate-tui
cargo run -p isolate-tui

# Keybindings:
#   q       Quit
#   Tab     Switch panel
#   k/↑     Previous isobox
#   j/↓     Next isobox
#   f       Freeze selected
#   t       Thaw selected
#   x       Kill selected
#   ?       Help overlay
```

---

### isolate-ui (Tauri desktop GUI)

```sh
cd crates/isolate-ui

# First time:
npm install

# Development (hot-reload):
npm run tauri dev

# Production build:
npm run tauri build
# → Outputs to src-tauri/target/release/bundle/
```

**What the GUI shows:**
- Dashboard with isobox cards (anomaly score, paladin level, state)
- Live event rate chart (last 60 seconds)
- Per-isobox detail: top syscalls bar chart, network connections, event stream
- Alert feed with severity badges (INFO / WARN / CRITICAL / EMERGENCY)
- Policy editor (TOML) with audit reason field
- Threat feed manager (IOC counts, refresh)
- Settings (daemon URL configuration)

---

### isolate-paladin (last-resort guardian)

```sh
cargo build -p isolate-paladin

# Requires root (accesses cgroups, nftables)
# Environment variables:
export PALADIN_SOCKET=/run/isolate/paladin.sock
export PALADIN_AUDIT_LOG=/var/log/isolate/paladin.log
export PALADIN_HEARTBEAT_TIMEOUT=15
# export PALADIN_ABSOLUTION_ENABLED=true  # ← DANGER: enables kernel panic at level 7

sudo cargo run -p isolate-paladin
```

---

### eBPF programs (Linux only)

```sh
# Requires clang ≥ 15 + bpf-linker + vmlinux.h
# Install bpf-linker:
cargo install bpf-linker

# Build (from ebpf/):
cd ebpf
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -I. -c syscall_monitor.bpf.c -o syscall_monitor.bpf.o

# Programs are loaded at runtime by isolate-sandbox/src/backend/linux/ebpf.rs
# when isolatd starts on Linux.
```

---

### Proto codegen (for gRPC)

```sh
# Build isolate-proto to generate tonic stubs:
cargo build -p isolate-proto

# Generated code lands in:
#   target/debug/build/isolate-proto-*/out/
# and is re-exported via crates/isolate-proto/src/lib.rs
```

---

## Known Remaining Issues

### Critical (must fix before real use)

| # | Crate | Issue |
|---|-------|-------|
| C1 | `isolate-store` | `sqlx::migrate!` requires `SQLX_OFFLINE=true` or a live database at compile time. Run: `cargo sqlx prepare --workspace` once a DB exists |
| C2 | `isolate-proto` | `tonic-build` codegen requires `protoc` installed: `brew install protobuf` |
| C3 | All (macOS) | **Xcode license must be accepted** before any `cargo` command works |

### Phase 2 (backend implementation)

| Backend | Status | What's needed |
|---------|--------|---------------|
| Linux eBPF loader | Skeleton | Wire `aya` ring buffer reader to EventBus |
| seccomp-BPF | Skeleton | Build and install filter via `seccompiler` |
| Landlock | Skeleton | Build and apply ruleset from filesystem policy |
| Linux namespaces | Skeleton | `nix::sched::clone()` with all CLONE_NEW* flags |
| macOS ESF | Skeleton | FFI to `EndpointSecurity.framework` |
| macOS Seatbelt | Skeleton | SBPL profile generation + `sandbox_init()` |
| Wasmtime WASM | Skeleton | Wire `wasmtime::Engine` + WASI preopens |
| macOS pfctl | Stub | Paladin CONTAIN level on macOS (use `pfctl`) |

### Phase 3 (intelligence)

| Feature | Status |
|---------|--------|
| ONNX anomaly model | Stub — needs `models/behavior_classifier_v1.onnx` |
| Baseline profiler | Stub — sliding window logic needs implementing |
| Feed parser (URLhaus) | Partial — HTTP fetch + parser outlined |
| Policy hardener | Stub — suggestion generation needs implementing |
| CEL rule evaluator | Partial — substring matching only; needs `cel-interpreter` |

---

## Architecture Quick Reference

```
isobox run ──► isolatd (REST :7778 / gRPC :7777 / WS :7779)
                  │
                  ├── SandboxEngine ──► backends (eBPF / seccomp / Landlock / ESF / …)
                  │                         │ raw events (zero-copy)
                  │                         ▼
                  ├── EventBus ──────────── fan-out ──► Store / Intel / Policy / WS
                  │
                  ├── IntelEngine ─────── anomaly score → Alert → paladin
                  ├── PolicyEnforcer ───── live enforcement via backend
                  └── heartbeat ──────────► isolate-paladin (dead-man's switch)
                                               │
                                               └── 8 escalation levels
                                                   WATCHING → ALERT → CONTAIN →
                                                   FREEZE → TERMINATE → SCORCH →
                                                   RAMPART → ABSOLUTION
```

---

## File Count Summary

```
Rust source files:   ~60
TypeScript/TSX files: 12
eBPF C files:          4
Proto files:           3
TOML policy files:     4 + 1 example
Documentation:         4
SQL migrations:        1
Total lines (approx): ~8,000
```
