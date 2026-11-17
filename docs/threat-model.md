# isolate — Threat Model

## Scope

This document models the threats that isolate itself is designed to defend against,
as well as the threats to isolate's own integrity (i.e., how an attacker might
try to subvert or escape the sandboxing system).

---

## What isolate protects

### Primary threat actors

| Actor | Description |
|-------|-------------|
| **Malicious binary** | A downloaded executable containing malware, ransomware, a supply-chain compromise, or a backdoor |
| **Compromised dependency** | A legitimately-installed library or tool that has been poisoned (typosquatting, dependency confusion, upstream compromise) |
| **Vulnerable service** | A microservice that has been exploited in production; attacker now has code execution inside the process |
| **Insider threat** | A developer or CI/CD job accidentally (or deliberately) running malicious code |

### Assets being protected

- **Host filesystem** — kernel, OS files, user data, SSH keys, cloud credentials
- **Host network** — other hosts reachable from this machine, cloud metadata endpoints
- **Host processes** — other processes running on the system (privilege escalation targets)
- **Secrets** — environment variables, mounted secret files, credential stores
- **The sandbox system itself** — isolatd, eBPF maps, paladin socket

---

## Threat categories

### T1 — Filesystem escape

- **Attack**: The workload reads/writes files outside its allowed paths using
  absolute paths, symlink traversal, `/proc/self/fd`, or `open_by_handle_at`.
- **Mitigations**:
  - Landlock ruleset blocks path access at the kernel VFS layer
  - eBPF LSM `file_open` hook blocks and records any attempt matching the deny list
  - Container rootfs (OCI/namespace) provides an independent filesystem boundary
  - seccomp blocks `open_by_handle_at` (no inode handle tricks)
  - Seatbelt on macOS provides `allow file-read-metadata` control

### T2 — Network exfiltration

- **Attack**: The workload attempts to send data to an attacker-controlled server
  via TCP/UDP/ICMP, DNS tunnelling, or raw sockets.
- **Mitigations**:
  - TC/XDP eBPF programs drop packets not matching the allowlist
  - eBPF LSM `socket_connect` blocks connection attempts at the socket layer
  - `nftables` rules (applied by paladin at CONTAIN level) provide a
    second independent layer not dependent on eBPF
  - `dns_over_https = true` prevents DNS tunnelling over UDP/53
  - Network namespace gives the isobox an isolated network stack

### T3 — Privilege escalation

- **Attack**: The workload exploits a kernel vulnerability or misconfiguration
  to gain root / CAP_SYS_ADMIN.
- **Mitigations**:
  - Run as unprivileged UID (100 000+) with empty capability set
  - User namespace drops all capabilities outside the namespace
  - seccomp blocks `setuid`, `setgid`, `capset`, `unshare`, `setns`
  - eBPF LSM hooks on `bprm_check_security` detect unexpected exec chains
  - Anomaly scorer detects unusual privilege-related syscall sequences

### T4 — Container escape / namespace breakout

- **Attack**: The workload exploits runc/containerd vulnerabilities or
  kernel namespace implementation bugs to reach the host.
- **Mitigations**:
  - `pivot_root` + bind mount isolation in namespace backend
  - seccomp blocks `unshare`, `setns`, `pivot_root`
  - KVM/Firecracker backend provides hardware-level isolation (VM boundary)
  - eBPF monitors all `clone` and `unshare` syscalls

### T5 — IOC-matched malware behaviour

- **Attack**: The workload contacts known-malicious IPs/domains, writes
  known malware hashes, or exhibits known C2 communication patterns.
- **Mitigations**:
  - IocMatcher checks every network connection against URLhaus/ThreatFox
  - SHA256 of every executed binary is computed and checked against MalwareBazaar
  - Immediate alert + configurable auto-action (freeze/kill) on IOC hit

### T6 — Anomalous behaviour (zero-day / novel malware)

- **Attack**: Novel malware not in any feed; behaviour is statistically abnormal
  but not matched by signatures.
- **Mitigations**:
  - ONNX-based isolation forest detects deviations from the baseline
  - Baseline covers syscall rates, file access patterns, network entropy, fork rates
  - Score ≥ threshold triggers alert; auto-freeze/kill configurable
  - Paladin escalates independently based on anomaly score

### T7 — Persistence / lateral movement

- **Attack**: Malware installs a cron job, modifies system files, or spreads
  to other containers/VMs on the same host.
- **Mitigations**:
  - Read-only filesystem for system paths
  - Network allowlist prevents C2 and lateral movement
  - Fork/exec policy blocks spawning of persistence mechanisms
  - Anomaly scorer detects unusual write patterns to system paths

### T8 — Anti-analysis / sandbox detection

- **Attack**: Malware detects it is inside a sandbox (via timing, `/proc` inspection,
  known eBPF artefacts) and goes dormant.
- **Mitigations**:
  - eBPF programs are not visible to the sandboxed process (they live in kernel space)
  - VM-based backend hides the host entirely
  - `prctl(PR_SET_DUMPABLE, 0)` prevents `/proc` enumeration by other processes
  - Paladin's out-of-band monitoring operates entirely outside the sandboxed path

---

## Threats to isolate itself

### I1 — Compromised isolatd

- **Attack**: An attacker with root access modifies `isolatd` to disable enforcement.
- **Mitigation**: The paladin monitors isoboxes **independently** of `isolatd`.
  If `isolatd` stops sending heartbeats, paladin escalates at CONTAIN level.
  The paladin does NOT trust eBPF (uses `nftables` for network containment).

### I2 — eBPF map tampering

- **Attack**: An attacker writes to the `syscall_policy` or `net_allowlist` BPF maps
  to disable enforcement.
- **Mitigation**: Maps are pinned under `/sys/fs/bpf/isolate/` with 0600 permissions.
  The paladin's sentinel checks map integrity via `/sys/fs/bpf` stat.
  Seccomp filter blocks `bpf(2)` syscall inside the isobox.

### I3 — Paladin socket compromise

- **Attack**: An attacker impersonates `isolatd` on the paladin's Unix socket.
- **Mitigation**: Socket is `0600` owned by root. In production, mTLS authentication
  is applied over the socket (Phase 5 hardening).

### I4 — Kernel module / BPF verifier bypass

- **Attack**: A kernel vulnerability allows the sandboxed process to escape the
  seccomp/eBPF/Landlock boundary entirely.
- **Mitigation**: VM backend (KVM/Firecracker) provides a hardware boundary independent
  of kernel software. The paladin's ABSOLUTION level forces a kdump for forensics.

---

## Out of scope

- Physical access attacks (cold boot, DMA attacks)
- Attacks against the isolate build toolchain (supply-chain of isolate itself)
- Side-channel attacks (Spectre/Meltdown variants)
- Attacks that require kernel 0-days with no existing PoC

---

## Security disclosure

Report vulnerabilities to: `security@isolate-project.example` (placeholder).
PGP key: published at the project repository.
Response SLA: 48 hours acknowledgement, 90 days disclosure.
