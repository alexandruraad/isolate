//! Demo seeder — injects mock isoboxes and synthetic events for presentation.
//!
//! Call `POST /api/v1/demo/seed` to start. The background simulation:
//!   - Emits syscall, network, and file events continuously
//!   - Escalates anomaly score on "suspicious-binary" over ~25 seconds
//!   - Fires WARN → CRITICAL → EMERGENCY alerts through the real event bus
//!   - Raises Paladin level in lock-step with the anomaly

use chrono::Utc;
use isolate_core::IsoboxId;
use isolate_events::{
    bus::EventBus,
    event::{
        Alert as EventAlert, AlertAction, AlertSeverity, EventBody,
        FileEvent, FileOp, IsolateEvent, NetworkDirection, NetworkEvent,
        NetworkProtocol, NetworkVerdict, SyscallEvent,
    },
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tokio::time::{interval, Duration};
use tracing::info;

// ── Public types ──────────────────────────────────────────────────────────────

/// In-memory mock isobox — field names match the TypeScript `Isobox` interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockIsobox {
    pub id: String,
    pub name: String,
    pub state: String,
    pub backends: Vec<String>,
    pub workload_class: String,
    pub created_at: String,
    pub anomaly_score: f64,
    pub paladin_level: u8,
    pub event_count: u64,
    pub alert_count: u32,
}

pub struct DemoState {
    pub isoboxes: Vec<MockIsobox>,
    pub generation: u64, // bumped on each seed call; simulation exits when generation changes
}

pub type DemoStore = Arc<Mutex<DemoState>>;

pub fn new_store() -> DemoStore {
    Arc::new(Mutex::new(DemoState {
        isoboxes: Vec::new(),
        generation: 0,
    }))
}

/// Returns the current isobox list (cloned for serialization).
pub fn snapshot(store: &DemoStore) -> Vec<MockIsobox> {
    store.lock().unwrap().isoboxes.clone()
}

// ── Seed ─────────────────────────────────────────────────────────────────────

const MALWARE_ID: &str = "01JNDEMO0MALWARE0XSUSPECT01";
const BUILD_ID:   &str = "01JNDEMO0BUILD000NPMREACT01";
const FROZEN_ID:  &str = "01JNDEMO0FROZEN00SUSPECT001";

pub async fn seed(store: DemoStore, bus: EventBus) -> usize {
    let now = Utc::now().to_rfc3339();

    let isoboxes = vec![
        MockIsobox {
            id: MALWARE_ID.into(),
            name: "suspicious-binary".into(),
            state: "running".into(),
            backends: vec!["seatbelt".into(), "esf".into()],
            workload_class: "malware-analysis".into(),
            created_at: now.clone(),
            anomaly_score: 0.0,
            paladin_level: 0,
            event_count: 0,
            alert_count: 0,
        },
        MockIsobox {
            id: BUILD_ID.into(),
            name: "npm-install-react".into(),
            state: "running".into(),
            backends: vec!["seccomp".into(), "landlock".into(), "namespaces".into()],
            workload_class: "build-tool".into(),
            created_at: now.clone(),
            anomaly_score: 0.0,
            paladin_level: 0,
            event_count: 0,
            alert_count: 0,
        },
        MockIsobox {
            id: FROZEN_ID.into(),
            name: "frozen-suspect".into(),
            state: "frozen".into(),
            backends: vec!["seatbelt".into()],
            workload_class: "malware-analysis".into(),
            created_at: now,
            anomaly_score: 0.92,
            paladin_level: 3,
            event_count: 12_847,
            alert_count: 7,
        },
    ];

    let count = isoboxes.len();
    let gen = {
        let mut lock = store.lock().unwrap();
        lock.isoboxes = isoboxes;
        lock.generation += 1;
        lock.generation
    };

    tokio::spawn(simulate(store.clone(), bus, gen));
    info!("demo: seeded {} isoboxes (generation {})", count, gen);
    count
}

// ── Background simulation ─────────────────────────────────────────────────────

const MALWARE_SYSCALLS: &[(&str, u32)] = &[
    ("mmap",     9),
    ("mprotect", 10),
    ("ptrace",   101),
    ("socket",   41),
    ("connect",  42),
    ("sendto",   44),
    ("recvfrom", 45),
    ("open",     2),
    ("read",     0),
    ("write",    1),
];

const BUILD_SYSCALLS: &[(&str, u32)] = &[
    ("read",   0),
    ("write",  1),
    ("openat", 257),
    ("stat",   4),
    ("execve", 59),
    ("clone",  56),
    ("wait4",  61),
    ("poll",   7),
    ("futex",  202),
];

async fn simulate(store: DemoStore, bus: EventBus, gen: u64) {
    let start = std::time::Instant::now();
    let mut seq: u64 = 10_000;
    let mut tick = interval(Duration::from_millis(175));
    let mut malware_events: u64 = 0;
    let mut build_events: u64 = 0;
    let mut warned = false;
    let mut crit   = false;
    let mut emerg  = false;

    let malware_id = IsoboxId::from(MALWARE_ID);
    let build_id   = IsoboxId::from(BUILD_ID);

    loop {
        tick.tick().await;

        // Exit if a newer seed call has superseded this simulation
        if store.lock().unwrap().generation != gen {
            info!("demo: simulation generation {} superseded, exiting", gen);
            return;
        }

        let elapsed = start.elapsed().as_secs_f64();
        let counter = (elapsed * 5.7) as usize;

        // ── Malware isobox events ─────────────────────────────────────────────

        let (sc_name, sc_nr) = MALWARE_SYSCALLS[counter % MALWARE_SYSCALLS.len()];
        let blocked = sc_name == "ptrace" || (elapsed > 10.0 && sc_name == "connect");

        bus.publish(IsolateEvent {
            seq,
            timestamp: Utc::now(),
            isobox_id: malware_id.clone(),
            backend: "esf".into(),
            body: EventBody::Syscall(SyscallEvent {
                pid: 42100,
                tid: 42100,
                ppid: 1,
                uid: 0,
                gid: 0,
                syscall_nr: sc_nr,
                syscall_name: sc_name.into(),
                args: [0; 6],
                ret: if blocked { Some(-1) } else { Some(0) },
                blocked,
                comm: "suspicious".into(),
            }),
        });
        seq += 1;
        malware_events += 1;

        // Every 7th tick: network connection attempt to C2 IP
        if counter % 7 == 0 {
            bus.publish(IsolateEvent {
                seq,
                timestamp: Utc::now(),
                isobox_id: malware_id.clone(),
                backend: "esf".into(),
                body: EventBody::Network(NetworkEvent {
                    pid: 42100,
                    comm: "suspicious".into(),
                    direction: NetworkDirection::Egress,
                    protocol: NetworkProtocol::Tcp,
                    src_addr: None,
                    src_port: None,
                    dst_addr: Some("185.220.101.47".parse().unwrap()),
                    dst_port: Some(4444),
                    length: 256,
                    verdict: if elapsed > 10.0 { NetworkVerdict::Block } else { NetworkVerdict::Allow },
                    ioc_match: None,
                }),
            });
            seq += 1;
            malware_events += 1;
        }

        // Every 11th tick: suspicious file read
        if counter % 11 == 0 {
            let path = if counter % 22 == 0 {
                "/root/.ssh/id_rsa"
            } else {
                "/etc/shadow"
            };
            bus.publish(IsolateEvent {
                seq,
                timestamp: Utc::now(),
                isobox_id: malware_id.clone(),
                backend: "esf".into(),
                body: EventBody::File(FileEvent {
                    pid: 42100,
                    comm: "suspicious".into(),
                    op: FileOp::Open,
                    path: path.into(),
                    flags: 0,
                    mode: None,
                    blocked: elapsed > 8.0,
                    sha256: None,
                    ioc_match: None,
                }),
            });
            seq += 1;
            malware_events += 1;
        }

        // ── Build isobox: normal busy syscalls ────────────────────────────────

        let (bsc_name, bsc_nr) = BUILD_SYSCALLS[counter % BUILD_SYSCALLS.len()];
        bus.publish(IsolateEvent {
            seq,
            timestamp: Utc::now(),
            isobox_id: build_id.clone(),
            backend: "seccomp".into(),
            body: EventBody::Syscall(SyscallEvent {
                pid: 55000 + (counter % 24) as u32,
                tid: 55000 + (counter % 24) as u32,
                ppid: 54999,
                uid: 1000,
                gid: 1000,
                syscall_nr: bsc_nr,
                syscall_name: bsc_name.into(),
                args: [0; 6],
                ret: Some(0),
                blocked: false,
                comm: "node".into(),
            }),
        });
        seq += 1;
        build_events += 1;

        // ── Anomaly escalation ────────────────────────────────────────────────

        let (anomaly, paladin, alert_count) = if elapsed >= 8.0 {
            let raw = ((elapsed - 8.0) / 20.0_f64).min(1.0);
            let score = (raw * raw * 0.96_f64).min(0.96);
            let level: u8 = if score >= 0.88 { 3 } else if score >= 0.70 { 2 } else if score >= 0.46 { 1 } else { 0 };

            // WARN at 0.42
            if !warned && score >= 0.42 {
                warned = true;
                emit_alert(&bus, &malware_id, seq, AlertSeverity::Warn, level,
                    "Anomalous syscall pattern detected",
                    "ptrace + mprotect sequence exceeds behavioral baseline by 3.1σ. \
                     Process is reading /etc/shadow and /root/.ssh/id_rsa.",
                    score as f32, AlertAction::Logged);
                seq += 1;
            }

            // CRITICAL at 0.68
            if !crit && score >= 0.68 {
                crit = true;
                emit_alert(&bus, &malware_id, seq, AlertSeverity::Critical, level,
                    "C2 beacon detected — outbound connection blocked",
                    "TCP egress to 185.220.101.47:4444 matched Cobalt Strike C2 beacon \
                     in MalwareBazaar IOC feed (confidence 0.94). Connection dropped by policy.",
                    score as f32, AlertAction::PaladinEscalated);
                seq += 1;
            }

            // EMERGENCY at 0.86
            if !emerg && score >= 0.86 {
                emerg = true;
                emit_alert(&bus, &malware_id, seq, AlertSeverity::Emergency, level,
                    "Memory injection attempt — isobox frozen by Paladin",
                    "PTRACE_POKEDATA into PID 1 detected. Lateral movement attempt contained. \
                     Paladin escalated to FREEZE (level 3). Forensic snapshot queued.",
                    score as f32, AlertAction::Frozen);
                seq += 1;
            }

            let ac = warned as u32 + crit as u32 + emerg as u32;
            (score, level, ac)
        } else {
            (0.0, 0, 0)
        };

        // ── Update mock isobox stats ──────────────────────────────────────────
        {
            let mut lock = store.lock().unwrap();
            if lock.generation != gen { return; } // double-check

            if let Some(b) = lock.isoboxes.iter_mut().find(|b| b.id == MALWARE_ID) {
                b.event_count   = malware_events;
                b.anomaly_score = anomaly;
                b.paladin_level = paladin;
                b.alert_count   = alert_count;
                // Freeze visually when Paladin triggers FREEZE
                if emerg { b.state = "frozen".into(); }
            }
            if let Some(b) = lock.isoboxes.iter_mut().find(|b| b.id == BUILD_ID) {
                b.event_count = build_events;
            }
        }
    }
}

fn emit_alert(
    bus: &EventBus,
    isobox_id: &IsoboxId,
    seq: u64,
    severity: AlertSeverity,
    paladin_level: u8,
    title: &str,
    detail: &str,
    anomaly_score: f32,
    action_taken: AlertAction,
) {
    bus.publish(IsolateEvent {
        seq,
        timestamp: Utc::now(),
        isobox_id: isobox_id.clone(),
        backend: "paladin".into(),
        body: EventBody::Alert(EventAlert {
            id: format!("alert_{seq}"),
            timestamp: Utc::now(),
            isobox_id: isobox_id.clone(),
            severity,
            title: title.into(),
            detail: detail.into(),
            anomaly_score: Some(anomaly_score),
            ioc_match: None,
            triggering_event: None,
            action_taken,
            paladin_level: Some(paladin_level),
        }),
    });
}
