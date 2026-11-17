//! Behavioral baseline profiler.
//!
//! Maintains sliding-window histograms per workload class across three windows:
//!   5 min  — fine-grained, sensitive to short bursts
//!   60 min — medium-term patterns
//!   24 hr  — long-term behavioral profile

use isolate_events::event::{EventBody, IsolateEvent};
use isolate_core::types::WorkloadClass;
use std::collections::HashMap;

/// Time windows tracked (in minutes)
const WINDOWS: &[u32] = &[5, 60, 1440];

/// Behavioral baseline for a single workload class, across all windows.
#[derive(Debug, Default)]
pub struct BaselineProfiler {
    classes: HashMap<String, ClassBaseline>,
}

#[derive(Debug, Default)]
pub struct ClassBaseline {
    windows: HashMap<u32, WindowStats>,
    sample_count: u64,
    /// Whether we have enough data to score anomalies
    pub is_warm: bool,
    pub warmup_target: u64,
}

#[derive(Debug, Default, Clone)]
pub struct WindowStats {
    /// Syscall number → count
    pub syscall_counts: HashMap<u32, u64>,
    /// Network connection rate (connections/min)
    pub net_rate: f64,
    /// Process spawn rate (spawns/min)
    pub spawn_rate: f64,
    /// Unique file path count (approximate)
    pub file_path_count: u64,
    /// Total event count in this window
    pub total_events: u64,
}

impl BaselineProfiler {
    pub fn new() -> Self { Self::default() }

    /// Ingest an event and update the baseline for its workload class.
    pub fn ingest(&mut self, event: &IsolateEvent, class: &WorkloadClass) {
        let baseline = self.classes
            .entry(class.0.clone())
            .or_insert_with(|| ClassBaseline {
                warmup_target: 600, // 600 events ≈ 10 min of activity
                ..Default::default()
            });

        baseline.sample_count += 1;

        // Update all windows
        for window in WINDOWS {
            let stats = baseline.windows.entry(*window).or_default();
            stats.total_events += 1;

            match &event.body {
                EventBody::Syscall(s) => {
                    *stats.syscall_counts.entry(s.syscall_nr).or_insert(0) += 1;
                }
                EventBody::Network(_) => {
                    stats.net_rate = (stats.net_rate * 0.99) + 0.01; // EWMA
                }
                EventBody::Process(p) => {
                    use isolate_events::event::ProcessEventType;
                    if matches!(p.event_type, ProcessEventType::Fork | ProcessEventType::Clone) {
                        stats.spawn_rate = (stats.spawn_rate * 0.99) + 0.01;
                    }
                }
                EventBody::File(_) => {
                    stats.file_path_count += 1;
                }
                _ => {}
            }
        }

        if !baseline.is_warm && baseline.sample_count >= baseline.warmup_target {
            baseline.is_warm = true;
            tracing::info!(workload_class = %class, "behavioral baseline warm");
        }
    }

    /// Get the current stats for a workload class and window.
    pub fn stats(&self, class: &WorkloadClass, window_minutes: u32) -> Option<&WindowStats> {
        self.classes.get(&class.0)?.windows.get(&window_minutes)
    }

    /// Whether the baseline for a workload class is warm enough to score.
    pub fn is_warm(&self, class: &WorkloadClass) -> bool {
        self.classes.get(&class.0).map(|b| b.is_warm).unwrap_or(false)
    }

    /// Extract feature vector for ONNX inference.
    /// Returns None if baseline is not yet warm.
    pub fn feature_vector(&self, class: &WorkloadClass, current_event: &IsolateEvent) -> Option<Vec<f32>> {
        let baseline = self.classes.get(&class.0)?;
        if !baseline.is_warm { return None; }

        let mut features: Vec<f32> = Vec::new();

        // Feature group: syscall distribution (top 50 syscalls)
        for window in WINDOWS {
            if let Some(stats) = baseline.windows.get(window) {
                let total = stats.total_events.max(1) as f32;
                for nr in 0u32..50 {
                    let count = stats.syscall_counts.get(&nr).copied().unwrap_or(0) as f32;
                    features.push(count / total);
                }
                features.push(stats.net_rate as f32);
                features.push(stats.spawn_rate as f32);
                features.push((stats.file_path_count as f32).ln_1p());
            } else {
                features.extend(std::iter::repeat(0.0f32).take(53));
            }
        }

        Some(features)
    }
}
