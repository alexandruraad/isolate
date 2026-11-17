//! TUI application state.

use isolate_events::event::IsolateEvent;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct IsoboxSummary {
    pub id: String,
    pub name: String,
    pub state: String,
    pub anomaly_score: Option<f32>,
    pub backends: Vec<String>,
    pub uptime_secs: Option<u64>,
    pub alert_count: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AlertEntry {
    pub severity: String,
    pub title: String,
    pub timestamp: String,
    pub isobox_id: String,
}

pub struct App {
    pub isoboxes: Vec<IsoboxSummary>,
    pub selected_isobox: usize,
    pub alerts: Vec<AlertEntry>,
    pub current_panel: Panel,
    pub show_help: bool,
    pub tick_count: u64,
    daemon_addr: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Panel {
    IsoboxList,
    SyscallGraph,
    NetworkMap,
    AnomalyGauge,
    AlertFeed,
}

impl App {
    pub fn new() -> Self {
        Self {
            isoboxes: vec![],
            selected_isobox: 0,
            alerts: vec![],
            current_panel: Panel::IsoboxList,
            show_help: false,
            tick_count: 0,
            daemon_addr: std::env::var("ISOLATE_DAEMON")
                .unwrap_or_else(|_| "127.0.0.1:7778".into()),
        }
    }

    pub fn tick(&mut self) {
        self.tick_count += 1;
        // Every 4 ticks (≈1 second), refresh data
        if self.tick_count % 4 == 0 {
            // In production: fetch from REST API asynchronously
            // For now: placeholder data
            if self.isoboxes.is_empty() {
                self.isoboxes = vec![
                    IsoboxSummary {
                        id: "01JK7X8VZQ2GFHM5NRPT4WY6D".into(),
                        name: "malware-sample".into(),
                        state: "running".into(),
                        anomaly_score: Some(0.82),
                        backends: vec!["ebpf".into(), "seccomp".into(), "landlock".into()],
                        uptime_secs: Some(134),
                        alert_count: Some(3),
                    },
                    IsoboxSummary {
                        id: "01JK7Y3MNPQ8VBHD6SRZFW4XC".into(),
                        name: "dev-env".into(),
                        state: "running".into(),
                        anomaly_score: Some(0.12),
                        backends: vec!["ebpf".into(), "seccomp".into()],
                        uptime_secs: Some(1112),
                        alert_count: Some(0),
                    },
                ];
            }
        }
    }

    pub fn next_panel(&mut self) {
        self.current_panel = match self.current_panel {
            Panel::IsoboxList   => Panel::SyscallGraph,
            Panel::SyscallGraph => Panel::NetworkMap,
            Panel::NetworkMap   => Panel::AnomalyGauge,
            Panel::AnomalyGauge => Panel::AlertFeed,
            Panel::AlertFeed    => Panel::IsoboxList,
        };
    }

    pub fn selected(&self) -> Option<&IsoboxSummary> {
        self.isoboxes.get(self.selected_isobox)
    }

    pub fn next_isobox(&mut self) {
        if !self.isoboxes.is_empty() {
            self.selected_isobox = (self.selected_isobox + 1) % self.isoboxes.len();
        }
    }

    pub fn prev_isobox(&mut self) {
        if !self.isoboxes.is_empty() {
            self.selected_isobox = self.selected_isobox
                .checked_sub(1)
                .unwrap_or(self.isoboxes.len() - 1);
        }
    }

    pub fn action_freeze(&mut self) {
        if let Some(ib) = self.selected() {
            // TODO: POST /api/v1/isoboxes/{id}/freeze
        }
    }

    pub fn action_thaw(&mut self) {
        if let Some(ib) = self.selected() {
            // TODO: POST /api/v1/isoboxes/{id}/thaw
        }
    }

    pub fn action_kill(&mut self) {
        // This would need confirmation in production
    }

    pub fn toggle_help(&mut self) {
        self.show_help = !self.show_help;
    }

    /// Push a live event from the WebSocket feed into the alert list if it's an alert.
    pub fn push_event(&mut self, event: IsolateEvent) {
        use isolate_events::event::EventBody;
        if let EventBody::Alert(a) = event.body {
            let entry = AlertEntry {
                severity: format!("{:?}", a.severity),
                title: a.title,
                timestamp: a.timestamp.to_rfc3339(),
                isobox_id: event.isobox_id.to_string(),
            };
            self.alerts.insert(0, entry);
            // Keep last 200 alerts in memory
            self.alerts.truncate(200);
        }
    }

    /// Replace the isobox list with data fetched from the REST API.
    pub fn update_isobox_list(&mut self, items: Vec<serde_json::Value>) {
        self.isoboxes = items.into_iter().filter_map(|v| {
            serde_json::from_value(v).ok()
        }).collect();
    }
}
