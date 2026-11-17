use crate::event::{Alert, IsolateEvent};
use crossbeam_channel::{bounded, Receiver, Sender};
use isolate_core::id::IsoboxId;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{debug, warn};

/// Capacity of the internal event ring buffer.
/// Events dropped if consumers can't keep up (back-pressure strategy: drop-oldest).
const BUS_CAPACITY: usize = 65_536;
const BROADCAST_CAPACITY: usize = 4_096;

/// The EventBus receives raw events from all backends and fans them out
/// to multiple consumers: store, intel pipeline, policy enforcer, UI streams.
///
/// All fan-out is non-blocking. Slow consumers get dropped events, not back-pressure,
/// to ensure the kernel-side ring buffer never fills up.
#[derive(Clone)]
pub struct EventBus {
    inner: Arc<BusInner>,
}

struct BusInner {
    /// MPSC channel: backends → bus dispatcher
    ingest_tx: Sender<IsolateEvent>,
    /// Broadcast: bus → all subscribers (store, intel, policy, UI)
    event_broadcast: broadcast::Sender<IsolateEvent>,
    /// Separate alert broadcast (alerts are a subset of events, but prioritized)
    alert_broadcast: broadcast::Sender<Alert>,
}

impl EventBus {
    pub fn new() -> (Self, EventBusWorker) {
        let (ingest_tx, ingest_rx) = bounded(BUS_CAPACITY);
        let (event_broadcast, _) = broadcast::channel(BROADCAST_CAPACITY);
        let (alert_broadcast, _) = broadcast::channel(BROADCAST_CAPACITY);

        let inner = Arc::new(BusInner {
            ingest_tx,
            event_broadcast: event_broadcast.clone(),
            alert_broadcast: alert_broadcast.clone(),
        });

        let bus = Self { inner };
        let worker = EventBusWorker {
            ingest_rx,
            event_broadcast,
            alert_broadcast,
        };

        (bus, worker)
    }

    /// Publish an event from a backend. Non-blocking. Returns false if dropped.
    pub fn publish(&self, event: IsolateEvent) -> bool {
        match self.inner.ingest_tx.try_send(event) {
            Ok(()) => true,
            Err(crossbeam_channel::TrySendError::Full(ev)) => {
                warn!(isobox_id = %ev.isobox_id, "EventBus ring buffer full — event dropped");
                false
            }
            Err(crossbeam_channel::TrySendError::Disconnected(_)) => false,
        }
    }

    /// Subscribe to all events from all isoboxes.
    pub fn subscribe_events(&self) -> broadcast::Receiver<IsolateEvent> {
        self.inner.event_broadcast.subscribe()
    }

    /// Subscribe to alerts only.
    pub fn subscribe_alerts(&self) -> broadcast::Receiver<Alert> {
        self.inner.alert_broadcast.subscribe()
    }

    /// Subscribe to events from a specific isobox (filtered).
    pub fn subscribe_isobox(&self, id: IsoboxId) -> IsoboxEventReceiver {
        IsoboxEventReceiver {
            inner: self.inner.event_broadcast.subscribe(),
            filter: id,
        }
    }
}

/// Runs the dispatch loop: reads from the ingest channel, fans out to all subscribers.
/// Should be run as a dedicated tokio task.
pub struct EventBusWorker {
    ingest_rx: Receiver<IsolateEvent>,
    event_broadcast: broadcast::Sender<IsolateEvent>,
    alert_broadcast: broadcast::Sender<Alert>,
}

impl EventBusWorker {
    /// Blocking dispatch loop. Run with `tokio::task::spawn_blocking`.
    pub fn run(self) {
        for event in self.ingest_rx {
            // Extract alerts and broadcast separately
            if let crate::event::EventBody::Alert(ref alert) = event.body {
                if self.alert_broadcast.receiver_count() > 0 {
                    let _ = self.alert_broadcast.send(alert.clone());
                }
            }

            if self.event_broadcast.receiver_count() > 0 {
                if let Err(e) = self.event_broadcast.send(event) {
                    debug!("EventBus broadcast: no receivers ({})", e);
                }
            }
        }
    }
}

/// A filtered event receiver that only yields events from a specific isobox.
pub struct IsoboxEventReceiver {
    inner: broadcast::Receiver<IsolateEvent>,
    filter: IsoboxId,
}

impl IsoboxEventReceiver {
    pub async fn recv(&mut self) -> Option<IsolateEvent> {
        loop {
            match self.inner.recv().await {
                Ok(ev) if ev.isobox_id == self.filter => return Some(ev),
                Ok(_) => continue, // not our isobox
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!(isobox_id = %self.filter, "IsoboxEventReceiver lagged by {n} events");
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}
