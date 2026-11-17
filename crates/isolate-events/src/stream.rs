use crate::event::IsolateEvent;
use std::pin::Pin;
use tokio::sync::broadcast;

/// A stream of IsolateEvents from a sandbox backend.
pub type EventStream = Pin<Box<dyn futures_core::Stream<Item = IsolateEvent> + Send>>;

/// A broadcast channel handle for subscribing to live events.
pub struct EventBroadcast {
    sender: broadcast::Sender<IsolateEvent>,
}

impl EventBroadcast {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    pub fn publish(&self, event: IsolateEvent) {
        // Ignore send errors — no subscribers is fine
        let _ = self.sender.send(event);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<IsolateEvent> {
        self.sender.subscribe()
    }
}
