// App-wide shared state for the Tauri backend.

use std::sync::RwLock;

pub struct AppState {
    /// Base URL for the isolatd REST API
    rest_url: RwLock<String>,
    /// WebSocket URL for the live event stream
    ws_url: RwLock<String>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            rest_url: RwLock::new("http://127.0.0.1:7778".into()),
            ws_url:   RwLock::new("ws://127.0.0.1:7779/ws/events".into()),
        }
    }

    pub fn rest_url(&self) -> String {
        self.rest_url.read().unwrap().clone()
    }

    pub fn ws_url(&self) -> String {
        self.ws_url.read().unwrap().clone()
    }

    pub fn set_urls(&self, rest: String, ws: String) {
        *self.rest_url.write().unwrap() = rest;
        *self.ws_url.write().unwrap()   = ws;
    }
}
