// SPDX-License-Identifier: Apache-2.0
//! Keyboard input handler + WebSocket event feed for the TUI.
//!
//! Runs a background task that:
//!   1. Connects to `isolatd` WebSocket (`ws://localhost:7779/ws/events`)
//!   2. Deserialises incoming `IsolateEvent` JSON and pushes them to the App
//!   3. Handles reconnect with exponential back-off

use anyhow::Result;
use isolate_events::event::IsolateEvent;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{Duration, sleep};
use tracing::{info, warn, error};

use crate::app::App;

/// Start the WebSocket feed task.
///
/// Connects to `ws_url` and forwards events to `app` via `App::push_event`.
/// Reconnects automatically on disconnect.
pub fn spawn_ws_feed(app: Arc<Mutex<App>>, ws_url: String) {
    tokio::spawn(async move {
        let mut backoff = Duration::from_secs(1);

        loop {
            info!(%ws_url, "connecting to isolatd WebSocket");
            match connect_and_stream(app.clone(), &ws_url).await {
                Ok(_) => {
                    info!("WebSocket stream ended — reconnecting");
                    backoff = Duration::from_secs(1);
                }
                Err(e) => {
                    warn!("WebSocket error: {e} — retrying in {:.1}s", backoff.as_secs_f32());
                    sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(60));
                }
            }
        }
    });
}

async fn connect_and_stream(app: Arc<Mutex<App>>, ws_url: &str) -> Result<()> {
    use tokio_tungstenite::connect_async;
    use futures_util::StreamExt;

    let (mut stream, _) = connect_async(ws_url).await?;

    while let Some(msg) = stream.next().await {
        match msg? {
            tokio_tungstenite::tungstenite::Message::Text(text) => {
                // Skip lag notices and other meta-messages
                if text.contains("\"type\":\"lag_notice\"") {
                    let dropped: serde_json::Value = serde_json::from_str(&text)
                        .unwrap_or(serde_json::Value::Null);
                    let n = dropped.get("dropped").and_then(|v| v.as_u64()).unwrap_or(0);
                    warn!("ws: server dropped {n} events (ring buffer lag)");
                    continue;
                }

                match serde_json::from_str::<IsolateEvent>(&text) {
                    Ok(event) => {
                        let mut app = app.lock().await;
                        app.push_event(event);
                    }
                    Err(e) => {
                        warn!("ws: failed to parse event: {e}");
                    }
                }
            }
            tokio_tungstenite::tungstenite::Message::Close(_) => {
                info!("ws: server closed connection");
                return Ok(());
            }
            tokio_tungstenite::tungstenite::Message::Ping(_) => {
                // tungstenite handles pong automatically
            }
            _ => {}
        }
    }

    Ok(())
}

/// Poll the isolatd REST API once and update App state.
/// Called from `App::tick()` as the primary refresh path.
pub async fn fetch_isoboxes(app: Arc<Mutex<App>>, base_url: &str) -> Result<()> {
    let url = format!("{}/api/v1/isoboxes", base_url);
    let resp = reqwest::get(&url).await?;

    if !resp.status().is_success() {
        return Err(anyhow::anyhow!("REST GET /isoboxes returned {}", resp.status()));
    }

    let list: serde_json::Value = resp.json().await?;
    if let Some(items) = list.as_array() {
        let mut app = app.lock().await;
        app.update_isobox_list(items.clone());
    }

    Ok(())
}
