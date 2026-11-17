// SPDX-License-Identifier: Apache-2.0
//! WebSocket live event stream — pushes `IsolateEvent` JSON to connected clients.
//!
//! Endpoint: `ws://localhost:7779/ws/events`
//!
//! Clients receive a continuous stream of newline-delimited JSON objects.
//! Optionally filter by isobox_id via query param: `?isobox_id=<id>`

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    response::IntoResponse,
    routing::get,
    Router,
};
use isolate_events::bus::EventBus;
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::time::{Duration, interval};
use tracing::{info, debug, warn};

#[derive(Clone)]
pub struct WsState {
    pub bus: EventBus,
}

#[derive(Deserialize, Default)]
struct EventsQuery {
    isobox_id: Option<String>,
}

pub fn router(bus: EventBus) -> Router {
    let state = Arc::new(WsState { bus });
    Router::new()
        .route("/ws/events", get(ws_events_handler))
        .with_state(state)
}

async fn ws_events_handler(
    ws: WebSocketUpgrade,
    Query(params): Query<EventsQuery>,
    State(state): State<Arc<WsState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws(socket, state, params.isobox_id))
}

async fn handle_ws(mut socket: WebSocket, state: Arc<WsState>, filter_id: Option<String>) {
    let addr_info = filter_id.as_deref().unwrap_or("*");
    info!(filter = %addr_info, "WebSocket client connected");

    let mut rx = state.bus.subscribe_events();
    let mut ping_ticker = interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            event_result = rx.recv() => {
                match event_result {
                    Ok(event) => {
                        // Apply optional isobox_id filter
                        if let Some(ref id) = filter_id {
                            if event.isobox_id.as_str() != id.as_str() {
                                continue;
                            }
                        }

                        match serde_json::to_string(&event) {
                            Ok(json) => {
                                if socket.send(Message::Text(json)).await.is_err() {
                                    debug!("WebSocket client disconnected");
                                    return;
                                }
                            }
                            Err(e) => {
                                warn!("ws: failed to serialize event: {e}");
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!("ws: receiver lagged {n} events");
                        // Send a synthetic lag notice
                        let notice = serde_json::json!({
                            "type": "lag_notice",
                            "dropped": n
                        });
                        if socket.send(Message::Text(notice.to_string())).await.is_err() {
                            return;
                        }
                    }
                    Err(_) => {
                        // Bus closed — server shutting down
                        break;
                    }
                }
            }

            _ = ping_ticker.tick() => {
                if socket.send(Message::Ping(vec![])).await.is_err() {
                    return;
                }
            }

            // Drain incoming messages (handle close frames + pong)
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => {
                        info!("WebSocket client closed connection");
                        return;
                    }
                    Some(Err(_)) => return,
                    _ => {}
                }
            }
        }
    }
}

/// Start the standalone WebSocket server (axum HTTP server on `ws_addr`).
pub async fn serve(ws_addr: SocketAddr, bus: EventBus) {
    let app = router(bus);
    info!(addr = %ws_addr, "WebSocket server listening");
    let listener = tokio::net::TcpListener::bind(ws_addr)
        .await
        .expect("failed to bind WebSocket addr");
    axum::serve(listener, app)
        .await
        .expect("WebSocket server crashed");
}
