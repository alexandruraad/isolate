// WebSocket relay: connects to isolatd's WS event stream and emits
// Tauri events to the frontend.
//
// Frontend listens with:
//   listen("isolate:event",        (ev) => addEvent(ev.payload))
//   listen("isolate:alert",        (ev) => addAlert(ev.payload))
//   listen("isolate:connected",    ()   => setConnected(true))
//   listen("isolate:disconnected", ()   => setConnected(false))

use futures_util::StreamExt;
use tauri::{AppHandle, Manager};
use tokio::time::{sleep, Duration};
use tracing::{info, warn};

pub fn spawn_relay(app: AppHandle, ws_url: String) {
    tauri::async_runtime::spawn(async move {
        let mut backoff = Duration::from_secs(1);
        loop {
            info!(%ws_url, "ws relay: connecting");
            match stream_events(app.clone(), &ws_url).await {
                Ok(_) => {
                    let _ = app.emit_all("isolate:disconnected", ());
                    info!("ws relay: stream ended, reconnecting");
                    backoff = Duration::from_secs(1);
                }
                Err(e) => {
                    let _ = app.emit_all("isolate:disconnected", e.to_string());
                    warn!("ws relay: error {e}, retry in {:.1}s", backoff.as_secs_f32());
                    sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                }
            }
        }
    });
}

async fn stream_events(app: AppHandle, ws_url: &str) -> anyhow::Result<()> {
    use tokio_tungstenite::connect_async;
    use tokio_tungstenite::tungstenite::Message;

    let (mut stream, _) = connect_async(ws_url).await?;
    let _ = app.emit_all("isolate:connected", ws_url);

    while let Some(msg) = stream.next().await {
        match msg? {
            Message::Text(text) => {
                if let Ok(mut val) = serde_json::from_str::<serde_json::Value>(&text) {
                    // ── Timestamp: convert RFC3339 string → epoch milliseconds ──
                    // The UI stores timestamps as numbers and uses Date.now() (ms) for comparison.
                    let ts_ms = val
                        .get("timestamp")
                        .and_then(|t| t.as_str())
                        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                        .map(|dt| dt.timestamp_millis())
                        .unwrap_or_else(|| chrono::Utc::now().timestamp_millis());

                    if let Some(obj) = val.as_object_mut() {
                        obj.insert("timestamp".into(), serde_json::json!(ts_ms));
                    }

                    // ── Alert detection: body.kind == "alert" ──
                    // (EventBody enum uses #[serde(tag = "kind")] so variant is in "kind" field,
                    //  not as a nested "alert" key)
                    let is_alert = val
                        .get("body")
                        .and_then(|b| b.get("kind"))
                        .and_then(|k| k.as_str())
                        == Some("alert");

                    if is_alert {
                        // ── Reshape to the UI Alert interface ──
                        //
                        // Daemon Alert (body fields):       UI Alert interface:
                        //   id           → id
                        //   isobox_id    → isobox_id        (from outer IsolateEvent)
                        //   severity     → severity          (string→u8: emergency=3, critical=2, warn=1, info=0)
                        //   title        → title
                        //   detail       → detail
                        //   anomaly_score→ anomaly_score
                        //   action_taken → action_taken
                        //   paladin_level→ paladin_level
                        //   timestamp    → created_at
                        let body = val.get("body").cloned().unwrap_or(serde_json::Value::Null);

                        let severity: u8 = match body.get("severity").and_then(|s| s.as_str()) {
                            Some("emergency") => 3,
                            Some("critical")  => 2,
                            Some("warn")      => 1,
                            _                 => 0,
                        };

                        let alert_ui = serde_json::json!({
                            "id":            body.get("id"),
                            "isobox_id":     val.get("isobox_id"),
                            "severity":      severity,
                            "title":         body.get("title"),
                            "detail":        body.get("detail"),
                            "anomaly_score": body.get("anomaly_score").and_then(|v| v.as_f64()).unwrap_or(0.0),
                            "action_taken":  body.get("action_taken"),
                            "paladin_level": body.get("paladin_level").and_then(|v| v.as_u64()).unwrap_or(0),
                            "created_at":    body.get("timestamp"),
                        });

                        let _ = app.emit_all("isolate:alert", &alert_ui);
                    } else {
                        let _ = app.emit_all("isolate:event", &val);
                    }
                }
            }
            Message::Close(_) => return Ok(()),
            _ => {}
        }
    }
    Ok(())
}
