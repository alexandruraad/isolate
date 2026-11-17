// Tauri commands — thin wrappers over the isolatd REST API.
// Called from the React frontend via `invoke('command_name', { ...args })`.

use crate::state::AppState;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::State;

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct CmdError {
    message: String,
}

impl From<reqwest::Error> for CmdError {
    fn from(e: reqwest::Error) -> Self {
        Self { message: e.to_string() }
    }
}
impl From<anyhow::Error> for CmdError {
    fn from(e: anyhow::Error) -> Self {
        Self { message: e.to_string() }
    }
}

type CmdResult<T> = Result<T, CmdError>;

// ── Helper ────────────────────────────────────────────────────────────────────

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap()
}

// ── Commands ──────────────────────────────────────────────────────────────────

/// List all active isoboxes.
#[tauri::command]
pub async fn list_isoboxes(state: State<'_, AppState>) -> CmdResult<Value> {
    let url = format!("{}/api/v1/isoboxes", state.rest_url());
    let resp = client().get(&url).send().await?.json::<Value>().await?;
    Ok(resp)
}

/// Get a single isobox by ID.
#[tauri::command]
pub async fn get_isobox(state: State<'_, AppState>, id: String) -> CmdResult<Value> {
    let url = format!("{}/api/v1/isoboxes/{}", state.rest_url(), id);
    let resp = client().get(&url).send().await?.json::<Value>().await?;
    Ok(resp)
}

/// Create a new isobox.
#[tauri::command]
pub async fn create_isobox(
    state: State<'_, AppState>,
    config_toml: String,
) -> CmdResult<Value> {
    let url = format!("{}/api/v1/isoboxes", state.rest_url());
    let body = serde_json::json!({ "config_toml": config_toml });
    let resp = client()
        .post(&url)
        .json(&body)
        .send()
        .await?
        .json::<Value>()
        .await?;
    Ok(resp)
}

/// Stop and destroy an isobox.
#[tauri::command]
pub async fn stop_isobox(state: State<'_, AppState>, id: String) -> CmdResult<Value> {
    let url = format!("{}/api/v1/isoboxes/{}", state.rest_url(), id);
    let resp = client().delete(&url).send().await?.json::<Value>().await?;
    Ok(resp)
}

/// Freeze an isobox (pause all processes).
#[tauri::command]
pub async fn freeze_isobox(state: State<'_, AppState>, id: String) -> CmdResult<Value> {
    let url = format!("{}/api/v1/isoboxes/{}/freeze", state.rest_url(), id);
    let resp = client().post(&url).send().await?.json::<Value>().await?;
    Ok(resp)
}

/// Thaw (resume) a frozen isobox.
#[tauri::command]
pub async fn thaw_isobox(state: State<'_, AppState>, id: String) -> CmdResult<Value> {
    let url = format!("{}/api/v1/isoboxes/{}/thaw", state.rest_url(), id);
    let resp = client().post(&url).send().await?.json::<Value>().await?;
    Ok(resp)
}

/// Create a forensic snapshot.
#[tauri::command]
pub async fn snapshot_isobox(
    state: State<'_, AppState>,
    id: String,
    output_path: String,
) -> CmdResult<Value> {
    let url = format!("{}/api/v1/isoboxes/{}/snapshot", state.rest_url(), id);
    let body = serde_json::json!({ "output_path": output_path });
    let resp = client()
        .post(&url)
        .json(&body)
        .send()
        .await?
        .json::<Value>()
        .await?;
    Ok(resp)
}

/// Get the current policy for an isobox.
#[tauri::command]
pub async fn get_policy(state: State<'_, AppState>, id: String) -> CmdResult<Value> {
    let url = format!("{}/api/v1/isoboxes/{}/policy", state.rest_url(), id);
    let resp = client().get(&url).send().await?.json::<Value>().await?;
    Ok(resp)
}

/// Apply a policy update.
#[tauri::command]
pub async fn apply_policy(
    state: State<'_, AppState>,
    id: String,
    patch_toml: String,
    reason: String,
) -> CmdResult<Value> {
    let url = format!("{}/api/v1/isoboxes/{}/policy", state.rest_url(), id);
    let body = serde_json::json!({ "patch_toml": patch_toml, "reason": reason });
    let resp = client()
        .put(&url)
        .json(&body)
        .send()
        .await?
        .json::<Value>()
        .await?;
    Ok(resp)
}

/// List recent alerts.
#[tauri::command]
pub async fn list_alerts(
    state: State<'_, AppState>,
    isobox_id: Option<String>,
    limit: Option<u32>,
) -> CmdResult<Value> {
    let mut url = format!("{}/api/v1/alerts", state.rest_url());
    let mut params = vec![];
    if let Some(id) = isobox_id { params.push(format!("isobox_id={}", id)); }
    if let Some(l) = limit { params.push(format!("limit={}", l)); }
    if !params.is_empty() { url.push('?'); url.push_str(&params.join("&")); }

    let resp = client().get(&url).send().await?.json::<Value>().await?;
    Ok(resp)
}

/// List configured threat feeds.
#[tauri::command]
pub async fn list_feeds(state: State<'_, AppState>) -> CmdResult<Value> {
    let url = format!("{}/api/v1/feeds", state.rest_url());
    let resp = client().get(&url).send().await?.json::<Value>().await?;
    Ok(resp)
}

/// Trigger a feed refresh.
#[tauri::command]
pub async fn update_feeds(state: State<'_, AppState>) -> CmdResult<Value> {
    let url = format!("{}/api/v1/feeds/update", state.rest_url());
    let resp = client().post(&url).send().await?.json::<Value>().await?;
    Ok(resp)
}

/// Get isolatd health.
#[tauri::command]
pub async fn get_health(state: State<'_, AppState>) -> CmdResult<Value> {
    let url = format!("{}/health", state.rest_url());
    let resp = client().get(&url).send().await?.json::<Value>().await?;
    Ok(resp)
}

/// Update the daemon URL (for connecting to a remote isolatd).
#[tauri::command]
pub fn set_daemon_url(
    state: State<'_, AppState>,
    rest_url: String,
    ws_url: String,
) {
    state.set_urls(rest_url, ws_url);
}
