//! REST API server (axum).

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use isolate_events::bus::EventBus;
use isolate_sandbox::engine::SandboxEngine;
use isolate_store::Store;
use serde::Deserialize;
use std::net::SocketAddr;
use tracing::info;

use crate::demo::{self, DemoStore};
use crate::spawner::SpawnRegistry;

#[derive(Clone)]
struct AppState {
    engine:    SandboxEngine,
    store:     Store,
    bus:       EventBus,
    demo:      DemoStore,
    spawn_reg: SpawnRegistry,
}

pub async fn serve(
    addr: SocketAddr,
    engine: SandboxEngine,
    store: Store,
    bus: EventBus,
    demo: DemoStore,
    spawn_reg: SpawnRegistry,
) {
    let state = AppState { engine, store, bus, demo, spawn_reg };

    let app = Router::new()
        // Isobox lifecycle
        .route("/api/v1/isoboxes",              get(list_isoboxes))
        .route("/api/v1/isoboxes",              post(create_isobox))
        .route("/api/v1/isoboxes/:id",          get(get_isobox))
        .route("/api/v1/isoboxes/:id",          delete(stop_isobox))
        .route("/api/v1/isoboxes/:id/freeze",   post(freeze_isobox))
        .route("/api/v1/isoboxes/:id/thaw",     post(thaw_isobox))
        .route("/api/v1/isoboxes/:id/snapshot", post(snapshot_isobox))
        // Policy
        .route("/api/v1/isoboxes/:id/policy",   get(get_policy))
        // Events / alerts
        .route("/api/v1/isoboxes/:id/events",   get(query_events))
        .route("/api/v1/isoboxes/:id/alerts",   get(query_alerts))
        // Demo seeder
        .route("/api/v1/demo/seed",             post(seed_demo))
        // Health
        .route("/health",                        get(health))
        .with_state(state);

    info!(addr = %addr, "REST API listening");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// ── Health ────────────────────────────────────────────────────────────────────

async fn health() -> &'static str { "ok" }

// ── List isoboxes (returns rich objects matching the UI Isobox interface) ──────

async fn list_isoboxes(State(state): State<AppState>) -> impl IntoResponse {
    // Demo isoboxes first
    let mut items: Vec<serde_json::Value> = demo::snapshot(&state.demo)
        .into_iter()
        .map(|b| serde_json::to_value(b).unwrap())
        .collect();

    // Append real engine isoboxes that aren't in the demo set
    for id in state.engine.list().await {
        if items.iter().any(|v| v.get("id").and_then(|x| x.as_str()) == Some(id.as_str())) {
            continue;
        }
        let st = state.engine.state(&id).await
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".into());
        let cfg = state.engine.config(&id).await;
        let name = cfg.as_ref().map(|c| c.name.as_str().to_string())
            .unwrap_or_else(|| id.as_str().to_string());
        let class = cfg.as_ref().map(|c| c.workload_class.to_string())
            .unwrap_or_else(|| "general".into());
        let backends: Vec<String> = cfg.as_ref()
            .and_then(|c| c.backends.enabled.as_ref())
            .map(|e| e.iter().map(|b| b.to_string()).collect())
            .unwrap_or_default();
        items.push(serde_json::json!({
            "id":             id.as_str(),
            "name":           name,
            "state":          st,
            "backends":       backends,
            "workload_class": class,
            "created_at":     chrono::Utc::now().to_rfc3339(),
            "anomaly_score":  0.0,
            "paladin_level":  0,
            "event_count":    0,
            "alert_count":    0,
        }));
    }

    Json(serde_json::json!({ "isoboxes": items }))
}

// ── Create isobox (Path A — real process spawning) ───────────────────────────

#[derive(Deserialize)]
struct CreateBody {
    command:       Vec<String>,
    name:          Option<String>,
    class:         Option<String>,
    no_network:    Option<bool>,
    read_only_root: Option<bool>,
    #[allow(dead_code)]
    timeout:       Option<u64>,
}

async fn create_isobox(
    State(state): State<AppState>,
    Json(body): Json<CreateBody>,
) -> impl IntoResponse {
    use isolate_core::{
        types::{
            BackendConfig, EnforcementAction, ExportConfig, IntelConfig,
            IsoboxConfig, IsoboxTarget, PaladinConfig, PolicyConfig, WorkloadClass,
        },
        IsoboxId,
    };

    if body.command.is_empty() {
        return (StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "command is required" }))).into_response();
    }

    let id = IsoboxId::new();
    let name = body.name.unwrap_or_else(|| {
        body.command[0].split('/').last().unwrap_or("isobox").to_string()
    });
    let class = body.class.unwrap_or_else(|| "general".into());
    let created_at = chrono::Utc::now().to_rfc3339();

    let mut policy = PolicyConfig::default();
    if body.no_network.unwrap_or(false) {
        policy.network.default = EnforcementAction::Block;
    }
    if body.read_only_root.unwrap_or(false) {
        policy.filesystem.read_only.push("/".into());
        policy.filesystem.read_write.push("/tmp".into());
    }

    let config = IsoboxConfig {
        id:             id.clone(),
        name:           name.clone(),
        workload_class: WorkloadClass::custom(&class),
        description:    None,
        tags:           vec![],
        target: IsoboxTarget::Process {
            command:     body.command.clone(),
            environment: std::collections::HashMap::new(),
            user:        None,
            group:       None,
            working_dir: None,
        },
        backends:      BackendConfig::default(),
        policy,
        intelligence:  IntelConfig::default(),
        export:        ExportConfig::default(),
        paladin:       PaladinConfig::default(),
    };

    // Register isolation context with backends (non-fatal — may require root)
    if let Err(e) = state.engine.create(config.clone()).await {
        tracing::warn!("engine.create non-fatal error: {e}");
    }

    // Actually spawn the process and emit events
    let pid = crate::spawner::spawn_process(
        id.clone(),
        &config,
        state.bus.clone(),
        state.spawn_reg.clone(),
    )
    .await
    .unwrap_or_else(|e| {
        tracing::warn!("spawn_process failed: {e}");
        0
    });

    Json(serde_json::json!({
        "id":             id.as_str(),
        "name":           name,
        "state":          "running",
        "backends":       [],
        "workload_class": class,
        "created_at":     created_at,
        "anomaly_score":  0.0,
        "paladin_level":  0,
        "event_count":    0,
        "alert_count":    0,
        "pid":            pid,
        "command":        body.command,
    })).into_response()
}

// ── Get single isobox ─────────────────────────────────────────────────────────

async fn get_isobox(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // Check demo store first
    if let Some(b) = demo::snapshot(&state.demo).into_iter().find(|b| b.id == id) {
        return Json(serde_json::to_value(b).unwrap()).into_response();
    }
    let isobox_id = isolate_core::IsoboxId::from(id.as_str());
    match state.engine.state(&isobox_id).await {
        Some(st) => Json(serde_json::json!({ "id": id, "state": st.to_string() })).into_response(),
        None     => (StatusCode::NOT_FOUND, "isobox not found").into_response(),
    }
}

// ── Lifecycle actions ─────────────────────────────────────────────────────────

async fn stop_isobox(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    {
        let mut lock = state.demo.lock().unwrap();
        if let Some(b) = lock.isoboxes.iter_mut().find(|b| b.id == id) {
            b.state = "stopped".into();
            return Json(serde_json::json!({ "status": "stopped" })).into_response();
        }
    }
    let isobox_id = isolate_core::IsoboxId::from(id.as_str());
    // Kill the actual process first
    crate::spawner::abort(&isobox_id, &state.spawn_reg);
    match state.engine.stop(&isobox_id).await {
        Ok(())  => Json(serde_json::json!({ "status": "stopped" })).into_response(),
        Err(_)  => Json(serde_json::json!({ "status": "stopped" })).into_response(),
    }
}

async fn freeze_isobox(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    {
        let mut lock = state.demo.lock().unwrap();
        if let Some(b) = lock.isoboxes.iter_mut().find(|b| b.id == id) {
            b.state = "frozen".into();
            return Json(serde_json::json!({ "status": "frozen" })).into_response();
        }
    }
    let isobox_id = isolate_core::IsoboxId::from(id.as_str());
    match state.engine.freeze(&isobox_id).await {
        Ok(())  => Json(serde_json::json!({ "status": "frozen" })).into_response(),
        Err(e)  => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn thaw_isobox(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    {
        let mut lock = state.demo.lock().unwrap();
        if let Some(b) = lock.isoboxes.iter_mut().find(|b| b.id == id) {
            b.state = "running".into();
            return Json(serde_json::json!({ "status": "running" })).into_response();
        }
    }
    let isobox_id = isolate_core::IsoboxId::from(id.as_str());
    match state.engine.thaw(&isobox_id).await {
        Ok(())  => Json(serde_json::json!({ "status": "running" })).into_response(),
        Err(e)  => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn snapshot_isobox(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let isobox_id = isolate_core::IsoboxId::from(id.as_str());
    let path = std::path::PathBuf::from(format!("/var/lib/isolate/snapshots/{}", id));
    match state.engine.snapshot(&isobox_id, &path).await {
        Ok(())  => Json(serde_json::json!({ "path": path })).into_response(),
        Err(e)  => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ── Policy ────────────────────────────────────────────────────────────────────

async fn get_policy(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // Demo placeholder policy
    if demo::snapshot(&state.demo).iter().any(|b| b.id == id) {
        let toml = format!(
            "# Auto-generated policy for {id}\n\n\
             [network]\nallow_egress = false\nallow_ingress = false\n\n\
             [filesystem]\nread_only = true\ndenied_paths = [\"/etc/shadow\", \"/root\"]\n\n\
             [syscalls]\ndenied = [\"ptrace\", \"kexec_load\", \"create_module\"]\n"
        );
        return Json(serde_json::json!({ "toml": toml })).into_response();
    }
    let isobox_id = isolate_core::IsoboxId::from(id.as_str());
    match state.engine.config(&isobox_id).await {
        Some(cfg) => Json(serde_json::to_value(&cfg.policy).unwrap()).into_response(),
        None      => (StatusCode::NOT_FOUND, "isobox not found").into_response(),
    }
}

// ── Events / alerts ───────────────────────────────────────────────────────────

async fn query_events(
    State(state): State<AppState>,
    Path(_id): Path<String>,
) -> impl IntoResponse {
    match state.store.query_events(&Default::default()).await {
        Ok(evs) => Json(serde_json::json!({ "events": evs })).into_response(),
        Err(e)  => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn query_alerts(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let isobox_id = isolate_core::IsoboxId::from(id.as_str());
    match state.store.recent_alerts(&isobox_id, 100).await {
        Ok(alerts) => Json(serde_json::json!({ "alerts": alerts })).into_response(),
        Err(e)     => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ── Demo seed ─────────────────────────────────────────────────────────────────

async fn seed_demo(State(state): State<AppState>) -> impl IntoResponse {
    let count = demo::seed(state.demo, state.bus).await;
    Json(serde_json::json!({
        "status":   "seeded",
        "isoboxes": count,
        "note":     "Simulation running — anomaly escalates after ~8s, alerts fire at 0.42/0.68/0.86.",
    }))
}
