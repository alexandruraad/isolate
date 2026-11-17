use crate::Store;
use chrono::{DateTime, Utc};
use isolate_core::id::IsoboxId;
use isolate_events::event::IsolateEvent;
use serde::{Deserialize, Serialize};
use sqlx::Row;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEvent {
    pub row_id: i64,
    pub seq: i64,
    pub isobox_id: String,
    pub backend: String,
    pub kind: String,
    pub timestamp: DateTime<Utc>,
    pub body_json: String,
}

#[derive(Debug, Clone, Default)]
pub struct EventQuery {
    pub isobox_id: Option<IsoboxId>,
    pub kind: Option<String>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

impl Store {
    /// Persist a normalized event to SQLite.
    pub async fn insert_event(&self, event: &IsolateEvent) -> isolate_core::Result<()> {
        let kind = event_kind(&event.body);
        let body = serde_json::to_string(&event.body)
            .map_err(|e| isolate_core::IsolateError::Serialization(e.to_string()))?;
        let ts = event.timestamp.to_rfc3339();

        sqlx::query(
            "INSERT INTO events (seq, isobox_id, backend, kind, timestamp, body_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
        )
        .bind(event.seq as i64)
        .bind(event.isobox_id.as_str())
        .bind(&event.backend)
        .bind(kind)
        .bind(ts)
        .bind(body)
        .execute(&self.pool)
        .await
        .map_err(|e| isolate_core::IsolateError::Store(e.to_string()))?;

        Ok(())
    }

    /// Query events with optional filters.
    pub async fn query_events(&self, q: &EventQuery) -> isolate_core::Result<Vec<StoredEvent>> {
        let limit = q.limit.unwrap_or(1000);
        let offset = q.offset.unwrap_or(0);

        let rows = sqlx::query(
            "SELECT rowid as row_id, seq, isobox_id, backend, kind, timestamp, body_json
             FROM events ORDER BY timestamp DESC LIMIT ?1 OFFSET ?2"
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| isolate_core::IsolateError::Store(e.to_string()))?;

        rows.into_iter().map(|r| {
            let ts_str: String = r.try_get("timestamp")
                .map_err(|e| isolate_core::IsolateError::Store(e.to_string()))?;
            let timestamp = ts_str.parse::<DateTime<Utc>>()
                .map_err(|e| isolate_core::IsolateError::Store(e.to_string()))?;
            Ok(StoredEvent {
                row_id: r.try_get("row_id").map_err(|e| isolate_core::IsolateError::Store(e.to_string()))?,
                seq: r.try_get("seq").map_err(|e| isolate_core::IsolateError::Store(e.to_string()))?,
                isobox_id: r.try_get("isobox_id").map_err(|e| isolate_core::IsolateError::Store(e.to_string()))?,
                backend: r.try_get("backend").map_err(|e| isolate_core::IsolateError::Store(e.to_string()))?,
                kind: r.try_get("kind").map_err(|e| isolate_core::IsolateError::Store(e.to_string()))?,
                timestamp,
                body_json: r.try_get("body_json").map_err(|e| isolate_core::IsolateError::Store(e.to_string()))?,
            })
        }).collect()
    }

    /// Count events for an isobox (used in TUI stats).
    pub async fn count_events(&self, isobox_id: &IsoboxId) -> isolate_core::Result<i64> {
        let row = sqlx::query(
            "SELECT COUNT(*) as count FROM events WHERE isobox_id = ?1"
        )
        .bind(isobox_id.as_str())
        .fetch_one(&self.pool)
        .await
        .map_err(|e| isolate_core::IsolateError::Store(e.to_string()))?;

        let count: i64 = row.try_get("count")
            .map_err(|e| isolate_core::IsolateError::Store(e.to_string()))?;
        Ok(count)
    }
}

fn event_kind(body: &isolate_events::event::EventBody) -> &'static str {
    match body {
        isolate_events::event::EventBody::Syscall(_)  => "syscall",
        isolate_events::event::EventBody::Network(_)  => "network",
        isolate_events::event::EventBody::File(_)     => "file",
        isolate_events::event::EventBody::Process(_)  => "process",
        isolate_events::event::EventBody::Exec(_)     => "exec",
        isolate_events::event::EventBody::Alert(_)    => "alert",
        isolate_events::event::EventBody::Raw { .. }  => "raw",
    }
}
