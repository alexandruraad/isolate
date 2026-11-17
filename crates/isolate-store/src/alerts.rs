use crate::Store;
use chrono::{DateTime, Utc};
use isolate_core::id::IsoboxId;
use isolate_events::event::Alert;
use serde::{Deserialize, Serialize};
use sqlx::Row;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAlert {
    pub row_id: i64,
    pub alert_id: String,
    pub isobox_id: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
    pub timestamp: DateTime<Utc>,
    pub anomaly_score: Option<f64>,
    pub action_taken: String,
    pub paladin_level: Option<i64>,
    pub full_json: String,
}

impl Store {
    pub async fn insert_alert(&self, alert: &Alert) -> isolate_core::Result<()> {
        let severity = format!("{:?}", alert.severity).to_lowercase();
        let action = format!("{:?}", alert.action_taken);
        let full_json = serde_json::to_string(alert)
            .map_err(|e| isolate_core::IsolateError::Serialization(e.to_string()))?;
        let ts = alert.timestamp.to_rfc3339();

        sqlx::query(
            "INSERT INTO alerts
                (alert_id, isobox_id, severity, title, detail, timestamp,
                 anomaly_score, action_taken, paladin_level, full_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"
        )
        .bind(&alert.id)
        .bind(alert.isobox_id.as_str())
        .bind(severity)
        .bind(&alert.title)
        .bind(&alert.detail)
        .bind(ts)
        .bind(alert.anomaly_score.map(|s| s as f64))
        .bind(action)
        .bind(alert.paladin_level.map(|l| l as i64))
        .bind(full_json)
        .execute(&self.pool)
        .await
        .map_err(|e| isolate_core::IsolateError::Store(e.to_string()))?;

        Ok(())
    }

    pub async fn recent_alerts(
        &self,
        isobox_id: &IsoboxId,
        limit: i64,
    ) -> isolate_core::Result<Vec<StoredAlert>> {
        let rows = sqlx::query(
            "SELECT rowid as row_id, alert_id, isobox_id, severity, title, detail,
                    timestamp, anomaly_score, action_taken, paladin_level, full_json
             FROM alerts
             WHERE isobox_id = ?1
             ORDER BY timestamp DESC
             LIMIT ?2"
        )
        .bind(isobox_id.as_str())
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| isolate_core::IsolateError::Store(e.to_string()))?;

        rows.into_iter().map(|r| {
            let ts_str: String = r.try_get("timestamp")
                .map_err(|e| isolate_core::IsolateError::Store(e.to_string()))?;
            let timestamp = ts_str.parse::<DateTime<Utc>>()
                .map_err(|e| isolate_core::IsolateError::Store(e.to_string()))?;
            Ok(StoredAlert {
                row_id: r.try_get("row_id").map_err(|e| isolate_core::IsolateError::Store(e.to_string()))?,
                alert_id: r.try_get("alert_id").map_err(|e| isolate_core::IsolateError::Store(e.to_string()))?,
                isobox_id: r.try_get("isobox_id").map_err(|e| isolate_core::IsolateError::Store(e.to_string()))?,
                severity: r.try_get("severity").map_err(|e| isolate_core::IsolateError::Store(e.to_string()))?,
                title: r.try_get("title").map_err(|e| isolate_core::IsolateError::Store(e.to_string()))?,
                detail: r.try_get("detail").map_err(|e| isolate_core::IsolateError::Store(e.to_string()))?,
                timestamp,
                anomaly_score: r.try_get("anomaly_score").map_err(|e| isolate_core::IsolateError::Store(e.to_string()))?,
                action_taken: r.try_get("action_taken").map_err(|e| isolate_core::IsolateError::Store(e.to_string()))?,
                paladin_level: r.try_get("paladin_level").map_err(|e| isolate_core::IsolateError::Store(e.to_string()))?,
                full_json: r.try_get("full_json").map_err(|e| isolate_core::IsolateError::Store(e.to_string()))?,
            })
        }).collect()
    }

    pub async fn critical_alert_count(&self, isobox_id: &IsoboxId) -> isolate_core::Result<i64> {
        let row = sqlx::query(
            "SELECT COUNT(*) as count FROM alerts
             WHERE isobox_id = ?1 AND severity IN ('critical', 'emergency')"
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
