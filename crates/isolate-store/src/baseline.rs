use crate::Store;
use chrono::Utc;
use isolate_core::types::WorkloadClass;
use sqlx::Row;

/// A serializable baseline snapshot for a workload class + time window.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BaselineSnapshot {
    pub workload_class: String,
    pub window_minutes: u32,
    pub sample_count: u64,
    /// Syscall number → count per window
    pub syscall_counts: std::collections::HashMap<u32, u64>,
    /// Estimated unique file paths (bloom filter state serialized as bytes)
    pub file_bloom_bytes: Vec<u8>,
    /// Network destination entropy (bytes)
    pub net_entropy: f64,
    /// Child process spawn rate per minute
    pub spawn_rate: f64,
    /// Memory growth rate (bytes/sec)
    pub mem_growth_rate: f64,
}

impl Store {
    pub async fn load_baseline(
        &self,
        class: &WorkloadClass,
        window_minutes: u32,
    ) -> isolate_core::Result<Option<BaselineSnapshot>> {
        let row = sqlx::query(
            "SELECT data_msgpack FROM baselines
             WHERE workload_class = ?1 AND window_minutes = ?2"
        )
        .bind(&class.0)
        .bind(window_minutes as i64)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| isolate_core::IsolateError::Store(e.to_string()))?;

        if let Some(r) = row {
            let bytes: Vec<u8> = r.try_get("data_msgpack")
                .map_err(|e| isolate_core::IsolateError::Store(e.to_string()))?;
            let snap: BaselineSnapshot = rmp_serde::from_slice(&bytes)
                .map_err(|e| isolate_core::IsolateError::Serialization(e.to_string()))?;
            Ok(Some(snap))
        } else {
            Ok(None)
        }
    }

    pub async fn save_baseline(&self, snap: &BaselineSnapshot) -> isolate_core::Result<()> {
        let data = rmp_serde::to_vec(snap)
            .map_err(|e| isolate_core::IsolateError::Serialization(e.to_string()))?;
        let now = Utc::now().to_rfc3339();

        sqlx::query(
            "INSERT INTO baselines (workload_class, window_minutes, updated_at, sample_count, data_msgpack)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(workload_class, window_minutes) DO UPDATE SET
                 updated_at   = excluded.updated_at,
                 sample_count = excluded.sample_count,
                 data_msgpack = excluded.data_msgpack"
        )
        .bind(&snap.workload_class)
        .bind(snap.window_minutes as i64)
        .bind(now)
        .bind(snap.sample_count as i64)
        .bind(data)
        .execute(&self.pool)
        .await
        .map_err(|e| isolate_core::IsolateError::Store(e.to_string()))?;

        Ok(())
    }
}
