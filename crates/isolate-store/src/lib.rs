//! isolate-store — SQLite-backed persistent event and alert store
//!
//! Uses sqlx with SQLite. The schema is managed via embedded migrations.
//! Supports time-range queries, isobox-scoped queries, and alert retrieval.

pub mod alerts;
pub mod baseline;
pub mod events;
pub mod migrations;

use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};
use std::path::Path;

pub use events::{EventQuery, StoredEvent};
pub use alerts::StoredAlert;

/// The central store handle. Clone to share across tasks.
#[derive(Clone)]
pub struct Store {
    pub pool: SqlitePool,
}

impl Store {
    /// Open (or create) the SQLite database at `path` and run migrations.
    pub async fn open(path: &Path) -> isolate_core::Result<Self> {
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .map_err(|e| isolate_core::IsolateError::Store(e.to_string()))?;

        // Apply PRAGMAs outside of any transaction (WAL mode cannot be set inside one)
        sqlx::query("PRAGMA journal_mode = WAL;").execute(&pool).await
            .map_err(|e| isolate_core::IsolateError::Store(e.to_string()))?;
        sqlx::query("PRAGMA synchronous = NORMAL;").execute(&pool).await
            .map_err(|e| isolate_core::IsolateError::Store(e.to_string()))?;

        // Run embedded migrations
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(|e| isolate_core::IsolateError::Store(e.to_string()))?;

        Ok(Self { pool })
    }

    /// Open an in-memory store (for testing).
    pub async fn in_memory() -> isolate_core::Result<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .map_err(|e| isolate_core::IsolateError::Store(e.to_string()))?;

        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(|e| isolate_core::IsolateError::Store(e.to_string()))?;

        Ok(Self { pool })
    }
}
