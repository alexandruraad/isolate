// isolate-store migrations module.
//
// The actual migrations are SQL files in the `migrations/` directory.
// They are embedded and run by `sqlx::migrate!("./migrations")` in lib.rs.
//
// This module exists to satisfy the `pub mod migrations;` declaration
// and can be used to expose migration utilities or metadata.

/// The path (relative to this crate) where SQL migration files live.
pub const MIGRATIONS_PATH: &str = "./migrations";

/// Returns the number of migration files embedded at compile time.
/// Useful for health checks and version reporting.
pub fn migration_count() -> usize {
    // sqlx embeds the files at compile time via the migrate! macro in lib.rs.
    // This count is manually maintained to match the migrations/ directory.
    1 // 001_initial.sql
}
