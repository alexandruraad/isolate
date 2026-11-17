//! isolate-config — isobox.toml schema parsing, validation, and layered config
//!
//! Configuration is loaded in order (later entries win):
//!   1. Built-in defaults
//!   2. /etc/isolate/daemon.toml (global)
//!   3. ./isobox.toml (per-workload)
//!   4. Environment variables (ISOLATE_*)
//!   5. CLI flags

pub mod defaults;
pub mod schema;
pub mod validate;

pub use schema::{DaemonConfig, IsoboxToml};
pub use validate::validate_isobox_toml;

use isolate_core::{IsoboxConfig, IsoboxId, Result, WorkloadClass};

/// Load an `IsoboxConfig` from a TOML file path (or built-in preset name).
pub fn load_config(
    source: &ConfigSource,
    id: Option<IsoboxId>,
) -> Result<IsoboxConfig> {
    let toml = match source {
        ConfigSource::File(path) => {
            let raw = std::fs::read_to_string(path)
                .map_err(|e| isolate_core::IsolateError::config(e.to_string()))?;
            toml::from_str::<IsoboxToml>(&raw)
                .map_err(|e| isolate_core::IsolateError::config(e.to_string()))?
        }
        ConfigSource::Preset(name) => defaults::preset(name)?,
    };

    validate_isobox_toml(&toml)?;

    let id = id.unwrap_or_else(IsoboxId::new);
    Ok(toml.into_config(id))
}

/// Where to load the isobox configuration from.
pub enum ConfigSource {
    File(std::path::PathBuf),
    Preset(String),
}
