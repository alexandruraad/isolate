use crate::schema::IsoboxToml;
use isolate_core::{IsolateError, Result};

/// Return a built-in policy preset by name.
pub fn preset(name: &str) -> Result<IsoboxToml> {
    let raw = match name {
        "malware-analysis"        => include_str!("../../../policy/malware-analysis.toml"),
        "dev-environment"         => include_str!("../../../policy/dev-environment.toml"),
        "zero-trust-service"      => include_str!("../../../policy/zero-trust-service.toml"),
        "compromised-containment" => include_str!("../../../policy/compromised-containment.toml"),
        other => {
            return Err(IsolateError::config(format!(
                "unknown policy preset '{other}'. Known presets: \
                 malware-analysis, dev-environment, zero-trust-service, compromised-containment"
            )))
        }
    };

    toml::from_str(raw).map_err(|e| IsolateError::config(e.to_string()))
}
