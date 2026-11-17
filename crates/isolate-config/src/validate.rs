use crate::schema::IsoboxToml;
use isolate_core::{IsolateError, Result};

/// Validate a parsed `IsoboxToml` for consistency and safety.
pub fn validate_isobox_toml(toml: &IsoboxToml) -> Result<()> {
    // Name must be non-empty and safe
    if toml.isobox.name.is_empty() {
        return Err(IsolateError::PolicyValidation("isobox name cannot be empty".into()));
    }
    if toml.isobox.name.contains('/') || toml.isobox.name.contains('\0') {
        return Err(IsolateError::PolicyValidation(
            "isobox name contains invalid characters".into(),
        ));
    }

    // Target validation
    if let Some(ref target) = toml.target {
        match target {
            crate::schema::TargetToml::Process { command, .. } => {
                if command.is_empty() {
                    return Err(IsolateError::PolicyValidation(
                        "process target requires a non-empty command".into(),
                    ));
                }
            }
            crate::schema::TargetToml::Container { image, .. } => {
                if image.is_empty() {
                    return Err(IsolateError::PolicyValidation(
                        "container target requires an image".into(),
                    ));
                }
            }
            crate::schema::TargetToml::Vm { image, .. } => {
                if !image.exists() {
                    tracing::warn!(path = %image.display(), "VM image does not exist at validation time");
                }
            }
            crate::schema::TargetToml::WasmModule { module, .. } => {
                if !module.exists() {
                    tracing::warn!(path = %module.display(), "WASM module does not exist at validation time");
                }
            }
        }
    }

    // Policy validation
    if let Some(ref policy) = toml.policy {
        // Validate anomaly threshold if intel is configured
        if let Some(ref intel) = toml.intelligence {
            if let Some(threshold) = intel.anomaly_threshold {
                if !(0.0..=1.0).contains(&threshold) {
                    return Err(IsolateError::PolicyValidation(
                        "anomaly_threshold must be between 0.0 and 1.0".into(),
                    ));
                }
            }
        }

        // Validate CEL rule conditions are non-empty
        for rule in &policy.rules {
            if rule.name.is_empty() {
                return Err(IsolateError::PolicyValidation("policy rule has empty name".into()));
            }
            if rule.condition.is_empty() {
                return Err(IsolateError::PolicyValidation(
                    format!("policy rule '{}' has empty condition", rule.name),
                ));
            }
        }
    }

    // Paladin validation
    if let Some(ref paladin) = toml.paladin {
        if let Some(level) = paladin.max_auto_level {
            if level > 7 {
                return Err(IsolateError::PolicyValidation(
                    "paladin max_auto_level cannot exceed 7 (ABSOLUTION)".into(),
                ));
            }
        }
        if let Some(threshold) = paladin.escalation_threshold {
            if !(0.0..=1.0).contains(&threshold) {
                return Err(IsolateError::PolicyValidation(
                    "paladin escalation_threshold must be between 0.0 and 1.0".into(),
                ));
            }
        }
    }

    Ok(())
}
