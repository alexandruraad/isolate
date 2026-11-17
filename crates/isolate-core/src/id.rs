use serde::{Deserialize, Serialize};
use std::fmt;
use ulid::Ulid;

/// Unique identifier for an isobox instance.
/// Uses ULID for lexicographic sortability by creation time.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IsoboxId(String);

impl IsoboxId {
    /// Generate a new unique isobox ID.
    pub fn new() -> Self {
        Self(Ulid::new().to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for IsoboxId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for IsoboxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for IsoboxId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for IsoboxId {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

/// Per-request trace ID for correlation across components.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TraceId(String);

impl TraceId {
    pub fn new() -> Self {
        Self(Ulid::new().to_string())
    }
}

impl Default for TraceId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for TraceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
