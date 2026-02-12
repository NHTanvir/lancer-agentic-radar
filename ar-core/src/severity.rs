//! Finding severity.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Severity of a [`crate::Finding`]. Ordered ascending in declaration so that
/// `Severity::Critical > Severity::Info` under the derived `Ord`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// All severities, ascending.
    pub const ALL: [Severity; 5] = [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];

    /// Lowercase canonical name (matches serde + CLI parsing).
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }

    /// SARIF `level` mapping (`error` / `warning` / `note`).
    pub fn sarif_level(self) -> &'static str {
        match self {
            Severity::Critical | Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low | Severity::Info => "note",
        }
    }

    /// A coarse 0.0–10.0 base CVSS-ish score for reports that want a number.
    pub fn numeric(self) -> f32 {
        match self {
            Severity::Critical => 9.5,
            Severity::High => 7.5,
            Severity::Medium => 5.0,
            Severity::Low => 2.5,
            Severity::Info => 0.0,
        }
    }

    /// Hex color used by the HTML/Mermaid reporters.
    pub fn color(self) -> &'static str {
        match self {
            Severity::Critical => "#b91c1c",
            Severity::High => "#ea580c",
            Severity::Medium => "#ca8a04",
            Severity::Low => "#2563eb",
            Severity::Info => "#6b7280",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "critical" | "crit" => Ok(Severity::Critical),
            "high" => Ok(Severity::High),
            "medium" | "med" => Ok(Severity::Medium),
            "low" => Ok(Severity::Low),
            "info" | "informational" | "note" => Ok(Severity::Info),
            other => Err(format!("unknown severity: {other}")),
        }
    }
}
