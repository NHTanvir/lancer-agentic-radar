//! Trust labels propagated across the agent graph.
//!
//! User input is `Untrusted`; vetted internal RAG is `Trusted`; an LLM call's
//! output is `Mixed` (tending untrusted); a tool result's label depends on the
//! tool. Detectors flag privileged sinks reachable from `Untrusted` sources.

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TrustLabel {
    /// Vetted, controlled by the operator (internal docs, constant prompts).
    Trusted,
    /// Could be attacker-controlled (user input, public web, user uploads).
    Untrusted,
    /// Partially controlled — notably raw LLM output, which is conservatively
    /// treated as tending-untrusted during propagation.
    Mixed,
    /// Not yet labelled.
    #[default]
    Unknown,
}

impl TrustLabel {
    /// Conservative join used during propagation: any untrusted contribution
    /// taints the result; mixed downgrades trusted to mixed.
    pub fn join(self, other: TrustLabel) -> TrustLabel {
        use TrustLabel::*;
        match (self, other) {
            (Untrusted, _) | (_, Untrusted) => Untrusted,
            (Mixed, _) | (_, Mixed) => Mixed,
            (Unknown, x) | (x, Unknown) => x,
            (Trusted, Trusted) => Trusted,
        }
    }

    /// True when data carrying this label must be treated as attacker-influenced.
    pub fn is_tainted(self) -> bool {
        matches!(self, TrustLabel::Untrusted | TrustLabel::Mixed)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            TrustLabel::Trusted => "trusted",
            TrustLabel::Untrusted => "untrusted",
            TrustLabel::Mixed => "mixed",
            TrustLabel::Unknown => "unknown",
        }
    }

    /// Edge color used by the Mermaid/DOT reporters.
    pub fn edge_color(self) -> &'static str {
        match self {
            TrustLabel::Trusted => "#16a34a",   // green
            TrustLabel::Mixed => "#d97706",     // orange
            TrustLabel::Untrusted => "#dc2626", // red
            TrustLabel::Unknown => "#9ca3af",   // gray
        }
    }
}

impl fmt::Display for TrustLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
