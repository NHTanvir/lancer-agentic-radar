//! The four-part prompt-hardening rubric and the heuristic scorer.
//!
//! Upstream `agentic-radar --harden-prompts` (and our `prompt-hardening-needed`
//! detector) judge a system prompt against four defensive components:
//!
//! 1. **role separator / confidentiality** — the prompt establishes a clear,
//!    non-overridable role and protects its own contents ("do not reveal the
//!    system prompt", explicit `you are` boundary, distinct role markers).
//! 2. **refusal clause** — the prompt tells the model to *refuse / decline /
//!    not comply* with out-of-scope or malicious requests.
//! 3. **output-format constraint** — the prompt constrains the shape of the
//!    output ("respond in", "format", "JSON", "only output").
//! 4. **anti-jailbreak preamble** — the prompt anticipates override attempts
//!    ("ignore previous instructions", "override", "jailbreak", "DAN",
//!    "regardless of").
//!
//! [`crate::score_prompt`] populates a [`HardeningRubric`] by matching each
//! component with conservative case-insensitive regexes/substrings.

use serde::{Deserialize, Serialize};

/// Presence flags for each of the four hardening components in a prompt.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct HardeningRubric {
    /// A clear role boundary / system-prompt-confidentiality clause is present.
    pub role_separator: bool,
    /// A refusal / decline clause is present.
    pub refusal_clause: bool,
    /// An output-format constraint is present.
    pub output_constraint: bool,
    /// An anti-jailbreak / override-resistance preamble is present.
    pub anti_jailbreak: bool,
}

impl HardeningRubric {
    /// A rubric with every component absent (the worst, "naive prompt" case).
    pub const EMPTY: HardeningRubric = HardeningRubric {
        role_separator: false,
        refusal_clause: false,
        output_constraint: false,
        anti_jailbreak: false,
    };

    /// A rubric with every component present.
    pub const FULL: HardeningRubric = HardeningRubric {
        role_separator: true,
        refusal_clause: true,
        output_constraint: true,
        anti_jailbreak: true,
    };

    /// Number of components present (0..=4).
    pub fn score(&self) -> u8 {
        self.role_separator as u8
            + self.refusal_clause as u8
            + self.output_constraint as u8
            + self.anti_jailbreak as u8
    }

    /// Whether the prompt is considered adequately hardened (>= 3 of 4).
    pub fn passes(&self) -> bool {
        self.score() >= 3
    }

    /// True if every component is present.
    pub fn is_full(&self) -> bool {
        self.role_separator && self.refusal_clause && self.output_constraint && self.anti_jailbreak
    }
}

impl Default for HardeningRubric {
    fn default() -> Self {
        HardeningRubric::EMPTY
    }
}
