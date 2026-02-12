//! The [`Detector`] trait, its [`DetectorMeta`] descriptor, the
//! [`define_detectors!`] convenience macro, and a small bag of shared helpers
//! (regex libraries, location copying, compliance-tag builders) every category
//! module reuses.
//!
//! Detectors are intentionally *pure*: each takes an immutable [`AgentGraph`]
//! reference and returns a `Vec<Finding>`. They never mutate the graph and have
//! no side effects, so the registry can run them in any order (and, later, in
//! parallel) and the result is deterministic.

use ar_core::{AgentGraph, DetectorCategory, Finding, Severity};

/// A single security sub-check.
///
/// Every concrete detector is a zero-sized unit struct implementing this trait;
/// the [`define_detectors!`] macro generates them from a compact table.
pub trait Detector {
    /// Stable sub-check id, e.g. `tb-tool-output-to-next-tool-input`.
    fn id(&self) -> &'static str;
    /// The detector category this sub-check rolls up into.
    fn category(&self) -> DetectorCategory;
    /// The severity findings default to (individual findings may downgrade).
    fn default_severity(&self) -> Severity;
    /// Human-readable title for the sub-check (used in reports + `--self-test`).
    fn title(&self) -> &'static str;
    /// Run the check over `g`, returning zero or more findings.
    fn detect(&self, g: &AgentGraph) -> Vec<Finding>;
}

/// Static description of a registered detector sub-check.
///
/// Surfaced by [`crate::registry`] to drive `--self-test` output and the GUI's
/// detector catalog without having to instantiate every detector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectorMeta {
    pub id: &'static str,
    pub category: DetectorCategory,
    pub default_severity: Severity,
    pub title: &'static str,
}

impl DetectorMeta {
    /// Build a [`DetectorMeta`] from any [`Detector`].
    pub fn of(d: &dyn Detector) -> Self {
        DetectorMeta {
            id: d.id(),
            category: d.category(),
            default_severity: d.default_severity(),
            title: d.title(),
        }
    }
}

/// Declare one or more unit-struct detectors from a compact table.
///
/// Each entry names the struct, its id / category / default severity / title,
/// and a `detect` body. The body is a closure-style expression: it receives the
/// graph as `$g` and must evaluate to a `Vec<Finding>`.
///
/// ```ignore
/// define_detectors! {
///     /// Doc comment forwarded onto the generated struct.
///     PromptLeak {
///         id: "pi-system-prompt-leak-via-echo",
///         category: DetectorCategory::PromptInjection,
///         severity: Severity::Medium,
///         title: "System prompt may be echoed back to the user",
///         detect: |g| { Vec::new() }
///     }
/// }
/// ```
#[macro_export]
macro_rules! define_detectors {
    (
        $(
            $(#[$meta:meta])*
            $name:ident {
                id: $id:expr,
                category: $cat:expr,
                severity: $sev:expr,
                title: $title:expr,
                detect: |$g:ident| $body:block
            }
        )+
    ) => {
        $(
            $(#[$meta])*
            #[derive(Debug, Default, Clone, Copy)]
            pub struct $name;

            impl $crate::detector::Detector for $name {
                fn id(&self) -> &'static str { $id }
                fn category(&self) -> ::ar_core::DetectorCategory { $cat }
                fn default_severity(&self) -> ::ar_core::Severity { $sev }
                fn title(&self) -> &'static str { $title }
                fn detect(&self, $g: &::ar_core::AgentGraph) -> ::std::vec::Vec<::ar_core::Finding> {
                    $body
                }
            }
        )+
    };
}

// ---------------------------------------------------------------------------
// Shared helpers used across every category module.
// ---------------------------------------------------------------------------

/// Regex / string-pattern helpers and the secret / PII pattern library.
pub mod helpers {
    use ar_core::{
        AgentNode, ComplianceTags, Finding, MemoryStore, RAGSource, SourceLocation, ToolNode,
    };
    use regex::Regex;

    /// Copy a node's [`SourceLocation`] onto a finding (clones the file/line and
    /// any source snippet, so inline `# ar-ignore:` hints carried in the snippet
    /// survive into the finding for the suppression pass).
    pub fn loc(base: &SourceLocation) -> SourceLocation {
        base.clone()
    }

    /// Lowercased view of an optional string (system prompt / description).
    pub fn lc(s: &Option<String>) -> String {
        s.as_deref().unwrap_or("").to_ascii_lowercase()
    }

    /// True if any `needle` appears (case-insensitively) in `hay`.
    pub fn contains_any(hay: &str, needles: &[&str]) -> bool {
        let h = hay.to_ascii_lowercase();
        needles.iter().any(|n| h.contains(&n.to_ascii_lowercase()))
    }

    /// True if `hay` matches the given regex pattern (pattern is a constant, so
    /// compilation cannot fail in practice; on the off chance it does we return
    /// `false` rather than panicking).
    pub fn rx_match(hay: &str, pattern: &str) -> bool {
        match Regex::new(pattern) {
            Ok(re) => re.is_match(hay),
            Err(_) => false,
        }
    }

    /// Return the first regex capture of `pattern` in `hay`, if any (the full
    /// match, group 0).
    pub fn rx_first<'a>(hay: &'a str, pattern: &str) -> Option<String> {
        let re = Regex::new(pattern).ok()?;
        re.find(hay).map(|m| m.as_str().to_string())
    }

    // -- secret / PII pattern library (plan §secret-leakage / §missing-output-filter)

    /// AWS access-key id (`AKIA...` / `ASIA...`, 16 trailing base32 chars).
    pub const RE_AWS_KEY: &str = r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b";
    /// AWS secret access key (40-char base64-ish blob assigned to an obvious var).
    pub const RE_AWS_SECRET: &str =
        r#"(?i)aws.{0,20}(?:secret|sk).{0,20}['"][0-9a-zA-Z/+]{40}['"]"#;
    /// Generic provider key prefixes (OpenAI `sk-`, Anthropic `sk-ant-`, etc.).
    pub const RE_GENERIC_KEY: &str =
        r"\b(?:sk-ant-[0-9A-Za-z_\-]{20,}|sk-[0-9A-Za-z]{20,}|xox[baprs]-[0-9A-Za-z\-]{10,}|ghp_[0-9A-Za-z]{36}|gho_[0-9A-Za-z]{36}|AIza[0-9A-Za-z_\-]{35})\b";
    /// `api_key = "..."` / `apikey: '...'` / `token="..."` assignment patterns.
    pub const RE_ASSIGNED_SECRET: &str =
        r#"(?i)\b(?:api[_-]?key|apikey|secret|password|passwd|token|bearer|access[_-]?token|client[_-]?secret)\b\s*[:=]\s*['"][^'"\s]{8,}['"]"#;
    /// Private-key PEM header.
    pub const RE_PRIVATE_KEY: &str = r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----";
    /// Email address.
    pub const RE_EMAIL: &str = r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b";
    /// US Social-Security-Number.
    pub const RE_SSN: &str = r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b";
    /// Credit-card-ish 13-16 digit run (loose; for PII output filtering).
    pub const RE_CC: &str = r"\b(?:[0-9]{4}[ \-]?){3}[0-9]{1,4}\b";

    /// True if `text` contains anything that looks like a hard-coded secret.
    pub fn has_secret(text: &str) -> bool {
        rx_match(text, RE_AWS_KEY)
            || rx_match(text, RE_AWS_SECRET)
            || rx_match(text, RE_GENERIC_KEY)
            || rx_match(text, RE_PRIVATE_KEY)
            || rx_match(text, RE_ASSIGNED_SECRET)
    }

    /// The first secret-looking substring in `text`, redacted for evidence.
    pub fn first_secret(text: &str) -> Option<String> {
        for p in [
            RE_AWS_KEY,
            RE_GENERIC_KEY,
            RE_PRIVATE_KEY,
            RE_AWS_SECRET,
            RE_ASSIGNED_SECRET,
        ] {
            if let Some(m) = rx_first(text, p) {
                return Some(redact(&m));
            }
        }
        None
    }

    /// Redact the middle of a secret-looking token for safe evidence display.
    pub fn redact(s: &str) -> String {
        let chars: Vec<char> = s.chars().collect();
        if chars.len() <= 8 {
            return "*".repeat(chars.len());
        }
        let head: String = chars[..4].iter().collect();
        let tail: String = chars[chars.len() - 4..].iter().collect();
        format!("{head}…{tail}")
    }

    /// Truncate a snippet for evidence so reports stay readable.
    pub fn truncate(s: &str, max: usize) -> String {
        let t = s.trim();
        if t.chars().count() <= max {
            t.to_string()
        } else {
            let cut: String = t.chars().take(max).collect();
            format!("{cut}…")
        }
    }

    /// Best-effort evidence snippet for an agent's system prompt.
    pub fn prompt_evidence(a: &AgentNode) -> String {
        match &a.system_prompt {
            Some(p) => truncate(p, 160),
            None => format!("agent `{}` has no extracted system prompt", a.name),
        }
    }

    /// Best-effort evidence snippet for a tool description.
    pub fn tool_evidence(t: &ToolNode) -> String {
        match &t.description {
            Some(d) => truncate(d, 160),
            None => format!("tool `{}` declares no description", t.name),
        }
    }

    /// Best-effort evidence for a RAG source.
    pub fn rag_evidence(r: &RAGSource) -> String {
        format!(
            "rag `{}` ({}) source={} trust={}",
            r.name,
            r.kind,
            r.document_source.as_deref().unwrap_or("?"),
            r.trust
        )
    }

    /// Best-effort evidence for a memory store.
    pub fn memory_evidence(m: &MemoryStore) -> String {
        format!(
            "memory `{}` ({}) cross_session={} tenant_isolated={} eviction={}",
            m.name, m.kind, m.cross_session, m.tenant_isolated, m.has_eviction_policy
        )
    }

    /// Re-export so category modules can stamp [`ComplianceTags`] tersely.
    pub fn tags() -> ComplianceTags {
        ComplianceTags::new()
    }

    /// Stamp a finding's compliance from a builder closure (ergonomic chaining).
    pub fn tagged(f: Finding, build: impl FnOnce(ComplianceTags) -> ComplianceTags) -> Finding {
        let c = build(ComplianceTags::new());
        f.with_compliance(c)
    }
}

// Re-export commonly used ar-core symbols so downstream code can `use
// ar_detectors::detector::prelude::*;` and stay terse. (The `define_detectors!`
// macro is exported at the crate root via `#[macro_export]`.)
pub mod prelude {
    pub use super::helpers;
    pub use super::{Detector, DetectorMeta};
    pub use ar_core::{
        AivssVector, ComplianceTags, Confidence, DetectorCategory, EuAiActArticle, Finding,
        OwaspAgentic2026, OwaspLlm2025, Severity, SourceLocation, ToolEffects,
    };
}

