//! Missing-input-validation sub-checks (plan §"Detector catalog" item 7).
//!
//! Tools that accept arguments from the model (and thus, transitively, from
//! untrusted input) should validate them. These checks flag missing arg
//! schemas, missing length limits, missing URL allowlists, missing
//! path-traversal checks, and missing content-type checks.

use crate::detector::helpers::*;
use crate::define_detectors;
use ar_core::{DetectorCategory, EuAiActArticle, Finding, OwaspAgentic2026, OwaspLlm2025, Severity};

/// Combined haystack of a tool's textual surface.
fn surface(t: &ar_core::ToolNode) -> String {
    format!(
        "{} {} {}",
        t.name,
        t.signature.as_deref().unwrap_or(""),
        t.description.as_deref().unwrap_or("")
    )
    .to_ascii_lowercase()
}

define_detectors! {
    /// No declared schema on a tool that takes arguments.
    MivNoSchemaOnToolArgs {
        id: "miv-no-schema-on-tool-args",
        category: DetectorCategory::MissingInputValidation,
        severity: Severity::Medium,
        title: "Tool arguments have no validation schema",
        detect: |g| {
            let mut out = Vec::new();
            for t in &g.tools {
                if t.has_input_schema { continue; }
                // Only meaningful for tools that actually take args / do something.
                let takes_args = t.signature.as_deref().map(|s| s.contains('(') && !s.contains("()")).unwrap_or(true);
                if !takes_args && !t.effects.is_known() { continue; }
                let f = Finding::new(
                    "miv-no-schema-on-tool-args",
                    DetectorCategory::MissingInputValidation,
                    if t.effects.is_privileged() { Severity::High } else { Severity::Medium },
                    "Tool arguments have no validation schema",
                    format!(
                        "Tool `{}` declares no input schema, so the model can pass arbitrary, \
                         unvalidated arguments into it.",
                        t.name
                    ),
                )
                .with_tool(t.id.clone())
                .with_evidence(format!("signature={} effects=[{}]", t.signature.as_deref().unwrap_or("<none>"), t.effects.badges().join(",")))
                .with_location(loc(&t.location))
                .with_fix(
                    "Define a typed argument schema (Pydantic model / JSON Schema) with explicit \
                     types, ranges, enums and required fields.",
                );
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::ToolMisuse)
                        .with_llm(OwaspLlm2025::ExcessiveAgency)
                        .with_eu(EuAiActArticle::Article15Robustness)
                }));
            }
            out
        }
    }

    /// No length limit on string arguments.
    MivNoLengthLimit {
        id: "miv-no-length-limit",
        category: DetectorCategory::MissingInputValidation,
        severity: Severity::Low,
        title: "No length limit on tool arguments",
        detect: |g| {
            let mut out = Vec::new();
            for t in &g.tools {
                let s = surface(t);
                let has_str_arg = s.contains("str") || s.contains("string") || s.contains("text") || s.contains("query") || s.contains("input");
                if !has_str_arg { continue; }
                if contains_any(&s, &["max_length", "maxlength", "max_len", "constr(", "field(", "minlength", "truncate"]) { continue; }
                let f = Finding::new(
                    "miv-no-length-limit",
                    DetectorCategory::MissingInputValidation,
                    Severity::Low,
                    "No length limit on tool arguments",
                    format!(
                        "Tool `{}` accepts string arguments with no length bound, allowing oversized \
                         inputs that can exhaust resources or smuggle hidden payloads.",
                        t.name
                    ),
                )
                .with_tool(t.id.clone())
                .with_evidence(tool_evidence(t))
                .with_location(loc(&t.location))
                .with_fix("Bound string argument lengths in the schema (e.g. max_length).")
                .with_confidence(ar_core::Confidence::Low);
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::ToolMisuse)
                        .with_llm(OwaspLlm2025::UnboundedConsumption)
                }));
            }
            out
        }
    }

    /// No allowlist on a URL argument (SSRF surface).
    MivNoAllowlistOnUrl {
        id: "miv-no-allowlist-on-url",
        category: DetectorCategory::MissingInputValidation,
        severity: Severity::Medium,
        title: "URL argument has no allowlist",
        detect: |g| {
            let mut out = Vec::new();
            for t in &g.tools {
                let s = surface(t);
                let takes_url = t.effects.net_egress || contains_any(&s, &["url", "uri", "endpoint", "fetch", "http"]);
                if !takes_url { continue; }
                if contains_any(&s, &["allowlist", "allowed_hosts", "allowed_domains", "block_private", "validate_url", "ssrf"]) { continue; }
                let f = Finding::new(
                    "miv-no-allowlist-on-url",
                    DetectorCategory::MissingInputValidation,
                    Severity::Medium,
                    "URL argument has no allowlist",
                    format!(
                        "Tool `{}` accepts a URL/endpoint argument with no host allowlist or SSRF \
                         protection. The model can be steered to fetch internal/metadata endpoints.",
                        t.name
                    ),
                )
                .with_tool(t.id.clone())
                .with_evidence(tool_evidence(t))
                .with_location(loc(&t.location))
                .with_fix(
                    "Validate URLs against a host allowlist and block private/link-local ranges \
                     (169.254.0.0/16, 127.0.0.0/8, RFC1918).",
                );
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::ToolMisuse)
                        .with_agentic(OwaspAgentic2026::DataExfiltrationViaAgent)
                        .with_llm(OwaspLlm2025::ExcessiveAgency)
                }));
            }
            out
        }
    }

    /// No path-traversal check on a path argument.
    MivNoPathTraversalCheck {
        id: "miv-no-path-traversal-check",
        category: DetectorCategory::MissingInputValidation,
        severity: Severity::Medium,
        title: "Path argument has no traversal check",
        detect: |g| {
            let mut out = Vec::new();
            for t in &g.tools {
                let s = surface(t);
                let takes_path = t.effects.reads_fs || t.effects.writes_fs || contains_any(&s, &["path", "file", "filename", "dir", "directory"]);
                if !takes_path { continue; }
                if contains_any(&s, &["resolve", "realpath", "canonical", "safe_join", "is_relative_to", "within", "base_dir", "sandbox", "traversal"]) { continue; }
                let f = Finding::new(
                    "miv-no-path-traversal-check",
                    DetectorCategory::MissingInputValidation,
                    Severity::Medium,
                    "Path argument has no traversal check",
                    format!(
                        "Tool `{}` accepts a filesystem path with no traversal protection, so `..` \
                         sequences or absolute paths can escape the intended directory.",
                        t.name
                    ),
                )
                .with_tool(t.id.clone())
                .with_evidence(tool_evidence(t))
                .with_location(loc(&t.location))
                .with_fix(
                    "Canonicalize the path and assert it stays within an allowlisted base directory; \
                     reject `..`, absolute paths and symlinks.",
                );
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::ToolMisuse)
                        .with_llm(OwaspLlm2025::ExcessiveAgency)
                }));
            }
            out
        }
    }

    /// No content-type check on fetched / uploaded content.
    MivNoContentTypeCheck {
        id: "miv-no-content-type-check",
        category: DetectorCategory::MissingInputValidation,
        severity: Severity::Low,
        title: "No content-type validation on fetched content",
        detect: |g| {
            let mut out = Vec::new();
            for t in &g.tools {
                if !t.effects.net_egress { continue; }
                let s = surface(t);
                if contains_any(&s, &["content-type", "content_type", "mimetype", "mime", "accept:", "validate_type"]) { continue; }
                let f = Finding::new(
                    "miv-no-content-type-check",
                    DetectorCategory::MissingInputValidation,
                    Severity::Low,
                    "No content-type validation on fetched content",
                    format!(
                        "Tool `{}` fetches remote content with no content-type validation, so an \
                         attacker-controlled server can return an unexpected payload type the agent \
                         then mishandles.",
                        t.name
                    ),
                )
                .with_tool(t.id.clone())
                .with_evidence(tool_evidence(t))
                .with_location(loc(&t.location))
                .with_fix("Validate the response content-type/charset and size before processing it.")
                .with_confidence(ar_core::Confidence::Low);
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::ToolMisuse)
                        .with_llm(OwaspLlm2025::ImproperOutputHandling)
                }));
            }
            out
        }
    }
}
