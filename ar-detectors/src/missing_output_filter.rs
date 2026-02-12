//! Missing-output-filter sub-checks (plan §"Detector catalog" item 8).
//!
//! Output that reaches the user (or another tool) should be filtered for PII,
//! secrets, raw stack traces, policy violations, and jailbreak echoes. Because
//! the static graph can't see the response, these checks look for the *absence*
//! of any filtering signal on agents whose output is externally visible, and
//! for secret/PII patterns visibly present in prompts/descriptions.

use crate::detector::helpers::*;
use crate::define_detectors;
use ar_core::{
    AgentNode, DetectorCategory, EuAiActArticle, Finding, OwaspAgentic2026, OwaspLlm2025, Severity,
};

/// Whether the agent's prompt mentions any output-filtering control.
fn mentions_filter(a: &AgentNode, needles: &[&str]) -> bool {
    let p = lc(&a.system_prompt);
    contains_any(&p, needles)
}

/// Whether the agent produces user-facing output (heuristic: accepts user
/// input, or has no downstream agent consuming its handoff).
fn user_facing(g: &ar_core::AgentGraph, a: &AgentNode) -> bool {
    if a.accepts_user_input { return true; }
    // No outgoing handoff => terminal agent whose output reaches the user.
    !g.edges_from(&a.id).any(|e| e.kind == ar_core::EdgeKind::Handoff)
}

define_detectors! {
    /// No PII redaction on user-facing output.
    MofNoPiiRedaction {
        id: "mof-no-pii-redaction",
        category: DetectorCategory::MissingOutputFilter,
        severity: Severity::Medium,
        title: "No PII redaction on agent output",
        detect: |g| {
            let mut out = Vec::new();
            for a in &g.agents {
                if !user_facing(g, a) { continue; }
                if mentions_filter(a, &["redact", "pii", "presidio", "anonymize", "mask", "scrub", "sanitize output"]) { continue; }
                // Higher signal if the agent can read PII-bearing sources.
                let reads_data = !g.rag_of(&a.id).is_empty() || !g.memory_of(&a.id).is_empty()
                    || g.tools_of(&a.id).iter().any(|t| t.effects.reads_fs || t.effects.db_write);
                let f = Finding::new(
                    "mof-no-pii-redaction",
                    DetectorCategory::MissingOutputFilter,
                    Severity::Medium,
                    "No PII redaction on agent output",
                    format!(
                        "Agent `{}` returns output to users with no detectable PII redaction. If it \
                         can access personal data, that data may leak verbatim into responses.",
                        a.name
                    ),
                )
                .with_agent(a.id.clone())
                .with_evidence(prompt_evidence(a))
                .with_location(loc(&a.location))
                .with_fix(
                    "Add a PII redaction pass (e.g. Microsoft Presidio / regex filters for emails, \
                     SSNs, card numbers) before returning model output.",
                )
                .with_confidence(if reads_data { ar_core::Confidence::Medium } else { ar_core::Confidence::Low });
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::DataExfiltrationViaAgent)
                        .with_llm(OwaspLlm2025::SensitiveInformationDisclosure)
                        .with_eu(EuAiActArticle::Article10DataGovernance)
                }));
            }
            out
        }
    }

    /// No secret-pattern filter on output.
    MofNoSecretPatternFilter {
        id: "mof-no-secret-pattern-filter",
        category: DetectorCategory::MissingOutputFilter,
        severity: Severity::Medium,
        title: "No secret-pattern filter on agent output",
        detect: |g| {
            let mut out = Vec::new();
            for a in &g.agents {
                if !user_facing(g, a) { continue; }
                if mentions_filter(a, &["secret", "redact", "api key", "credential", "scrub", "filter secret"]) { continue; }
                // Only when the agent touches code/files/env (where secrets live).
                let touches_secretish = g.tools_of(&a.id).iter().any(|t| t.effects.reads_fs || t.effects.shell_exec || t.effects.net_egress);
                if !touches_secretish { continue; }
                let f = Finding::new(
                    "mof-no-secret-pattern-filter",
                    DetectorCategory::MissingOutputFilter,
                    Severity::Medium,
                    "No secret-pattern filter on agent output",
                    format!(
                        "Agent `{}` can read files/env/network and returns output with no \
                         secret-pattern filter, so API keys / tokens it encounters can leak to users.",
                        a.name
                    ),
                )
                .with_agent(a.id.clone())
                .with_evidence(prompt_evidence(a))
                .with_location(loc(&a.location))
                .with_fix(
                    "Run output through a secret-detection filter (AWS keys, `sk-…`, PEM blocks, \
                     bearer tokens) and block/redact matches before returning it.",
                );
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::DataExfiltrationViaAgent)
                        .with_llm(OwaspLlm2025::SensitiveInformationDisclosure)
                }));
            }
            out
        }
    }

    /// Raw stack traces / error detail may be returned to the user.
    MofRawStackTrace {
        id: "mof-raw-stack-trace",
        category: DetectorCategory::MissingOutputFilter,
        severity: Severity::Low,
        title: "Raw error/stack-trace may reach the user",
        detect: |g| {
            let mut out = Vec::new();
            for a in &g.agents {
                if !user_facing(g, a) { continue; }
                let p = lc(&a.system_prompt);
                // Prompt explicitly tells the model to include errors/traces, or
                // there is no instruction to hide internal errors.
                let exposes = contains_any(&p, &["traceback", "stack trace", "raw error", "include the error", "return the exception"]);
                let hides = contains_any(&p, &["do not reveal errors", "generic error", "hide stack", "no internal details"]);
                // Fire when explicitly exposing, OR when the agent runs code/shell
                // and gives no guidance about error handling.
                let runs_code = g.tools_of(&a.id).iter().any(|t| t.effects.shell_exec || t.effects.code_eval);
                if (exposes && !hides) || (runs_code && !hides && !p.is_empty()) {
                    let f = Finding::new(
                        "mof-raw-stack-trace",
                        DetectorCategory::MissingOutputFilter,
                        Severity::Low,
                        "Raw error/stack-trace may reach the user",
                        format!(
                            "Agent `{}` may surface raw errors / stack traces to users, leaking \
                             internal paths, dependency versions, and other recon detail.",
                            a.name
                        ),
                    )
                    .with_agent(a.id.clone())
                    .with_evidence(prompt_evidence(a))
                    .with_location(loc(&a.location))
                    .with_fix("Catch exceptions and return a generic user-safe message; log full detail server-side only.")
                    .with_confidence(ar_core::Confidence::Low);
                    out.push(tagged(f, |c| {
                        c.with_agentic(OwaspAgentic2026::DataExfiltrationViaAgent)
                            .with_llm(OwaspLlm2025::SensitiveInformationDisclosure)
                    }));
                }
            }
            out
        }
    }

    /// No content policy / moderation on output.
    MofNoContentPolicy {
        id: "mof-no-content-policy",
        category: DetectorCategory::MissingOutputFilter,
        severity: Severity::Low,
        title: "No output content policy / moderation",
        detect: |g| {
            let mut out = Vec::new();
            for a in &g.agents {
                if !user_facing(g, a) { continue; }
                if mentions_filter(a, &["moderation", "content policy", "safety", "refuse", "guardrail", "do not produce", "harmful"]) { continue; }
                let f = Finding::new(
                    "mof-no-content-policy",
                    DetectorCategory::MissingOutputFilter,
                    Severity::Low,
                    "No output content policy / moderation",
                    format!(
                        "Agent `{}` has no detectable content-policy / moderation guidance, so it may \
                         emit harmful or non-compliant content.",
                        a.name
                    ),
                )
                .with_agent(a.id.clone())
                .with_evidence(prompt_evidence(a))
                .with_location(loc(&a.location))
                .with_fix("Add a moderation pass / content-policy clause and route output through a safety filter.")
                .with_confidence(ar_core::Confidence::Low);
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::GoalHijacking)
                        .with_llm(OwaspLlm2025::Misinformation)
                        .with_eu(EuAiActArticle::Article15Robustness)
                }));
            }
            out
        }
    }

    /// No jailbreak-output detector (echoing a successful jailbreak).
    MofNoJailbreakOutputDetector {
        id: "mof-no-jailbreak-output-detector",
        category: DetectorCategory::MissingOutputFilter,
        severity: Severity::Low,
        title: "No jailbreak-output detector",
        detect: |g| {
            let mut out = Vec::new();
            for a in &g.agents {
                if !user_facing(g, a) { continue; }
                if mentions_filter(a, &["jailbreak", "dan ", "guardrail", "refuse", "policy violation", "do not roleplay"]) { continue; }
                // Only when the agent takes untrusted input (jailbreak entry point).
                if !a.accepts_user_input { continue; }
                let f = Finding::new(
                    "mof-no-jailbreak-output-detector",
                    DetectorCategory::MissingOutputFilter,
                    Severity::Low,
                    "No jailbreak-output detector",
                    format!(
                        "Agent `{}` accepts untrusted input but has no detectable jailbreak-output \
                         detector, so a successful jailbreak's output is returned unflagged.",
                        a.name
                    ),
                )
                .with_agent(a.id.clone())
                .with_evidence(prompt_evidence(a))
                .with_location(loc(&a.location))
                .with_fix("Add an output-side classifier that flags jailbreak/persona-override responses and blocks them.")
                .with_confidence(ar_core::Confidence::Low);
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::GoalHijacking)
                        .with_llm(OwaspLlm2025::PromptInjection)
                }));
            }
            out
        }
    }
}
