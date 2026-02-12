//! Indirect-injection sub-checks (plan §"Detector catalog" item 11).
//!
//! Indirect injection is where attacker-controlled content arrives through a
//! data channel (RAG documents, email/web tool output, MCP server results) and
//! is fed into the LLM context without sanitization or a trust label.

use crate::detector::helpers::*;
use crate::define_detectors;
use ar_core::{DetectorCategory, Finding, OwaspAgentic2026, OwaspLlm2025, Severity, ToolSource};

/// Names/descriptions that mark a tool as an external-content fetcher.
const FETCHER_MARKERS: &[&str] = &[
    "email", "imap", "smtp", "webpage", "web_page", "browse", "fetch", "scrape", "url", "http",
    "rss", "feed", "read_email", "get_page", "crawl",
];

define_detectors! {
    /// RAG output reaches context with no sanitization markers.
    IiRagOutputUnsanitized {
        id: "ii-rag-output-unsanitized",
        category: DetectorCategory::IndirectInjection,
        severity: Severity::High,
        title: "RAG output reaches context unsanitized",
        detect: |g| {
            let mut out = Vec::new();
            for a in &g.agents {
                let rags = g.rag_of(&a.id);
                if rags.is_empty() { continue; }
                let prompt = lc(&a.system_prompt);
                let sanitizes = contains_any(&prompt, &[
                    "<document>", "treat as data", "do not follow instructions", "untrusted",
                    "ignore any instructions in the documents", "sanitize",
                ]);
                if sanitizes { continue; }
                // Prioritize tainted/no-attribution sources.
                let risky = rags.iter().find(|r| r.trust.is_tainted() || !r.has_source_attribution);
                let r = match risky { Some(r) => r, None => continue };
                let f = Finding::new(
                    "ii-rag-output-unsanitized",
                    DetectorCategory::IndirectInjection,
                    if r.trust.is_tainted() { Severity::High } else { Severity::Medium },
                    "RAG output reaches context unsanitized",
                    format!(
                        "Agent `{}` feeds retrieved content from `{}` into the model context with no \
                         sanitization markers or data/instruction separation — a classic indirect \
                         prompt-injection channel.",
                        a.name, r.name
                    ),
                )
                .with_agent(a.id.clone())
                .with_evidence(rag_evidence(r))
                .with_location(loc(&a.location))
                .with_fix(
                    "Fence retrieved text in delimited <document> tags, instruct the model to treat \
                     it as data only, and never execute instructions found within.",
                );
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::GoalHijacking)
                        .with_llm(OwaspLlm2025::PromptInjection)
                        .with_atlas("AML.T0051.001")
                }));
            }
            out
        }
    }

    /// MCP server output enters context without a trust label.
    IiMcpOutputNoTrustLabel {
        id: "ii-mcp-output-no-trust-label",
        category: DetectorCategory::IndirectInjection,
        severity: Severity::Medium,
        title: "MCP output enters context without trust label",
        detect: |g| {
            let mut out = Vec::new();
            for a in &g.agents {
                let tools = g.tools_of(&a.id);
                let mcp: Vec<_> = tools.iter().filter(|t| matches!(t.source, ToolSource::Mcp(_))).collect();
                if mcp.is_empty() { continue; }
                let prompt = lc(&a.system_prompt);
                if contains_any(&prompt, &["untrusted", "treat tool output as data", "<tool_output>", "do not follow instructions"]) { continue; }
                let t = mcp[0];
                let f = Finding::new(
                    "ii-mcp-output-no-trust-label",
                    DetectorCategory::IndirectInjection,
                    Severity::Medium,
                    "MCP output enters context without trust label",
                    format!(
                        "Agent `{}` consumes MCP tool output (e.g. `{}`) with no trust label or \
                         instruction/data separation. MCP results are externally controlled and can \
                         carry injected instructions.",
                        a.name, t.name
                    ),
                )
                .with_agent(a.id.clone())
                .with_tool(t.id.clone())
                .with_evidence(tool_evidence(t))
                .with_location(loc(&a.location))
                .with_fix("Tag MCP results as untrusted data, wrap them in non-spoofable delimiters, and strip control characters.");
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::GoalHijacking)
                        .with_llm(OwaspLlm2025::PromptInjection)
                        .with_llm(OwaspLlm2025::SupplyChain)
                }));
            }
            out
        }
    }

    /// Email/webpage tool output reaches context (indirect injection vector).
    IiEmailWebpageToolToContext {
        id: "ii-email-webpage-tool-to-context",
        category: DetectorCategory::IndirectInjection,
        severity: Severity::High,
        title: "Email/web tool output reaches context",
        detect: |g| {
            let mut out = Vec::new();
            for a in &g.agents {
                let prompt = lc(&a.system_prompt);
                let sanitizes = contains_any(&prompt, &["untrusted", "treat as data", "do not follow instructions", "<email>", "<page>"]);
                for t in g.tools_of(&a.id) {
                    let surface = format!("{} {}", t.name, t.description.as_deref().unwrap_or(""));
                    let is_fetcher = contains_any(&surface, FETCHER_MARKERS) || t.effects.net_egress;
                    if !is_fetcher { continue; }
                    if sanitizes { continue; }
                    let f = Finding::new(
                        "ii-email-webpage-tool-to-context",
                        DetectorCategory::IndirectInjection,
                        Severity::High,
                        "Email/web tool output reaches context",
                        format!(
                            "Agent `{}` ingests content from external-fetch tool `{}` (email/web) into \
                             its context unsanitized. Attacker-authored pages/emails can inject \
                             instructions the agent then obeys.",
                            a.name, t.name
                        ),
                    )
                    .with_agent(a.id.clone())
                    .with_tool(t.id.clone())
                    .with_evidence(tool_evidence(t))
                    .with_location(loc(&t.location))
                    .with_fix("Treat fetched email/web content as untrusted data; fence it, strip active content, and never act on embedded instructions.");
                    out.push(tagged(f, |c| {
                        c.with_agentic(OwaspAgentic2026::GoalHijacking)
                            .with_llm(OwaspLlm2025::PromptInjection)
                            .with_atlas("AML.T0051.001")
                    }));
                }
            }
            out
        }
    }
}
