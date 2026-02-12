//! Resource-exhaustion sub-checks (plan §"Detector catalog" item 14).
//!
//! Unbounded token budgets, no max-step cap, no rate limit on tool calls, and
//! no cost cap are all unbounded-consumption risks. These are inferred from the
//! absence of the relevant configuration in the agent's prompt / source snippet.

use crate::detector::helpers::*;
use crate::define_detectors;
use ar_core::{AgentNode, DetectorCategory, Finding, OwaspAgentic2026, OwaspLlm2025, Severity};

/// Combined searchable text for an agent (prompt + source snippet + model).
fn agent_surface(a: &AgentNode) -> String {
    let mut s = String::new();
    if let Some(p) = &a.system_prompt { s.push_str(p); s.push('\n'); }
    if let Some(snip) = &a.location.snippet { s.push_str(snip); s.push('\n'); }
    if let Some(m) = &a.model { s.push_str(m); s.push('\n'); }
    s.to_ascii_lowercase()
}

define_detectors! {
    /// No token budget / max_tokens configured.
    ReTokenBudgetUnbounded {
        id: "re-token-budget-unbounded",
        category: DetectorCategory::ResourceExhaustion,
        severity: Severity::Low,
        title: "Token budget is unbounded",
        detect: |g| {
            let mut out = Vec::new();
            for a in &g.agents {
                let s = agent_surface(a);
                if contains_any(&s, &["max_tokens", "max_output_tokens", "token_limit", "max_completion_tokens", "maxtokens"]) { continue; }
                let f = Finding::new(
                    "re-token-budget-unbounded",
                    DetectorCategory::ResourceExhaustion,
                    Severity::Low,
                    "Token budget is unbounded",
                    format!("Agent `{}` sets no max-token / output-token budget, so a request can drive unbounded generation cost.", a.name),
                )
                .with_agent(a.id.clone())
                .with_evidence(prompt_evidence(a))
                .with_location(loc(&a.location))
                .with_fix("Set max_tokens / max_output_tokens on the model call.")
                .with_confidence(ar_core::Confidence::Low);
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::CascadingFailure)
                        .with_llm(OwaspLlm2025::UnboundedConsumption)
                }));
            }
            out
        }
    }

    /// No max-steps / iteration cap on the agent loop.
    ReNoMaxSteps {
        id: "re-no-max-steps",
        category: DetectorCategory::ResourceExhaustion,
        severity: Severity::Medium,
        title: "No max-steps / iteration cap",
        detect: |g| {
            let mut out = Vec::new();
            for a in &g.agents {
                // Only meaningful for agents that call tools (can loop).
                if g.tools_of(&a.id).is_empty() { continue; }
                let s = agent_surface(a);
                if contains_any(&s, &["max_iterations", "max_steps", "recursion_limit", "max_turns", "step_budget", "max_iter"]) { continue; }
                let f = Finding::new(
                    "re-no-max-steps",
                    DetectorCategory::ResourceExhaustion,
                    Severity::Medium,
                    "No max-steps / iteration cap",
                    format!("Agent `{}` calls tools with no max-iterations / max-steps cap, so a reasoning loop can run unbounded tool calls.", a.name),
                )
                .with_agent(a.id.clone())
                .with_evidence(prompt_evidence(a))
                .with_location(loc(&a.location))
                .with_fix("Set max_iterations / recursion_limit / max_turns on the agent executor.");
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::CascadingFailure)
                        .with_llm(OwaspLlm2025::UnboundedConsumption)
                }));
            }
            out
        }
    }

    /// No rate limit on tool calls.
    ReNoRateLimit {
        id: "re-no-rate-limit",
        category: DetectorCategory::ResourceExhaustion,
        severity: Severity::Low,
        title: "No rate limit on tool calls",
        detect: |g| {
            let mut out = Vec::new();
            for a in &g.agents {
                let tools = g.tools_of(&a.id);
                // Risk grows with the number of (especially networked) tools.
                let networked = tools.iter().any(|t| t.effects.net_egress);
                if tools.is_empty() { continue; }
                let s = agent_surface(a);
                if contains_any(&s, &["rate_limit", "ratelimit", "throttle", "backoff", "semaphore", "per_minute", "qps"]) { continue; }
                let f = Finding::new(
                    "re-no-rate-limit",
                    DetectorCategory::ResourceExhaustion,
                    Severity::Low,
                    "No rate limit on tool calls",
                    format!("Agent `{}` calls tools with no rate limit/throttle, so it can hammer downstream services (DoS / cost amplification).", a.name),
                )
                .with_agent(a.id.clone())
                .with_evidence(format!("{} tool(s); networked={}", tools.len(), networked))
                .with_location(loc(&a.location))
                .with_fix("Add per-tool rate limiting / throttling and a global call budget per request.")
                .with_confidence(ar_core::Confidence::Low);
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::CascadingFailure)
                        .with_llm(OwaspLlm2025::UnboundedConsumption)
                }));
            }
            out
        }
    }

    /// No cost cap configured.
    ReNoCostCap {
        id: "re-no-cost-cap",
        category: DetectorCategory::ResourceExhaustion,
        severity: Severity::Low,
        title: "No cost cap",
        detect: |g| {
            let mut out = Vec::new();
            for a in &g.agents {
                let s = agent_surface(a);
                if contains_any(&s, &["cost_cap", "budget", "max_cost", "spend_limit", "usage_limit"]) { continue; }
                // Only when the agent actually does work (tools or model set).
                if g.tools_of(&a.id).is_empty() && a.model.is_none() { continue; }
                let f = Finding::new(
                    "re-no-cost-cap",
                    DetectorCategory::ResourceExhaustion,
                    Severity::Low,
                    "No cost cap",
                    format!("Agent `{}` has no per-request / per-session cost cap, so a hostile workload can run up arbitrary spend.", a.name),
                )
                .with_agent(a.id.clone())
                .with_evidence(prompt_evidence(a))
                .with_location(loc(&a.location))
                .with_fix("Enforce a per-request and per-session cost budget; abort when exceeded.")
                .with_confidence(ar_core::Confidence::Low);
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::CascadingFailure)
                        .with_llm(OwaspLlm2025::UnboundedConsumption)
                }));
            }
            out
        }
    }
}
