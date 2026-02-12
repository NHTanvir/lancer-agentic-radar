//! Handoff-abuse sub-checks for OpenAI Agents SDK-style multi-agent systems
//! (plan §"Detector catalog" item 17).
//!
//! When one agent hands control to another, an input filter, a loop cap, and
//! per-agent scoping matter. These checks also flag disabled guardrails and
//! disabled tracing in production.

use crate::detector::helpers::*;
use crate::define_detectors;
use ar_core::{DetectorCategory, Finding, OwaspAgentic2026, OwaspLlm2025, Severity};

define_detectors! {
    /// A handoff edge with no input filter.
    OaHandoffWithoutInputFilter {
        id: "oa-handoff-without-input-filter",
        category: DetectorCategory::HandoffAbuse,
        severity: Severity::Medium,
        title: "Agent handoff without input filter",
        detect: |g| {
            let mut out = Vec::new();
            for e in g.handoff_edges() {
                // Heuristic: an input filter would be recorded in the edge label.
                let has_filter = e.label.as_deref().map(|l| {
                    let l = l.to_ascii_lowercase();
                    l.contains("filter") || l.contains("sanitiz") || l.contains("input_filter") || l.contains("guard")
                }).unwrap_or(false);
                if has_filter { continue; }
                let from = g.name_of(&e.from);
                let to = g.name_of(&e.to);
                let f = Finding::new(
                    "oa-handoff-without-input-filter",
                    DetectorCategory::HandoffAbuse,
                    Severity::Medium,
                    "Agent handoff without input filter",
                    format!(
                        "Handoff `{}` -> `{}` passes the conversation across with no input filter, \
                         so injected instructions and tainted context carry into the receiving agent.",
                        from, to
                    ),
                )
                .with_agent(e.from.clone())
                .with_evidence(format!("handoff {} -> {}", from, to))
                .with_location(loc(&g.agent(&e.from).map(|a| a.location.clone()).unwrap_or_default()))
                .with_fix("Attach an input filter to the handoff that strips/limits the transferred context and re-establishes the receiving agent's instructions.");
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::UnauthorizedHandoff)
                        .with_agentic(OwaspAgentic2026::GoalHijacking)
                        .with_llm(OwaspLlm2025::PromptInjection)
                }));
            }
            out
        }
    }

    /// A handoff cycle with no cap.
    OaHandoffLoopNoCap {
        id: "oa-handoff-loop-no-cap",
        category: DetectorCategory::HandoffAbuse,
        severity: Severity::Medium,
        title: "Handoff loop without cap",
        detect: |g| {
            let mut out = Vec::new();
            // Build a handoff-only adjacency and look for a cycle among agents.
            let handoffs: Vec<&ar_core::Edge> = g.handoff_edges();
            if handoffs.is_empty() { return out; }
            // Reuse cycles() but require the cycle to be linked by handoff edges.
            for scc in g.cycles() {
                if scc.len() < 2 { continue; }
                let in_scc: std::collections::HashSet<&ar_core::NodeId> = scc.iter().collect();
                let handoff_in_cycle = handoffs.iter().any(|e| in_scc.contains(&e.from) && in_scc.contains(&e.to));
                if !handoff_in_cycle { continue; }
                let capped = handoffs.iter().any(|e| {
                    in_scc.contains(&e.from) && e.label.as_deref().map(|l| {
                        let l = l.to_ascii_lowercase();
                        l.contains("max") || l.contains("limit") || l.contains("cap") || l.contains("turn")
                    }).unwrap_or(false)
                });
                if capped { continue; }
                let names: Vec<String> = scc.iter().map(|id| g.name_of(id)).collect();
                let f = Finding::new(
                    "oa-handoff-loop-no-cap",
                    DetectorCategory::HandoffAbuse,
                    Severity::Medium,
                    "Handoff loop without cap",
                    format!("Agents [{}] can hand off in a loop with no turn cap, so control can bounce between them indefinitely.", names.join(" -> ")),
                )
                .with_agent(scc[0].clone())
                .with_evidence(format!("handoff cycle: {}", names.join(" -> ")))
                .with_location(loc(&g.agent(&scc[0]).map(|a| a.location.clone()).unwrap_or_default()))
                .with_fix("Bound the total number of handoffs / turns per run and add an explicit terminal agent.");
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::UnauthorizedHandoff)
                        .with_agentic(OwaspAgentic2026::CascadingFailure)
                        .with_llm(OwaspLlm2025::UnboundedConsumption)
                }));
            }
            out
        }
    }

    /// An agent exposed as a tool to another agent without scoping.
    OaAgentAsToolNoScoping {
        id: "oa-agent-as-tool-no-scoping",
        category: DetectorCategory::HandoffAbuse,
        severity: Severity::Medium,
        title: "Agent-as-tool without scoping",
        detect: |g| {
            let mut out = Vec::new();
            // A tool node whose id/name refers to an agent, or that is marked
            // as an agent-as-tool wrapper.
            for t in &g.tools {
                let s = format!("{} {}", t.name, t.signature.as_deref().unwrap_or("")).to_ascii_lowercase();
                let agent_as_tool = s.contains("as_tool") || s.contains("agent_as_tool")
                    || g.agents.iter().any(|a| a.name.eq_ignore_ascii_case(&t.name) && a.id != t.id);
                if !agent_as_tool { continue; }
                let scoped = contains_any(&s, &["scope", "allowed", "guard", "restrict", "limit"]) || t.has_input_schema;
                if scoped { continue; }
                let f = Finding::new(
                    "oa-agent-as-tool-no-scoping",
                    DetectorCategory::HandoffAbuse,
                    Severity::Medium,
                    "Agent-as-tool without scoping",
                    format!("Tool `{}` wraps another agent (agent-as-tool) with no scoping/guard, so the caller inherits the sub-agent's full authority.", t.name),
                )
                .with_tool(t.id.clone())
                .with_evidence(tool_evidence(t))
                .with_location(loc(&t.location))
                .with_fix("Scope the agent-as-tool to a narrow input schema and a restricted tool set; add a guardrail on its output.");
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::UnauthorizedHandoff)
                        .with_agentic(OwaspAgentic2026::UnsafeAutonomyEscalation)
                        .with_llm(OwaspLlm2025::ExcessiveAgency)
                }));
            }
            out
        }
    }

    /// A guardrail is explicitly disabled.
    OaGuardrailDisabled {
        id: "oa-guardrail-disabled",
        category: DetectorCategory::HandoffAbuse,
        severity: Severity::High,
        title: "Guardrail disabled",
        detect: |g| {
            let mut out = Vec::new();
            for a in &g.agents {
                let s = {
                    let mut x = String::new();
                    if let Some(p) = &a.system_prompt { x.push_str(p); x.push('\n'); }
                    if let Some(snip) = &a.location.snippet { x.push_str(snip); }
                    x.to_ascii_lowercase()
                };
                let disabled = contains_any(&s, &["guardrails=none", "guardrail=none", "guardrails=[]", "disable_guardrail", "guardrails_disabled", "no guardrail"]);
                if !disabled { continue; }
                let f = Finding::new(
                    "oa-guardrail-disabled",
                    DetectorCategory::HandoffAbuse,
                    Severity::High,
                    "Guardrail disabled",
                    format!("Agent `{}` explicitly disables its guardrails, removing the input/output safety checks the framework provides.", a.name),
                )
                .with_agent(a.id.clone())
                .with_evidence(prompt_evidence(a))
                .with_location(loc(&a.location))
                .with_fix("Re-enable input/output guardrails for the agent.");
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::GoalHijacking)
                        .with_agentic(OwaspAgentic2026::RogueAgent)
                        .with_llm(OwaspLlm2025::PromptInjection)
                }));
            }
            out
        }
    }

    /// Tracing disabled in production (traceability gap).
    OaTracingDisabledInProd {
        id: "oa-tracing-disabled-in-prod",
        category: DetectorCategory::HandoffAbuse,
        severity: Severity::Low,
        title: "Tracing disabled in production",
        detect: |g| {
            let mut out = Vec::new();
            for a in &g.agents {
                let s = {
                    let mut x = String::new();
                    if let Some(snip) = &a.location.snippet { x.push_str(snip); }
                    x.to_ascii_lowercase()
                };
                let disabled = contains_any(&s, &["tracing_disabled=true", "tracing=false", "disable_tracing", "tracing=none", "set_tracing_disabled(true)"]);
                if !disabled { continue; }
                let f = Finding::new(
                    "oa-tracing-disabled-in-prod",
                    DetectorCategory::HandoffAbuse,
                    Severity::Low,
                    "Tracing disabled in production",
                    format!("Agent `{}` disables tracing, leaving no audit trail of tool calls and handoffs (traceability gap).", a.name),
                )
                .with_agent(a.id.clone())
                .with_evidence(prompt_evidence(a))
                .with_location(loc(&a.location))
                .with_fix("Enable tracing/telemetry in production and ship spans to an observability backend.");
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::TraceabilityGap)
                        .with_llm(OwaspLlm2025::Misinformation)
                        .with_nist("MEASURE 2.8")
                }));
            }
            out
        }
    }
}
