//! Infinite-loop sub-checks (plan §"Detector catalog" item 13).
//!
//! `while True:`-style loops without a timeout / step budget, and LangGraph
//! cycles with no exit condition, can spin forever.

use crate::detector::helpers::*;
use crate::define_detectors;
use ar_core::{DetectorCategory, EdgeKind, Finding, OwaspAgentic2026, OwaspLlm2025, Severity};

define_detectors! {
    /// A `while True` / unbounded loop with no timeout or step budget.
    IlWhileTrueNoTimeout {
        id: "il-while-true-no-timeout",
        category: DetectorCategory::InfiniteLoop,
        severity: Severity::Medium,
        title: "Unbounded loop without timeout / step budget",
        detect: |g| {
            let mut out = Vec::new();
            // Inspect agent snippets and unresolved nodes for unbounded loops.
            let consider = |snippet: &str, where_: String, loc_opt: Option<&ar_core::SourceLocation>, agent: Option<&ar_core::AgentNode>| -> Option<Finding> {
                let s = snippet.to_ascii_lowercase();
                let loops = s.contains("while true") || s.contains("while 1") || s.contains("loop {") || rx_match(&s, r"while\s*\(\s*true\s*\)");
                if !loops { return None; }
                let bounded = contains_any(&s, &["break", "timeout", "max_steps", "max_iter", "deadline", "step_budget", "recursion_limit", "elapsed"]);
                if bounded { return None; }
                let mut f = Finding::new(
                    "il-while-true-no-timeout",
                    DetectorCategory::InfiniteLoop,
                    Severity::Medium,
                    "Unbounded loop without timeout / step budget",
                    format!("{where_} contains an unbounded loop with no break/timeout/step budget, which can spin forever (resource exhaustion)."),
                )
                .with_evidence(truncate(snippet, 160))
                .with_fix("Add a timeout, a maximum-iteration counter, and an explicit break condition to the loop.");
                if let Some(l) = loc_opt { f = f.with_location(loc(l)); }
                if let Some(a) = agent { f = f.with_agent(a.id.clone()); }
                Some(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::CascadingFailure)
                        .with_llm(OwaspLlm2025::UnboundedConsumption)
                }))
            };
            for a in &g.agents {
                if let Some(snip) = &a.location.snippet {
                    if let Some(f) = consider(snip.as_str(), format!("Agent `{}`", a.name), Some(&a.location), Some(a)) {
                        out.push(f);
                    }
                }
            }
            for (id, label) in &g.unknowns {
                if let Some(f) = consider(label.as_str(), format!("Unresolved node `{id}`"), None, None) {
                    out.push(f);
                }
            }
            out
        }
    }

    /// A LangGraph (or any) cycle of nodes with no exit/terminal edge.
    IlLanggraphCycleNoExit {
        id: "il-langgraph-cycle-no-exit",
        category: DetectorCategory::InfiniteLoop,
        severity: Severity::Medium,
        title: "Graph cycle without exit condition",
        detect: |g| {
            let mut out = Vec::new();
            for scc in g.cycles() {
                if scc.is_empty() { continue; }
                // Does any node in the cycle have an edge that LEAVES the cycle
                // (an exit) or a conditional edge labelled like an exit?
                let in_scc: std::collections::HashSet<&ar_core::NodeId> = scc.iter().collect();
                let mut has_exit = false;
                let mut has_conditional = false;
                for id in &scc {
                    for e in g.edges_from(id) {
                        if !in_scc.contains(&e.to) {
                            has_exit = true;
                        }
                        if e.label.is_some() && matches!(e.kind, EdgeKind::Calls | EdgeKind::Handoff | EdgeKind::DataFlow | EdgeKind::Triggers) {
                            let l = e.label.as_deref().unwrap_or("").to_ascii_lowercase();
                            if l.contains("end") || l.contains("done") || l.contains("exit") || l.contains("stop") || l.contains("finish") || l.contains("complete") {
                                has_conditional = true;
                            }
                        }
                    }
                }
                if has_exit || has_conditional { continue; }
                let names: Vec<String> = scc.iter().map(|id| g.name_of(id)).collect();
                let first = &scc[0];
                let f = Finding::new(
                    "il-langgraph-cycle-no-exit",
                    DetectorCategory::InfiniteLoop,
                    Severity::Medium,
                    "Graph cycle without exit condition",
                    format!(
                        "Nodes [{}] form a cycle with no edge leaving the cycle and no exit-labelled \
                         conditional edge, so the state machine can loop without terminating.",
                        names.join(" -> ")
                    ),
                )
                .with_evidence(format!("cycle: {}", names.join(" -> ")))
                .with_fix("Add a conditional edge to a terminal/END node with a clear exit predicate, and bound total steps.");
                let f = match g.agent(first) {
                    Some(a) => f.with_agent(a.id.clone()).with_location(loc(&a.location)),
                    None => f,
                };
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::CascadingFailure)
                        .with_llm(OwaspLlm2025::UnboundedConsumption)
                }));
            }
            out
        }
    }
}
