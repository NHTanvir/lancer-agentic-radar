//! Recursion-bomb sub-checks (plan §"Detector catalog" item 12).
//!
//! An agent that can call itself (or a sub-agent that calls back) without a
//! depth cap, and mutual recursion across a cycle of agents, are cascading-
//! failure / unbounded-consumption risks.

use crate::detector::helpers::*;
use crate::define_detectors;
use ar_core::{DetectorCategory, EdgeKind, Finding, NodeKind, OwaspAgentic2026, OwaspLlm2025, Severity};

define_detectors! {
    /// An agent can invoke itself (self-loop) with no depth cap.
    RbAgentSelfCallNoCap {
        id: "rb-agent-self-call-no-cap",
        category: DetectorCategory::RecursionBomb,
        severity: Severity::Medium,
        title: "Agent self-recursion without depth cap",
        detect: |g| {
            let mut out = Vec::new();
            for a in &g.agents {
                // Self-loop via calls/handoff/data-flow edge.
                let self_loop = g.edges.iter().any(|e| e.from == a.id && e.to == a.id);
                if !self_loop { continue; }
                let prompt = lc(&a.system_prompt);
                let capped = contains_any(&prompt, &["max_depth", "depth limit", "max iterations", "max_steps", "recursion limit"]);
                if capped { continue; }
                let f = Finding::new(
                    "rb-agent-self-call-no-cap",
                    DetectorCategory::RecursionBomb,
                    Severity::Medium,
                    "Agent self-recursion without depth cap",
                    format!(
                        "Agent `{}` can invoke itself with no detectable depth cap, so a crafted \
                         input can drive unbounded recursion (resource exhaustion / cascading failure).",
                        a.name
                    ),
                )
                .with_agent(a.id.clone())
                .with_evidence(format!("self-edge on agent `{}`", a.name))
                .with_location(loc(&a.location))
                .with_fix("Add a recursion/iteration depth cap and a terminating condition to the agent loop.");
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::CascadingFailure)
                        .with_llm(OwaspLlm2025::UnboundedConsumption)
                }));
            }
            out
        }
    }

    /// Mutual recursion: a cycle that contains two or more agents.
    RbMutualRecursion {
        id: "rb-mutual-recursion",
        category: DetectorCategory::RecursionBomb,
        severity: Severity::Medium,
        title: "Mutual recursion across agents",
        detect: |g| {
            let mut out = Vec::new();
            for scc in g.cycles() {
                // Need at least two agents in the cycle for mutual recursion.
                let agents: Vec<_> = scc.iter().filter(|id| g.kind_of(id) == Some(NodeKind::Agent)).collect();
                if agents.len() < 2 { continue; }
                // Skip pure self-loops (handled by rb-agent-self-call-no-cap).
                if scc.len() == 1 { continue; }
                let names: Vec<String> = agents.iter().map(|id| g.name_of(id)).collect();
                // Is any edge in the cycle conditional/capped (best-effort)?
                let capped = scc.iter().any(|id| {
                    g.edges_from(id).any(|e| {
                        matches!(e.kind, EdgeKind::Handoff | EdgeKind::Calls)
                            && e.label.as_deref().map(|l| {
                                let l = l.to_ascii_lowercase();
                                l.contains("max") || l.contains("limit") || l.contains("done") || l.contains("end")
                            }).unwrap_or(false)
                    })
                });
                if capped { continue; }
                let f = Finding::new(
                    "rb-mutual-recursion",
                    DetectorCategory::RecursionBomb,
                    Severity::Medium,
                    "Mutual recursion across agents",
                    format!(
                        "Agents [{}] form a cycle with no detectable termination guard, so they can \
                         hand control back and forth indefinitely (cascading failure).",
                        names.join(" -> ")
                    ),
                )
                .with_agent(agents[0].clone())
                .with_evidence(format!("cycle: {}", names.join(" -> ")))
                .with_location(loc(&g.agent(agents[0]).map(|a| a.location.clone()).unwrap_or_default()))
                .with_fix("Add a global step/turn budget and an explicit exit condition for the agent hand-off cycle.");
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::CascadingFailure)
                        .with_agentic(OwaspAgentic2026::UnauthorizedHandoff)
                        .with_llm(OwaspLlm2025::UnboundedConsumption)
                }));
            }
            out
        }
    }
}
