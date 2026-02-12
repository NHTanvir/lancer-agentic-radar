//! Trust-boundary sub-checks (plan §"Detector catalog" item 5).
//!
//! These are the core data-flow checks: tainted data (user input, raw LLM
//! output, untrusted tool/RAG results) reaching a privileged sink. ar-core's
//! [`AgentGraph::edges_crossing_trust_boundary`] does the heavy lifting; each
//! sub-check here specializes the source/sink pairing.

use crate::detector::helpers::*;
use crate::define_detectors;
use ar_core::{
    AgentGraph, AgentNode, DetectorCategory, Finding, OwaspAgentic2026, OwaspLlm2025, Severity,
    ToolNode,
};

/// Iterate over tainted-source → privileged-tool call edges, resolving the
/// caller agent and the called tool for each.
fn tainted_calls(g: &AgentGraph) -> Vec<(&AgentNode, &ToolNode)> {
    let mut out = Vec::new();
    for e in g.edges_crossing_trust_boundary() {
        if let (Some(a), Some(t)) = (g.agent(&e.from), g.tool(&e.to)) {
            out.push((a, t));
        }
    }
    out
}

/// Does any agent that calls `tool` also read from a tainted RAG source?
fn agent_reads_tainted_rag(g: &AgentGraph, agent: &AgentNode) -> bool {
    g.rag_of(&agent.id).iter().any(|r| r.trust.is_tainted())
}

define_detectors! {
    /// Tainted data reaches a privileged tool's input (the general case).
    TbToolOutputToNextToolInput {
        id: "tb-tool-output-to-next-tool-input",
        category: DetectorCategory::TrustBoundary,
        severity: Severity::High,
        title: "Tainted data flows into a privileged tool",
        detect: |g| {
            let mut out = Vec::new();
            for (a, t) in tainted_calls(g) {
                let f = Finding::new(
                    "tb-tool-output-to-next-tool-input",
                    DetectorCategory::TrustBoundary,
                    Severity::High,
                    "Tainted data flows into a privileged tool",
                    format!(
                        "Agent `{}` carries tainted (untrusted / mixed) data into privileged tool \
                         `{}` [{}]. Untrusted tool/LLM output flowing into another tool's input is \
                         a trust-boundary violation that can be chained into a real exploit.",
                        a.name, t.name, t.effects.badges().join(",")
                    ),
                )
                .with_agent(a.id.clone())
                .with_tool(t.id.clone())
                .with_evidence(format!(
                    "edge: {} --calls--> {} (effects: {})",
                    a.name, t.name, t.effects.badges().join(",")
                ))
                .with_location(loc(&t.location))
                .with_fix(
                    "Insert a validation / sanitization step between the untrusted source and the \
                     privileged tool; strip control sequences and constrain the tool's arguments to \
                     an allowlisted schema.",
                );
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::ToolMisuse)
                        .with_llm(OwaspLlm2025::ImproperOutputHandling)
                        .with_llm(OwaspLlm2025::ExcessiveAgency)
                        .with_atlas("AML.T0051")
                }));
            }
            out
        }
    }

    /// Untrusted RAG document content reaches a shell-exec tool.
    TbRagDocToShellTool {
        id: "tb-rag-doc-to-shell-tool",
        category: DetectorCategory::TrustBoundary,
        severity: Severity::Critical,
        title: "Untrusted RAG content reaches a shell tool",
        detect: |g| {
            let mut out = Vec::new();
            for (a, t) in g.agents_calling_tool_with_effect(|e| e.shell_exec) {
                if !agent_reads_tainted_rag(g, a) { continue; }
                let f = Finding::new(
                    "tb-rag-doc-to-shell-tool",
                    DetectorCategory::TrustBoundary,
                    Severity::Critical,
                    "Untrusted RAG content reaches a shell tool",
                    format!(
                        "Agent `{}` reads untrusted RAG documents and can call shell tool `{}`. A \
                         poisoned document can drive shell command injection.",
                        a.name, t.name
                    ),
                )
                .with_agent(a.id.clone())
                .with_tool(t.id.clone())
                .with_evidence(format!("agent `{}` -> shell tool `{}`", a.name, t.name))
                .with_location(loc(&t.location))
                .with_fix(
                    "Never let retrieved document text reach a shell command. Use a fixed command \
                     allowlist with parameterized, non-shell execution and validate all inputs.",
                );
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::ToolMisuse)
                        .with_agentic(OwaspAgentic2026::UnsafeAutonomyEscalation)
                        .with_llm(OwaspLlm2025::ImproperOutputHandling)
                        .with_atlas("AML.T0051")
                }));
            }
            out
        }
    }

    /// User input reaches a code-eval tool.
    TbUserInputToEval {
        id: "tb-user-input-to-eval",
        category: DetectorCategory::TrustBoundary,
        severity: Severity::Critical,
        title: "User input reaches a code-eval tool",
        detect: |g| {
            let mut out = Vec::new();
            for (a, t) in g.agents_calling_tool_with_effect(|e| e.code_eval) {
                // Source must be tainted (accepts user input or reads tainted RAG).
                if !(a.accepts_user_input || agent_reads_tainted_rag(g, a)) { continue; }
                let f = Finding::new(
                    "tb-user-input-to-eval",
                    DetectorCategory::TrustBoundary,
                    Severity::Critical,
                    "User input reaches a code-eval tool",
                    format!(
                        "Agent `{}` accepts untrusted input and can call code-eval tool `{}`. \
                         Untrusted input flowing into eval/exec is remote code execution.",
                        a.name, t.name
                    ),
                )
                .with_agent(a.id.clone())
                .with_tool(t.id.clone())
                .with_evidence(format!("agent `{}` -> eval tool `{}`", a.name, t.name))
                .with_location(loc(&t.location))
                .with_fix(
                    "Remove dynamic code execution from the tool surface, or sandbox it with a \
                     hardened, resource-limited interpreter and never pass untrusted strings to it.",
                );
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::UnsafeAutonomyEscalation)
                        .with_agentic(OwaspAgentic2026::ToolMisuse)
                        .with_llm(OwaspLlm2025::ImproperOutputHandling)
                        .with_atlas("AML.T0050")
                }));
            }
            out
        }
    }

    /// LLM/tainted output reaches a filesystem-write tool.
    TbLlmOutputToFsWrite {
        id: "tb-llm-output-to-fs-write",
        category: DetectorCategory::TrustBoundary,
        severity: Severity::High,
        title: "LLM output reaches a filesystem-write tool",
        detect: |g| {
            let mut out = Vec::new();
            for (a, t) in g.agents_calling_tool_with_effect(|e| e.writes_fs) {
                // LLM output is always mixed/tainted; report when there is no
                // intervening validation (best-effort: always, since static).
                let f = Finding::new(
                    "tb-llm-output-to-fs-write",
                    DetectorCategory::TrustBoundary,
                    Severity::High,
                    "LLM output reaches a filesystem-write tool",
                    format!(
                        "Agent `{}` can write LLM-generated (untrusted) content to the filesystem \
                         via `{}`. Model output is mixed-trust; writing it unconstrained risks path \
                         traversal and content injection.",
                        a.name, t.name
                    ),
                )
                .with_agent(a.id.clone())
                .with_tool(t.id.clone())
                .with_evidence(format!("agent `{}` -> fs-write tool `{}`", a.name, t.name))
                .with_location(loc(&t.location))
                .with_fix(
                    "Constrain write paths to an allowlisted directory, reject traversal sequences, \
                     and validate file content/type before writing model output to disk.",
                )
                .with_confidence(if a.accepts_user_input { ar_core::Confidence::High } else { ar_core::Confidence::Medium });
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::ToolMisuse)
                        .with_llm(OwaspLlm2025::ImproperOutputHandling)
                }));
            }
            out
        }
    }

    /// LLM/tainted output reaches a database-write / SQL tool.
    TbLlmOutputToSqlQuery {
        id: "tb-llm-output-to-sql-query",
        category: DetectorCategory::TrustBoundary,
        severity: Severity::High,
        title: "LLM output reaches a database-write tool",
        detect: |g| {
            let mut out = Vec::new();
            for (a, t) in g.agents_calling_tool_with_effect(|e| e.db_write) {
                let f = Finding::new(
                    "tb-llm-output-to-sql-query",
                    DetectorCategory::TrustBoundary,
                    Severity::High,
                    "LLM output reaches a database-write tool",
                    format!(
                        "Agent `{}` can drive database writes via `{}` using LLM-generated \
                         (untrusted) content. Model-authored SQL/queries are an injection sink.",
                        a.name, t.name
                    ),
                )
                .with_agent(a.id.clone())
                .with_tool(t.id.clone())
                .with_evidence(format!("agent `{}` -> db-write tool `{}`", a.name, t.name))
                .with_location(loc(&t.location))
                .with_fix(
                    "Use parameterized queries and a fixed set of allowed operations; never let the \
                     model author raw SQL. Require a WHERE clause on destructive statements.",
                );
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::ToolMisuse)
                        .with_llm(OwaspLlm2025::ImproperOutputHandling)
                        .with_llm(OwaspLlm2025::ExcessiveAgency)
                }));
            }
            out
        }
    }

    /// An MCP tool result reaches a shell-exec tool.
    TbMcpResultToShell {
        id: "tb-mcp-result-to-shell",
        category: DetectorCategory::TrustBoundary,
        severity: Severity::Critical,
        title: "MCP tool result reaches a shell tool",
        detect: |g| {
            use ar_core::ToolSource;
            let mut out = Vec::new();
            for a in &g.agents {
                let tools = g.tools_of(&a.id);
                let has_mcp = tools.iter().any(|t| matches!(t.source, ToolSource::Mcp(_)));
                if !has_mcp { continue; }
                for t in tools.iter().filter(|t| t.effects.shell_exec) {
                    let f = Finding::new(
                        "tb-mcp-result-to-shell",
                        DetectorCategory::TrustBoundary,
                        Severity::Critical,
                        "MCP tool result reaches a shell tool",
                        format!(
                            "Agent `{}` calls both an MCP-sourced tool and shell tool `{}` in the \
                             same context. Untrusted MCP output can be chained into shell execution.",
                            a.name, t.name
                        ),
                    )
                    .with_agent(a.id.clone())
                    .with_tool(t.id.clone())
                    .with_evidence(format!("agent `{}` has MCP tools + shell tool `{}`", a.name, t.name))
                    .with_location(loc(&t.location))
                    .with_fix(
                        "Isolate MCP tool output from privileged sinks; validate and never pass MCP \
                         results into a shell command.",
                    );
                    out.push(tagged(f, |c| {
                        c.with_agentic(OwaspAgentic2026::ToolMisuse)
                            .with_agentic(OwaspAgentic2026::UnsafeAutonomyEscalation)
                            .with_llm(OwaspLlm2025::SupplyChain)
                            .with_llm(OwaspLlm2025::ImproperOutputHandling)
                            .with_atlas("AML.T0051")
                    }));
                }
            }
            out
        }
    }
}
