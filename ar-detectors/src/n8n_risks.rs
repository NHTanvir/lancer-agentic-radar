//! n8n workflow-risk sub-checks (plan §"Detector catalog" item 16).
//!
//! n8n workflows are parsed into the same [`AgentGraph`]; n8n-specific node
//! types surface as tools / triggers / unresolved nodes. These checks look for
//! public webhook triggers without auth, shared credentials, unsandboxed code
//! nodes, unbounded HTTP egress, AI-agent tool fan-out, and untrusted MCP nodes.

use crate::detector::helpers::*;
use crate::define_detectors;
use ar_core::{
    DetectorCategory, EdgeKind, Finding, OwaspAgentic2026, OwaspLlm2025, Severity, ToolSource,
};

/// Is this graph (likely) an n8n workflow? (any node declares the n8n framework
/// or carries an n8n-style label).
fn is_n8n(g: &ar_core::AgentGraph) -> bool {
    g.agents.iter().any(|a| a.framework == ar_core::Framework::N8n)
        || g.unknowns.iter().any(|(_, l)| l.to_ascii_lowercase().contains("n8n"))
        || g.tools.iter().any(|t| {
            let s = format!("{} {}", t.name, t.signature.as_deref().unwrap_or("")).to_ascii_lowercase();
            s.contains("n8n")
        })
}

/// Searchable text for a tool node (n8n node type lives in name/signature).
fn node_surface(t: &ar_core::ToolNode) -> String {
    format!(
        "{} {} {}",
        t.name,
        t.signature.as_deref().unwrap_or(""),
        t.description.as_deref().unwrap_or("")
    )
    .to_ascii_lowercase()
}

define_detectors! {
    /// A public webhook trigger with no authentication.
    N8nWebhookTriggerPublicWithoutAuth {
        id: "n8n-webhook-trigger-public-without-auth",
        category: DetectorCategory::N8nWorkflowRisks,
        severity: Severity::High,
        title: "Public n8n webhook trigger without auth",
        detect: |g| {
            if !is_n8n(g) { return Vec::new(); }
            let mut out = Vec::new();
            // Trigger edges + webhook-labelled nodes.
            let webhook_nodes: Vec<&ar_core::ToolNode> = g.tools.iter()
                .filter(|t| { let s = node_surface(t); s.contains("webhook") })
                .collect();
            let triggers: std::collections::HashSet<&ar_core::NodeId> = g.edges.iter()
                .filter(|e| e.kind == EdgeKind::Triggers)
                .map(|e| &e.from)
                .collect();
            for t in webhook_nodes {
                let s = node_surface(t);
                let has_auth = contains_any(&s, &["auth", "basicauth", "headerauth", "jwt", "bearer", "credential", "hmac", "signature"]);
                if has_auth { continue; }
                // A webhook node that is also a trigger entry point is the live
                // public ingress; treat it as Critical, otherwise High.
                let severity = if triggers.contains(&t.id) { Severity::Critical } else { Severity::High };
                let f = Finding::new(
                    "n8n-webhook-trigger-public-without-auth",
                    DetectorCategory::N8nWorkflowRisks,
                    severity,
                    "Public n8n webhook trigger without auth",
                    format!("n8n webhook node `{}` exposes a public entry point with no authentication, so anyone can invoke the workflow.", t.name),
                )
                .with_tool(t.id.clone())
                .with_evidence(node_surface(t))
                .with_location(loc(&t.location))
                .with_fix("Enable webhook authentication (header/basic auth, JWT, or HMAC signature) and restrict callers.");
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::IdentityAbuse)
                        .with_agentic(OwaspAgentic2026::GoalHijacking)
                        .with_llm(OwaspLlm2025::PromptInjection)
                }));
            }
            out
        }
    }

    /// Credentials shared across workflows.
    N8nCredentialSharedAcrossWorkflows {
        id: "n8n-credential-shared-across-workflows",
        category: DetectorCategory::N8nWorkflowRisks,
        severity: Severity::Medium,
        title: "n8n credential shared across workflows",
        detect: |g| {
            if !is_n8n(g) { return Vec::new(); }
            let mut out = Vec::new();
            for t in &g.tools {
                let s = node_surface(t);
                if !s.contains("credential") { continue; }
                let shared = contains_any(&s, &["shared", "global", "reused", "all workflows"]);
                if !shared { continue; }
                let f = Finding::new(
                    "n8n-credential-shared-across-workflows",
                    DetectorCategory::N8nWorkflowRisks,
                    Severity::Medium,
                    "n8n credential shared across workflows",
                    format!("n8n node `{}` uses a credential shared across workflows, widening the blast radius if any workflow is compromised.", t.name),
                )
                .with_tool(t.id.clone())
                .with_evidence(node_surface(t))
                .with_location(loc(&t.location))
                .with_fix("Scope credentials to a single workflow with least privilege; avoid global/shared credentials.");
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::IdentityAbuse)
                        .with_llm(OwaspLlm2025::ExcessiveAgency)
                        .with_aicm("AICM-IAM-02")
                }));
            }
            out
        }
    }

    /// A Code node running without a sandbox.
    N8nCodeNodeNoSandbox {
        id: "n8n-code-node-no-sandbox",
        category: DetectorCategory::N8nWorkflowRisks,
        severity: Severity::High,
        title: "n8n Code node without sandbox",
        detect: |g| {
            if !is_n8n(g) { return Vec::new(); }
            let mut out = Vec::new();
            for t in &g.tools {
                let s = node_surface(t);
                let is_code = s.contains("code") || s.contains("function") || t.effects.code_eval;
                if !is_code { continue; }
                if contains_any(&s, &["sandbox", "vm2", "isolated", "restricted"]) { continue; }
                let f = Finding::new(
                    "n8n-code-node-no-sandbox",
                    DetectorCategory::N8nWorkflowRisks,
                    Severity::High,
                    "n8n Code node without sandbox",
                    format!("n8n Code/Function node `{}` runs JavaScript/Python with no sandbox, so workflow input can reach arbitrary code execution.", t.name),
                )
                .with_tool(t.id.clone())
                .with_evidence(node_surface(t))
                .with_location(loc(&t.location))
                .with_fix("Run Code nodes in a restricted/sandboxed runtime and never pass untrusted input into eval.");
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::UnsafeAutonomyEscalation)
                        .with_agentic(OwaspAgentic2026::ToolMisuse)
                        .with_llm(OwaspLlm2025::ExcessiveAgency)
                        .with_atlas("AML.T0050")
                }));
            }
            out
        }
    }

    /// HTTP Request node with unbounded egress.
    N8nHttpRequestEgressUnbounded {
        id: "n8n-http-request-egress-unbounded",
        category: DetectorCategory::N8nWorkflowRisks,
        severity: Severity::Medium,
        title: "n8n HTTP Request node with unbounded egress",
        detect: |g| {
            if !is_n8n(g) { return Vec::new(); }
            let mut out = Vec::new();
            for t in &g.tools {
                let s = node_surface(t);
                let is_http = s.contains("httprequest") || s.contains("http request") || (t.effects.net_egress && s.contains("http"));
                if !is_http { continue; }
                if contains_any(&s, &["allowlist", "allowed_hosts", "allowed_domains", "ssrf"]) { continue; }
                let f = Finding::new(
                    "n8n-http-request-egress-unbounded",
                    DetectorCategory::N8nWorkflowRisks,
                    Severity::Medium,
                    "n8n HTTP Request node with unbounded egress",
                    format!("n8n HTTP Request node `{}` can call arbitrary URLs with no allowlist (SSRF / exfiltration channel).", t.name),
                )
                .with_tool(t.id.clone())
                .with_evidence(node_surface(t))
                .with_location(loc(&t.location))
                .with_fix("Restrict HTTP Request destinations to an allowlist and block internal/metadata endpoints.");
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::DataExfiltrationViaAgent)
                        .with_agentic(OwaspAgentic2026::ToolMisuse)
                        .with_llm(OwaspLlm2025::ExcessiveAgency)
                }));
            }
            out
        }
    }

    /// An AI Agent node wired to a large fan-out of tools.
    N8nAiAgentToolFanOut {
        id: "n8n-ai-agent-tool-fan-out",
        category: DetectorCategory::N8nWorkflowRisks,
        severity: Severity::Low,
        title: "n8n AI Agent node with large tool fan-out",
        detect: |g| {
            if !is_n8n(g) { return Vec::new(); }
            let mut out = Vec::new();
            for a in &g.agents {
                let tools = g.tools_of(&a.id);
                if tools.len() < 6 { continue; }
                let privileged = tools.iter().filter(|t| t.effects.is_privileged()).count();
                let f = Finding::new(
                    "n8n-ai-agent-tool-fan-out",
                    DetectorCategory::N8nWorkflowRisks,
                    if privileged >= 3 { Severity::Medium } else { Severity::Low },
                    "n8n AI Agent node with large tool fan-out",
                    format!(
                        "n8n AI Agent node `{}` is wired to {} tools ({} privileged). A broad tool \
                         surface increases the chance the model is steered into a dangerous call.",
                        a.name, tools.len(), privileged
                    ),
                )
                .with_agent(a.id.clone())
                .with_evidence(format!("{} tools, {} privileged", tools.len(), privileged))
                .with_location(loc(&a.location))
                .with_fix("Split responsibilities across smaller agents and grant each only the tools it needs.")
                .with_confidence(ar_core::Confidence::Low);
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::ToolMisuse)
                        .with_agentic(OwaspAgentic2026::UnsafeAutonomyEscalation)
                        .with_llm(OwaspLlm2025::ExcessiveAgency)
                }));
            }
            out
        }
    }

    /// An MCP node pointing at an untrusted server.
    N8nMcpNodeUntrustedServer {
        id: "n8n-mcp-node-untrusted-server",
        category: DetectorCategory::N8nWorkflowRisks,
        severity: Severity::High,
        title: "n8n MCP node with untrusted server",
        detect: |g| {
            if !is_n8n(g) { return Vec::new(); }
            let mut out = Vec::new();
            for t in &g.tools {
                let mcp_server = match &t.source { ToolSource::Mcp(s) => Some(s.clone()), _ => None };
                let s = node_surface(t);
                let is_mcp_node = mcp_server.is_some() || s.contains("mcp");
                if !is_mcp_node { continue; }
                let server = mcp_server.unwrap_or_else(|| "<declared in node>".into());
                let f = Finding::new(
                    "n8n-mcp-node-untrusted-server",
                    DetectorCategory::N8nWorkflowRisks,
                    Severity::High,
                    "n8n MCP node with untrusted server",
                    format!("n8n MCP node `{}` loads tools from MCP server `{}`; advertised tool descriptions are an untrusted supply-chain input fed to the model.", t.name, server),
                )
                .with_tool(t.id.clone())
                .with_evidence(format!("mcp-server={server}; {}", node_surface(t)))
                .with_location(loc(&t.location))
                .with_fix("Pin the MCP server to a signed release, review advertised tools, and restrict which servers the workflow may use.");
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::ToolMisuse)
                        .with_llm(OwaspLlm2025::SupplyChain)
                        .with_atlas("AML.T0010")
                }));
            }
            out
        }
    }
}
