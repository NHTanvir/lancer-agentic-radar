//! Tool-poisoning sub-checks (plan §"Detector catalog" item 2).
//!
//! Tool descriptions are read by the LLM and can carry hidden instructions
//! (the canonical MCP supply-chain risk). These checks look at where tool
//! definitions come from, whether their descriptions / schemas are permissive,
//! whether tools can be registered at runtime, whether MCP servers are signed,
//! and whether two tools collide on a name.

use crate::detector::helpers::*;
use crate::define_detectors;
use ar_core::{DetectorCategory, Finding, OwaspAgentic2026, OwaspLlm2025, Severity, ToolSource};

/// Suspicious phrases hidden inside a tool description that try to steer the model.
const INJECTION_PHRASES: &[&str] = &[
    "ignore previous",
    "ignore all previous",
    "disregard",
    "you must",
    "always call",
    "do not tell",
    "before using any other",
    "system:",
    "<important>",
    "instructions:",
    "as an ai",
    "reveal",
    "exfiltrate",
    "send to",
    "secretly",
];

define_detectors! {
    /// A tool is advertised by an MCP server whose trust is not established.
    TpMcpUntrustedServer {
        id: "tp-mcp-untrusted-server",
        category: DetectorCategory::ToolPoisoning,
        severity: Severity::High,
        title: "Tool sourced from an untrusted MCP server",
        detect: |g| {
            let mut out = Vec::new();
            for t in &g.tools {
                if let ToolSource::Mcp(server) = &t.source {
                    let lc_s = server.to_ascii_lowercase();
                    let local = lc_s.starts_with("stdio")
                        || lc_s.contains("localhost")
                        || lc_s.contains("127.0.0.1")
                        || lc_s.starts_with("file://");
                    let f = Finding::new(
                        "tp-mcp-untrusted-server",
                        DetectorCategory::ToolPoisoning,
                        if local { Severity::Medium } else { Severity::High },
                        "Tool sourced from an untrusted MCP server",
                        format!(
                            "Tool `{}` is advertised by MCP server `{}`. MCP tool definitions \
                             (name, description, schema) are attacker-influenceable supply-chain \
                             inputs and are fed straight to the model.",
                            t.name, server
                        ),
                    )
                    .with_tool(t.id.clone())
                    .with_evidence(format!("mcp-server={server}; {}", tool_evidence(t)))
                    .with_location(loc(&t.location))
                    .with_fix(
                        "Pin the MCP server to a known, signed release; review its advertised tool \
                         descriptions for embedded instructions; restrict which servers an agent may \
                         load tools from.",
                    );
                    out.push(tagged(f, |c| {
                        c.with_agentic(OwaspAgentic2026::ToolMisuse)
                            .with_llm(OwaspLlm2025::SupplyChain)
                            .with_atlas("AML.T0010")
                            .with_aicm("AICM-AIS-05")
                    }));
                }
            }
            out
        }
    }

    /// A tool description appears to come from an untrusted source and/or carries
    /// embedded instruction-like text.
    TpToolDescriptionFromUntrustedSource {
        id: "tp-tool-description-from-untrusted-source",
        category: DetectorCategory::ToolPoisoning,
        severity: Severity::High,
        title: "Tool description carries embedded instructions",
        detect: |g| {
            let mut out = Vec::new();
            for t in &g.tools {
                let desc = match &t.description { Some(d) if !d.is_empty() => d, _ => continue };
                let untrusted_src = matches!(t.source, ToolSource::Mcp(_) | ToolSource::Imported(_) | ToolSource::Unknown);
                let injects = contains_any(desc, INJECTION_PHRASES);
                // Unicode tag-character payloads / zero-width chars hidden in text.
                let hidden = desc.chars().any(|c| {
                    let u = c as u32;
                    (0xE0000..=0xE007F).contains(&u) // unicode tag chars
                        || u == 0x200B || u == 0x200C || u == 0x200D || u == 0xFEFF
                });
                if injects || hidden || (untrusted_src && desc.len() > 240) {
                    let why = if hidden {
                        "contains hidden/zero-width Unicode characters"
                    } else if injects {
                        "contains instruction-like phrasing"
                    } else {
                        "is unusually long and comes from an untrusted source"
                    };
                    let f = Finding::new(
                        "tp-tool-description-from-untrusted-source",
                        DetectorCategory::ToolPoisoning,
                        if hidden || injects { Severity::High } else { Severity::Medium },
                        "Tool description carries embedded instructions",
                        format!(
                            "Tool `{}` description {}. The model reads tool descriptions as trusted \
                             context, so a poisoned description can hijack tool selection.",
                            t.name, why
                        ),
                    )
                    .with_tool(t.id.clone())
                    .with_evidence(tool_evidence(t))
                    .with_location(loc(&t.location))
                    .with_fix(
                        "Sanitize/normalize tool descriptions before exposing them to the model; \
                         strip control / tag characters; review descriptions from third-party or \
                         MCP sources.",
                    );
                    out.push(tagged(f, |c| {
                        c.with_agentic(OwaspAgentic2026::ToolMisuse)
                            .with_llm(OwaspLlm2025::SupplyChain)
                            .with_llm(OwaspLlm2025::PromptInjection)
                            .with_atlas("AML.T0051")
                    }));
                }
            }
            out
        }
    }

    /// A privileged tool declares no / a too-permissive argument schema.
    TpParameterSchemaPermissive {
        id: "tp-parameter-schema-permissive",
        category: DetectorCategory::ToolPoisoning,
        severity: Severity::Medium,
        title: "Tool parameter schema is missing or overly permissive",
        detect: |g| {
            let mut out = Vec::new();
            for t in &g.tools {
                if !t.effects.is_privileged() { continue; }
                let permissive_sig = t.signature.as_deref().map(|s| {
                    let s = s.to_ascii_lowercase();
                    s.contains("**kwargs") || s.contains("any") || s.contains("dict") || s.contains("object")
                }).unwrap_or(true);
                if !t.has_input_schema || permissive_sig {
                    let f = Finding::new(
                        "tp-parameter-schema-permissive",
                        DetectorCategory::ToolPoisoning,
                        Severity::Medium,
                        "Tool parameter schema is missing or overly permissive",
                        format!(
                            "Privileged tool `{}` accepts free-form / unconstrained arguments \
                             (schema present: {}). Permissive schemas let the model (or an injected \
                             instruction) pass arbitrary parameters into a dangerous operation.",
                            t.name, t.has_input_schema
                        ),
                    )
                    .with_tool(t.id.clone())
                    .with_evidence(format!(
                        "effects=[{}] signature={}",
                        t.effects.badges().join(","),
                        t.signature.as_deref().unwrap_or("<none>")
                    ))
                    .with_location(loc(&t.location))
                    .with_fix(
                        "Declare a strict typed schema (Pydantic / JSON Schema) with enums, ranges \
                         and allowlists for every argument of a privileged tool.",
                    );
                    out.push(tagged(f, |c| {
                        c.with_agentic(OwaspAgentic2026::ToolMisuse)
                            .with_llm(OwaspLlm2025::ExcessiveAgency)
                    }));
                }
            }
            out
        }
    }

    /// Tools can be registered at runtime (unresolved / dynamic tool nodes).
    TpRuntimeToolRegistration {
        id: "tp-runtime-tool-registration",
        category: DetectorCategory::ToolPoisoning,
        severity: Severity::Medium,
        title: "Tools registered dynamically at runtime",
        detect: |g| {
            let mut out = Vec::new();
            // Unresolved nodes the parser flagged as dynamic tool registration.
            for (id, label) in &g.unknowns {
                let l = label.to_ascii_lowercase();
                if l.contains("tool") && (l.contains("append") || l.contains("register") || l.contains("runtime") || l.contains("dynamic")) {
                    let f = Finding::new(
                        "tp-runtime-tool-registration",
                        DetectorCategory::ToolPoisoning,
                        Severity::Medium,
                        "Tools registered dynamically at runtime",
                        format!(
                            "A tool appears to be added at runtime ({label}). Tools added after \
                             static review escape the scanner and any allowlist, expanding the \
                             agent's authority unpredictably.",
                        ),
                    )
                    .with_evidence(format!("unresolved node `{id}`: {label}"))
                    .with_fix(
                        "Register all tools statically and review them; if runtime registration is \
                         required, gate it behind an allowlist and re-scan the resulting tool set.",
                    );
                    out.push(tagged(f, |c| {
                        c.with_agentic(OwaspAgentic2026::ToolMisuse)
                            .with_llm(OwaspLlm2025::SupplyChain)
                    }));
                }
            }
            out
        }
    }

    /// An MCP-sourced tool with no evidence of server signature verification.
    TpMcpServerNoSignatureCheck {
        id: "tp-mcp-server-no-signature-check",
        category: DetectorCategory::ToolPoisoning,
        severity: Severity::Medium,
        title: "MCP server loaded without signature verification",
        detect: |g| {
            use std::collections::BTreeSet;
            let mut servers: BTreeSet<String> = BTreeSet::new();
            for t in &g.tools {
                if let ToolSource::Mcp(s) = &t.source {
                    servers.insert(s.clone());
                }
            }
            servers.into_iter().map(|server| {
                let f = Finding::new(
                    "tp-mcp-server-no-signature-check",
                    DetectorCategory::ToolPoisoning,
                    Severity::Medium,
                    "MCP server loaded without signature verification",
                    format!(
                        "MCP server `{server}` is loaded with no statically-detectable integrity / \
                         signature verification. A compromised or swapped server can ship poisoned \
                         tool advertisements.",
                    ),
                )
                .with_evidence(format!("mcp-server={server}"))
                .with_fix(
                    "Pin MCP servers to a content hash or signed release and verify the signature \
                     before trusting advertised tools.",
                );
                tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::ToolMisuse)
                        .with_llm(OwaspLlm2025::SupplyChain)
                        .with_aicm("AICM-AIS-05")
                        .with_atlas("AML.T0010")
                })
            }).collect()
        }
    }

    /// Two distinct tools share a name (shadowing / name collision).
    TpToolNameCollision {
        id: "tp-tool-name-collision",
        category: DetectorCategory::ToolPoisoning,
        severity: Severity::Medium,
        title: "Two tools share the same name",
        detect: |g| {
            use std::collections::HashMap;
            let mut by_name: HashMap<String, Vec<&ar_core::ToolNode>> = HashMap::new();
            for t in &g.tools {
                by_name.entry(t.name.to_ascii_lowercase()).or_default().push(t);
            }
            let mut out = Vec::new();
            for (name, tools) in by_name {
                if tools.len() < 2 { continue; }
                // Distinct ids => genuine collision, not a dedup artifact.
                let distinct = tools.iter().map(|t| &t.id).collect::<std::collections::HashSet<_>>().len();
                if distinct < 2 { continue; }
                let f = Finding::new(
                    "tp-tool-name-collision",
                    DetectorCategory::ToolPoisoning,
                    Severity::Medium,
                    "Two tools share the same name",
                    format!(
                        "{} distinct tools are named `{}`. A malicious tool can shadow a trusted one \
                         so the model calls the attacker's implementation.",
                        distinct, name
                    ),
                )
                .with_tool(tools[0].id.clone())
                .with_evidence(format!(
                    "ids: {}",
                    tools.iter().map(|t| t.id.as_str()).collect::<Vec<_>>().join(", ")
                ))
                .with_location(loc(&tools[0].location))
                .with_fix(
                    "Namespace tools by source/server and reject duplicate tool names; prefer the \
                     vetted definition explicitly.",
                );
                out.push(tagged(f, |c| {
                    c.with_agentic(OwaspAgentic2026::ToolMisuse)
                        .with_llm(OwaspLlm2025::SupplyChain)
                }));
            }
            out
        }
    }
}
