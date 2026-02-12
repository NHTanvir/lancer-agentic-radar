//! Semantic Kernel parser — C# `[KernelFunction]` attributes or Python
//! `kernel.add_plugin(...)` calls, plus planner configuration.

use crate::common::{infer_effects, locate, mint_id};
use ar_core::{
    AgentGraph, AgentNode, Edge, EdgeKind, Framework, ParseOptions, SourceLocation, ToolNode,
    ToolSource,
};
use regex::Regex;
use std::path::Path;

const FW: Framework = Framework::SemanticKernel;

/// Detect Semantic Kernel C# or Python source.
pub fn detect(path: &Path, content: &str) -> bool {
    match path.extension().and_then(|e| e.to_str()) {
        Some("cs") => Regex::new(r"(?i)KernelFunction|Microsoft\.SemanticKernel|using\s+Microsoft\.SemanticKernel")
            .unwrap()
            .is_match(content),
        Some("py") | Some("pyi") => Regex::new(
            r"(?i)semantic_kernel|kernel\.add_plugin|@kernel_function|sk_function|Kernel\(\)",
        )
        .unwrap()
        .is_match(content),
        _ => false,
    }
}

/// Parse Semantic Kernel source into a partial [`AgentGraph`].
pub fn parse(content: &str, path: &Path, _opts: &ParseOptions) -> AgentGraph {
    let mut g = AgentGraph::new();

    // One synthetic kernel "agent" representing the SK runtime.
    let aid = mint_id("agent", path, "kernel");
    let mut agent = AgentNode::new(aid.clone(), "SemanticKernel", FW);
    agent.accepts_user_input = true;
    agent.location = SourceLocation::new(path);

    // Planner config makes the kernel autonomous over its functions.
    let has_planner = Regex::new(r"(?i)Planner|FunctionCallingStepwisePlanner|SequentialPlanner|HandlebarsPlanner|auto_invoke")
        .unwrap()
        .is_match(content);
    let _ = has_planner;

    // C# [KernelFunction] attributes.
    let cs_fn = Regex::new(
        r#"(?s)\[KernelFunction[^\]]*\][^\n]*\n(?:\s*\[[^\]]*\]\s*\n)*\s*(?:public|private|internal|protected)?\s*(?:async\s+)?[\w<>\[\],\s\.]+?\s+([A-Za-z_]\w*)\s*\("#,
    )
    .unwrap();
    for c in cs_fn.captures_iter(content) {
        let name = c.get(1).unwrap().as_str();
        add_tool(content, path, name, c.get(0).unwrap().as_str(), &aid, &mut g);
    }

    // Python @kernel_function / @sk_function
    let py_fn = Regex::new(
        r#"(?m)^\s*@(?:kernel_function|sk_function)(?:\([^)]*\))?\s*\n\s*(?:async\s+)?def\s+([A-Za-z_]\w*)"#,
    )
    .unwrap();
    for c in py_fn.captures_iter(content) {
        let name = c.get(1).unwrap().as_str();
        add_tool(content, path, name, c.get(0).unwrap().as_str(), &aid, &mut g);
    }

    // Python plugins: kernel.add_plugin(SomePlugin(), plugin_name="x")
    let plugin = Regex::new(r#"add_plugin\s*\(\s*([A-Za-z_]\w*)"#).unwrap();
    for c in plugin.captures_iter(content) {
        let name = c.get(1).unwrap().as_str();
        add_tool(content, path, name, c.get(0).unwrap().as_str(), &aid, &mut g);
    }

    if !g.tools.is_empty() || detect(path, content) {
        g.add_agent(agent);
    }
    g
}

fn add_tool(
    content: &str,
    path: &Path,
    name: &str,
    anchor: &str,
    agent_id: &str,
    g: &mut AgentGraph,
) {
    let id = mint_id("tool", path, name);
    if g.tools.iter().any(|t| t.id.as_str() == id) {
        return;
    }
    let mut t = ToolNode::new(id.clone(), name);
    t.source = ToolSource::Native;
    let (e, r) = infer_effects(content);
    t.effects = e;
    t.effects_resolved = r;
    t.location = locate(path, content, anchor);
    g.add_tool(t);
    g.add_edge(Edge::new(agent_id.to_string(), id, EdgeKind::Calls));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_csharp_kernel_function() {
        let src = r#"
using Microsoft.SemanticKernel;
public class Lights {
    [KernelFunction("get_lights")]
    public string GetLights() { return "on"; }
}
"#;
        assert!(detect(Path::new("L.cs"), src));
        let g = parse(src, Path::new("L.cs"), &ParseOptions::default());
        assert!(!g.tools.is_empty());
        assert!(!g.agents.is_empty());
    }

    #[test]
    fn parses_python_plugin() {
        let src = r#"
import semantic_kernel as sk
kernel = sk.Kernel()
kernel.add_plugin(MathPlugin(), plugin_name="math")
"#;
        let g = parse(src, Path::new("k.py"), &ParseOptions::default());
        assert!(g.tools.iter().any(|t| t.name == "MathPlugin"));
    }
}
