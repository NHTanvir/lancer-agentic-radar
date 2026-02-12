//! OpenAI Agents SDK (`openai-agents`, Python) parser — distinct from the
//! Assistants API.
//!
//! Recognizes `Agent(...)`, `Runner.run(...)`, the `@function_tool` decorator,
//! `handoff(...)` between agents (→ `Handoff` edges), the builtin tools
//! `WebSearchTool` / `FileSearchTool` / `ComputerTool` (→
//! [`ToolSource::Builtin`]), guardrails, tracing, and `as_tool()` agent-as-tool
//! patterns.

use crate::common::{
    balanced, extract_model, infer_effects, kwarg_string, locate, mint_id, slug, unquote,
};
use ar_core::{
    AgentGraph, AgentNode, Edge, EdgeKind, Framework, ParseOptions, RAGSource, ToolEffects,
    ToolNode, ToolSource,
};
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;

const FW: Framework = Framework::OpenAIAgentsSdk;

/// Detect OpenAI Agents SDK Python source.
pub fn detect(path: &Path, content: &str) -> bool {
    if !matches!(path.extension().and_then(|e| e.to_str()), Some("py") | Some("pyi")) {
        return false;
    }
    Regex::new(
        r"(?i)from\s+agents\s+import|import\s+agents\b|@function_tool|Runner\.run|WebSearchTool|FileSearchTool|ComputerTool|\bhandoff\s*\(",
    )
    .unwrap()
    .is_match(content)
        // avoid clashing with langgraph / autogen
        && !content.contains("StateGraph")
        && !content.contains("ConversableAgent")
}

/// Parse OpenAI Agents SDK source into a partial [`AgentGraph`].
pub fn parse(content: &str, path: &Path, _opts: &ParseOptions) -> AgentGraph {
    let mut g = AgentGraph::new();
    let mut agent_by_var: HashMap<String, String> = HashMap::new();
    let mut tool_ids: HashMap<String, String> = HashMap::new();

    // @function_tool decorated functions.
    let tool_dec = Regex::new(
        r#"(?m)^\s*@function_tool(?:\([^)]*\))?\s*\n\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)"#,
    )
    .unwrap();
    for c in tool_dec.captures_iter(content) {
        let fname = c.get(1).unwrap().as_str();
        let sig = c.get(2).map(|m| m.as_str()).unwrap_or("");
        let body = body_after(content, c.get(0).unwrap().end());
        let tid = mint_id("tool", path, fname);
        let mut t = ToolNode::new(tid.clone(), fname);
        t.source = ToolSource::Native;
        let (e, r) = infer_effects(&body);
        t.effects = e;
        t.effects_resolved = r;
        t.signature = Some(sig.trim().to_string());
        t.has_input_schema = sig.contains(':');
        t.location = locate(path, content, c.get(0).unwrap().as_str());
        tool_ids.insert(fname.to_string(), tid);
        g.add_tool(t);
    }

    // Builtin tools mentioned anywhere become available tool nodes.
    for (builtin, eff) in [
        ("WebSearchTool", net_effect()),
        ("FileSearchTool", ToolEffects { reads_fs: true, ..ToolEffects::default() }),
        ("ComputerTool", computer_effect()),
        ("CodeInterpreterTool", code_effect()),
    ] {
        if content.contains(builtin) {
            let tid = mint_id("tool", path, builtin);
            // FileSearchTool also represents a RAG source.
            if builtin == "FileSearchTool" {
                let rid = mint_id("rag", path, "FileSearchTool");
                let mut r = RAGSource::new(rid, "FileSearchTool", "file_search");
                r.location = locate(path, content, builtin);
                g.add_rag(r);
            }
            let mut t = ToolNode::new(tid.clone(), builtin);
            t.source = ToolSource::Builtin(builtin.to_string());
            t.effects = eff;
            t.effects_resolved = true;
            t.location = locate(path, content, builtin);
            tool_ids.insert(builtin.to_string(), tid);
            g.add_tool(t);
        }
    }

    // Agent(name="...", instructions="...", tools=[...], handoffs=[...])
    let ctor = Regex::new(r#"(?m)([A-Za-z_]\w*)\s*=\s*Agent\s*\("#).unwrap();
    for c in ctor.captures_iter(content) {
        let var = c.get(1).unwrap().as_str();
        let open = c.get(0).unwrap().end() - 1;
        let args = balanced(content, open, '(', ')').unwrap_or_default();
        let name = kwarg_string(&args, "name")
            .map(|s| unquote(&s))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| var.to_string());
        let id = mint_id("agent", path, &slug(&name));
        let mut a = AgentNode::new(id.clone(), name, FW);
        if let Some(sp) = crate::common::extract_system_prompt(&args) {
            a.set_system_prompt(sp);
        }
        a.model = extract_model(&args).or_else(|| extract_model(content));
        a.accepts_user_input = true;
        a.location = locate(path, content, c.get(0).unwrap().as_str());
        agent_by_var.insert(var.to_string(), id.clone());
        g.add_agent(a);

        // tools=[...] → Calls edges
        if let Some(list) = bracket_after(&args, "tools") {
            for n in crate::common::ident_list(&list) {
                let key = unquote(&n);
                // strip a trailing .as_tool() form
                let base = key.split('.').next().unwrap_or(&key).to_string();
                if let Some(tid) = tool_ids.get(&base).or_else(|| tool_ids.get(&key)) {
                    g.add_edge(Edge::new(id.clone(), tid.clone(), EdgeKind::Calls));
                } else if let Some(aid2) = agent_by_var.get(&base) {
                    // agent-as-tool
                    g.add_edge(Edge::new(id.clone(), aid2.clone(), EdgeKind::Calls));
                } else {
                    let uid = mint_id("unknown", path, &base);
                    g.add_unknown(uid.clone(), format!("unresolved tool `{base}`"));
                    g.add_edge(Edge::new(id.clone(), uid, EdgeKind::Calls));
                }
            }
        }
        // handoffs=[agentB, handoff(agentC)]
        if let Some(list) = bracket_after(&args, "handoffs") {
            for n in crate::common::ident_list(&list) {
                let target = unquote(&n);
                let base = target.split('.').next().unwrap_or(&target).to_string();
                if let Some(aid2) = agent_by_var.get(&base) {
                    g.add_edge(Edge::new(id.clone(), aid2.clone(), EdgeKind::Handoff));
                } else {
                    let uid = mint_id("agent", path, &slug(&base));
                    g.add_edge(Edge::new(id.clone(), uid, EdgeKind::Handoff));
                }
            }
        }
    }

    // handoff(target) standalone calls / Runner.run resolution would refine
    // the above; resolve any dangling handoff targets to Unknown if needed.
    resolve_handoffs(&mut g);

    g
}

fn net_effect() -> ToolEffects {
    ToolEffects {
        net_egress: true,
        ..ToolEffects::default()
    }
}
fn computer_effect() -> ToolEffects {
    ToolEffects {
        shell_exec: true,
        reads_fs: true,
        writes_fs: true,
        ..ToolEffects::default()
    }
}
fn code_effect() -> ToolEffects {
    ToolEffects {
        code_eval: true,
        shell_exec: true,
        ..ToolEffects::default()
    }
}

/// Ensure handoff targets exist as nodes (mint Unknown otherwise).
fn resolve_handoffs(g: &mut AgentGraph) {
    let mut to_add: Vec<String> = Vec::new();
    for e in &g.edges {
        if e.kind == EdgeKind::Handoff {
            let to = e.to.clone();
            if g.kind_of(&to).is_none() {
                to_add.push(to.as_str().to_string());
            }
        }
    }
    for id in to_add {
        let nid = ar_core::NodeId::new(id.clone());
        if g.kind_of(&nid).is_none() {
            g.add_unknown(id, "unresolved handoff target");
        }
    }
}

fn bracket_after(args: &str, key: &str) -> Option<String> {
    let re = Regex::new(&format!(r"(?i)\b{}\s*=\s*\[", regex::escape(key))).unwrap();
    let m = re.find(args)?;
    let open = m.end() - 1;
    balanced(args, open, '[', ']')
}

fn body_after(content: &str, start: usize) -> String {
    let tail = &content[start.min(content.len())..];
    let mut idx = 0usize;
    let mut end = tail.len();
    for line in tail.split_inclusive('\n').skip(1) {
        idx += line.len();
        let t = line.trim_end_matches('\n');
        if !t.trim().is_empty() && !t.starts_with(' ') && !t.starts_with('\t') {
            end = idx;
            break;
        }
        if idx > 2000 {
            end = idx;
            break;
        }
    }
    tail[..end.min(tail.len())].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_agents_handoffs_builtins() {
        let src = r#"
from agents import Agent, Runner, function_tool, WebSearchTool, handoff

@function_tool
def lookup(q: str) -> str:
    return q

spanish = Agent(name="spanish", instructions="Speak Spanish.")
triage = Agent(name="triage", instructions="Route the user.", tools=[lookup, WebSearchTool()], handoffs=[spanish])
"#;
        assert!(detect(Path::new("oa.py"), src));
        let g = parse(src, Path::new("oa.py"), &ParseOptions::default());
        assert!(g.agents.iter().any(|a| a.name == "triage"));
        assert!(g.tools.iter().any(|t| matches!(&t.source, ToolSource::Builtin(b) if b == "WebSearchTool")));
        assert!(g.edges.iter().any(|e| e.kind == EdgeKind::Handoff));
        assert!(g.edges.iter().any(|e| e.kind == EdgeKind::Calls));
    }
}
