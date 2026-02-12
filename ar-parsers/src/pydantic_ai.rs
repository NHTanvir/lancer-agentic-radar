//! Pydantic AI (Python) parser.
//!
//! Recognizes `Agent(...)` constructors and `@agent.tool` / `@agent.tool_plain`
//! decorated functions.

use crate::common::{extract_model, infer_effects, locate, mint_id, slug, unquote};
use ar_core::{
    AgentGraph, AgentNode, Edge, EdgeKind, Framework, ParseOptions, ToolNode, ToolSource,
};
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;

const FW: Framework = Framework::PydanticAI;

/// Detect Pydantic AI Python source.
pub fn detect(path: &Path, content: &str) -> bool {
    if !matches!(path.extension().and_then(|e| e.to_str()), Some("py") | Some("pyi")) {
        return false;
    }
    Regex::new(r"(?i)from\s+pydantic_ai|import\s+pydantic_ai|@\w+\.tool(?:_plain)?\b|RunContext")
        .unwrap()
        .is_match(content)
}

/// Parse Pydantic AI source into a partial [`AgentGraph`].
pub fn parse(content: &str, path: &Path, _opts: &ParseOptions) -> AgentGraph {
    let mut g = AgentGraph::new();
    // agent variable -> id
    let mut agent_by_var: HashMap<String, String> = HashMap::new();

    // `var = Agent('openai:gpt-4o', system_prompt="...", tools=[...])`
    let ctor = Regex::new(r#"(?m)([A-Za-z_]\w*)\s*=\s*Agent\s*\("#).unwrap();
    for c in ctor.captures_iter(content) {
        let var = c.get(1).unwrap().as_str();
        let start = c.get(0).unwrap().end() - 1;
        let args = crate::common::balanced(content, start, '(', ')').unwrap_or_default();
        let name = var.to_string();
        let id = mint_id("agent", path, &slug(&name));
        let mut a = AgentNode::new(id.clone(), name, FW);
        if let Some(sp) = crate::common::extract_system_prompt(&args) {
            a.set_system_prompt(sp);
        }
        // First positional string is often the model: Agent('openai:gpt-4o')
        a.model = extract_model(&args).or_else(|| first_positional_model(&args));
        a.accepts_user_input = true;
        a.location = locate(path, content, c.get(0).unwrap().as_str());
        agent_by_var.insert(var.to_string(), id.clone());
        g.add_agent(a);

        // tools=[...] passed inline
        if let Some(list) = bracket_after(&args, "tools") {
            for n in crate::common::ident_list(&list) {
                let tn = unquote(&n);
                let tid = mint_id("tool", path, &tn);
                let mut t = ToolNode::new(tid.clone(), tn);
                t.source = ToolSource::Native;
                let (e, r) = infer_effects(content);
                t.effects = e;
                t.effects_resolved = r;
                t.location = locate(path, content, c.get(0).unwrap().as_str());
                g.add_tool(t);
                g.add_edge(Edge::new(id.clone(), tid, EdgeKind::Calls));
            }
        }
    }

    // `@agent.tool` / `@agent.tool_plain` decorated functions.
    let tool_dec = Regex::new(
        r#"(?m)^\s*@([A-Za-z_]\w*)\.tool(?:_plain)?(?:\([^)]*\))?\s*\n\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)"#,
    )
    .unwrap();
    for c in tool_dec.captures_iter(content) {
        let agent_var = c.get(1).unwrap().as_str();
        let fname = c.get(2).unwrap().as_str();
        let sig = c.get(3).map(|m| m.as_str()).unwrap_or("");
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
        g.add_tool(t);
        // attach to the named agent if known, else all agents
        if let Some(aid) = agent_by_var.get(agent_var) {
            g.add_edge(Edge::new(aid.clone(), tid, EdgeKind::Calls));
        } else {
            for aid in agent_by_var.values() {
                g.add_edge(Edge::new(aid.clone(), tid.clone(), EdgeKind::Calls));
            }
        }
    }

    g
}

/// A leading positional string literal that looks like a model id
/// (`openai:gpt-4o`, `anthropic:claude-...`, `gpt-4o`).
fn first_positional_model(args: &str) -> Option<String> {
    let lit = crate::common::first_string_literal(args, 0)?;
    let l = lit.trim();
    if l.contains(':') || l.starts_with("gpt") || l.starts_with("claude") || l.starts_with("gemini") {
        Some(l.to_string())
    } else {
        None
    }
}

fn bracket_after(args: &str, key: &str) -> Option<String> {
    let re = Regex::new(&format!(r"(?i)\b{}\s*=\s*\[", regex::escape(key))).unwrap();
    let m = re.find(args)?;
    let rest = &args[m.end()..];
    rest.find(']').map(|e| rest[..e].to_string())
}

/// Capture a Python def body from `start` to the next column-0 statement.
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
    fn parses_agent_and_tool() {
        let src = r#"
from pydantic_ai import Agent
agent = Agent('openai:gpt-4o', system_prompt="Be concise.")

@agent.tool
async def fetch(ctx, url: str) -> str:
    import httpx
    return httpx.get(url).text
"#;
        assert!(detect(Path::new("p.py"), src));
        let g = parse(src, Path::new("p.py"), &ParseOptions::default());
        assert!(g.agents.iter().any(|a| a.model.as_deref() == Some("openai:gpt-4o")));
        assert!(g.tools.iter().any(|t| t.name == "fetch" && t.effects.net_egress));
        assert!(g.edges.iter().any(|e| e.kind == EdgeKind::Calls));
    }
}
