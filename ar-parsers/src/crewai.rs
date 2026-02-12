//! CrewAI parser — dual mode.
//!
//! * **Python**: `Agent(...)`, `Task(...)`, `Crew(...)` constructors.
//! * **YAML**: `agents.yaml` / `tasks.yaml` config (detected structurally via
//!   [`serde_yaml::Value`], not by filename, since users rename).
//!
//! `mem0` memory is mapped to a memory store; tools listed on each agent become
//! `Calls` edges.

use crate::common::{
    call_args, extract_model, infer_effects, kwarg_string, locate, mint_id, slug, unquote,
};
use ar_core::{
    AgentGraph, AgentNode, Edge, EdgeKind, Framework, MemoryStore, ParseOptions, ToolNode,
    ToolSource,
};
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;

const FW: Framework = Framework::CrewAI;

/// Detect CrewAI Python source or a CrewAI-shaped YAML config.
pub fn detect(path: &Path, content: &str) -> bool {
    match path.extension().and_then(|e| e.to_str()) {
        Some("py") | Some("pyi") => {
            Regex::new(r"(?i)from\s+crewai|import\s+crewai|\bCrew\s*\(|\bAgent\s*\(\s*role")
                .unwrap()
                .is_match(content)
        }
        Some("yaml") | Some("yml") => yaml_is_crewai(content),
        _ => false,
    }
}

/// Structural YAML fingerprint: a mapping whose entries look like CrewAI agents
/// (have `role`/`goal`/`backstory`) or tasks (`description`/`expected_output`).
fn yaml_is_crewai(content: &str) -> bool {
    let val: serde_yaml::Value = match serde_yaml::from_str(content) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if let serde_yaml::Value::Mapping(map) = val {
        for (_k, v) in &map {
            if let serde_yaml::Value::Mapping(inner) = v {
                let has = |key: &str| inner.contains_key(key);
                if (has("role") && has("goal")) || (has("description") && has("expected_output")) {
                    return true;
                }
            }
        }
    }
    false
}

/// Parse CrewAI source/config into a partial [`AgentGraph`].
pub fn parse(content: &str, path: &Path, opts: &ParseOptions) -> AgentGraph {
    let is_yaml = matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("yaml") | Some("yml")
    );
    if is_yaml || (serde_yaml::from_str::<serde_yaml::Value>(content).is_ok() && yaml_is_crewai(content)) {
        if let Some(g) = parse_yaml(content, path) {
            return g;
        }
    }
    parse_python(content, path, opts)
}

// ---------------------------------------------------------------------------
// YAML mode
// ---------------------------------------------------------------------------

fn parse_yaml(content: &str, path: &Path) -> Option<AgentGraph> {
    let val: serde_yaml::Value = serde_yaml::from_str(content).ok()?;
    let map = match val {
        serde_yaml::Value::Mapping(m) => m,
        _ => return None,
    };
    let mut g = AgentGraph::new();
    let mut tool_ids: HashMap<String, String> = HashMap::new();

    for (k, v) in &map {
        let key = k.as_str().unwrap_or("entry").to_string();
        let inner = match v {
            serde_yaml::Value::Mapping(m) => m,
            _ => continue,
        };
        let get = |field: &str| {
            inner
                .get(field)
                .and_then(|x| x.as_str())
                .map(|s| s.to_string())
        };
        let is_agent = inner.contains_key("role") || inner.contains_key("goal");
        if is_agent {
            let id = mint_id("agent", path, &key);
            let mut a = AgentNode::new(id.clone(), key.clone(), FW);
            let prompt = [get("role"), get("goal"), get("backstory")]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join("\n");
            if !prompt.trim().is_empty() {
                a.set_system_prompt(prompt);
            }
            a.model = get("llm").or_else(|| get("model"));
            a.accepts_user_input = true;
            a.location = ar_core::SourceLocation::new(path);
            // tools list on the agent
            if let Some(serde_yaml::Value::Sequence(seq)) = inner.get("tools") {
                for tv in seq {
                    if let Some(tn) = tv.as_str() {
                        let tid = tool_ids
                            .entry(tn.to_string())
                            .or_insert_with(|| {
                                let tid = mint_id("tool", path, tn);
                                let mut t = ToolNode::new(tid.clone(), tn);
                                t.source = ToolSource::Native;
                                t.location = ar_core::SourceLocation::new(path);
                                g.add_tool(t);
                                tid
                            })
                            .clone();
                        g.add_edge(Edge::new(id.clone(), tid, EdgeKind::Calls));
                    }
                }
            }
            g.add_agent(a);
        }
    }
    if g.is_empty() {
        return None;
    }
    Some(g)
}

// ---------------------------------------------------------------------------
// Python mode
// ---------------------------------------------------------------------------

fn parse_python(content: &str, path: &Path, opts: &ParseOptions) -> AgentGraph {
    let mut g = AgentGraph::new();
    let mut tool_ids: HashMap<String, String> = HashMap::new();

    // mem0 / memory=True
    if Regex::new(r"(?i)\bmem0\b|memory\s*=\s*True|crewai\.memory").unwrap().is_match(content) {
        let id = mint_id("memory", path, "mem0");
        let mut m = MemoryStore::new(id, "mem0", "mem0");
        m.cross_session = true;
        m.location = locate(path, content, "memory");
        g.add_memory(m);
    }

    // RAG via crewai_tools retrievers
    for kind in ["RagTool", "Chroma", "PDFSearchTool", "WebsiteSearchTool", "Qdrant"] {
        if content.contains(kind) {
            let r = crate::common::make_rag(opts, path, content, kind, kind, kind);
            g.add_rag(r);
        }
    }

    // @tool decorated funcs (crewai_tools.tool)
    let tool_dec = Regex::new(
        r#"(?m)^\s*@tool(?:\(\s*["']([^"']*)["']\s*\)|\([^)]*\))?\s*\n\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)"#,
    )
    .unwrap();
    for c in tool_dec.captures_iter(content) {
        let name = c
            .get(1)
            .map(|m| m.as_str().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| c.get(2).unwrap().as_str().to_string());
        let sig = c.get(3).map(|m| m.as_str()).unwrap_or("");
        let id = mint_id("tool", path, &name);
        let mut t = ToolNode::new(id.clone(), name.clone());
        t.source = ToolSource::Native;
        let (e, r) = infer_effects(content);
        t.effects = e;
        t.effects_resolved = r;
        t.signature = Some(sig.trim().to_string());
        t.location = locate(path, content, c.get(0).unwrap().as_str());
        // record under both the func name and the decorator name
        let func_name = c.get(2).unwrap().as_str().to_string();
        tool_ids.insert(func_name, id.clone());
        tool_ids.insert(name, id);
        g.add_tool(t);
    }

    // Agent(role=..., goal=..., tools=[...])
    let agent_re = Regex::new(r"\bAgent\s*\(").unwrap();
    let mut idx = 0usize;
    for m in agent_re.find_iter(content) {
        let args = call_args(&content[m.start()..], "Agent").unwrap_or_default();
        let role = kwarg_string(&args, "role").map(|s| unquote(&s));
        let name = role
            .clone()
            .map(|r| slug(&r))
            .filter(|s| s != "anon")
            .unwrap_or_else(|| format!("crewai_agent_{idx}"));
        idx += 1;
        let id = mint_id("agent", path, &name);
        let mut a = AgentNode::new(id.clone(), name, FW);
        let prompt = [
            kwarg_string(&args, "role"),
            kwarg_string(&args, "goal"),
            kwarg_string(&args, "backstory"),
        ]
        .into_iter()
        .flatten()
        .map(|s| unquote(&s))
        .collect::<Vec<_>>()
        .join("\n");
        if !prompt.trim().is_empty() {
            a.set_system_prompt(prompt);
        }
        a.model = extract_model(&args).or_else(|| extract_model(content));
        a.accepts_user_input = true;
        a.location = locate(path, content, m.as_str());

        // tools=[...] on the agent
        if let Some(list) = bracket_after(&args, "tools") {
            for n in crate::common::ident_list(&list) {
                let name = unquote(&n);
                let tid = tool_ids
                    .entry(name.clone())
                    .or_insert_with(|| {
                        let tid = mint_id("tool", path, &name);
                        let mut t = ToolNode::new(tid.clone(), name.clone());
                        t.source = ToolSource::Native;
                        t.location = locate(path, content, m.as_str());
                        g.add_tool(t);
                        tid
                    })
                    .clone();
                g.add_edge(Edge::new(id.clone(), tid, EdgeKind::Calls));
            }
        }
        // memory edges
        for mem in &g.memory.clone() {
            g.add_edge(Edge::new(id.clone(), mem.id.clone(), EdgeKind::Writes));
        }
        for r in &g.rag.clone() {
            g.add_edge(Edge::new(id.clone(), r.id.clone(), EdgeKind::Reads));
        }
        g.add_agent(a);
    }

    g
}

fn bracket_after(args: &str, key: &str) -> Option<String> {
    let re = Regex::new(&format!(r"(?i)\b{}\s*=\s*\[", regex::escape(key))).unwrap();
    let m = re.find(args)?;
    let rest = &args[m.end()..];
    rest.find(']').map(|e| rest[..e].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_python_crew() {
        let src = r#"
from crewai import Agent, Crew
researcher = Agent(role="Researcher", goal="find facts", backstory="expert", tools=[search_tool], memory=True)
"#;
        let g = parse(src, Path::new("crew.py"), &ParseOptions::default());
        assert!(g.agents.iter().any(|a| a.system_prompt.is_some()));
        assert!(!g.memory.is_empty());
    }

    #[test]
    fn parses_yaml_agents() {
        let src = r#"
researcher:
  role: Senior Researcher
  goal: Uncover developments
  backstory: A seasoned researcher.
  tools:
    - search_tool
writer:
  role: Writer
  goal: Write content
  backstory: Crafts narratives.
"#;
        assert!(detect(Path::new("agents.yaml"), src));
        let g = parse(src, Path::new("agents.yaml"), &ParseOptions::default());
        assert_eq!(g.agents.len(), 2);
        assert!(g.edges.iter().any(|e| e.kind == EdgeKind::Calls));
    }
}
