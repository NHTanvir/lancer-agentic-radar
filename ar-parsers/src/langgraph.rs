//! LangGraph (Python) parser.
//!
//! Reconstructs the state machine from `StateGraph(...)`, `add_node`,
//! `add_edge`, and `add_conditional_edges`. Conditional edges carry the
//! predicate name as the edge label. `MessagesState` is mapped to a memory
//! store.

use crate::common::{
    extract_model, extract_system_prompt, ident_list, infer_effects, locate, mint_id, unquote,
};
use ar_core::{
    AgentGraph, AgentNode, Edge, EdgeKind, Framework, MemoryStore, ParseOptions, ToolNode,
    ToolSource,
};
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;

const FW: Framework = Framework::LangGraph;

/// Structural fingerprint for LangGraph Python source.
pub fn detect(path: &Path, content: &str) -> bool {
    if !matches!(path.extension().and_then(|e| e.to_str()), Some("py") | Some("pyi")) {
        return false;
    }
    let re = Regex::new(r"(?i)StateGraph|langgraph|add_conditional_edges|MessagesState").unwrap();
    re.is_match(content)
}

/// Parse LangGraph source into a partial [`AgentGraph`].
pub fn parse(content: &str, path: &Path, _opts: &ParseOptions) -> AgentGraph {
    let mut g = AgentGraph::new();

    // Memory: MessagesState / checkpointer.
    if content.contains("MessagesState") {
        let id = mint_id("memory", path, "MessagesState");
        let mut m = MemoryStore::new(id, "MessagesState", "MessagesState");
        m.location = locate(path, content, "MessagesState");
        g.add_memory(m);
    }
    if Regex::new(r"(?i)checkpointer|MemorySaver|SqliteSaver").unwrap().is_match(content) {
        let id = mint_id("memory", path, "checkpointer");
        let mut m = MemoryStore::new(id, "checkpointer", "Checkpointer");
        m.cross_session = true;
        m.location = locate(path, content, "checkpointer");
        g.add_memory(m);
    }

    // Nodes: add_node("name", fn) → each becomes an agent (graph node).
    let mut node_ids: HashMap<String, String> = HashMap::new();
    let add_node = Regex::new(r#"\.add_node\s*\(\s*(?:name\s*=\s*)?["']([^"']+)["']"#).unwrap();
    let add_node_ident = Regex::new(r#"\.add_node\s*\(\s*([A-Za-z_]\w*)\s*[,)]"#).unwrap();
    for c in add_node.captures_iter(content) {
        let name = c.get(1).unwrap().as_str();
        register_node(content, path, name, &mut node_ids, &mut g);
    }
    for c in add_node_ident.captures_iter(content) {
        let name = c.get(1).unwrap().as_str();
        register_node(content, path, name, &mut node_ids, &mut g);
    }

    // Tools bound via ToolNode / bind_tools / tools=[...]
    let mut tool_ids: HashMap<String, String> = HashMap::new();
    parse_tools(content, path, &mut tool_ids, &mut g);

    // Edges: add_edge("a", "b")
    let add_edge = Regex::new(r#"\.add_edge\s*\(\s*["']([^"']+)["']\s*,\s*["']([^"']+)["']"#).unwrap();
    for c in add_edge.captures_iter(content) {
        let from = c.get(1).unwrap().as_str();
        let to = c.get(2).unwrap().as_str();
        let fid = ensure_node(content, path, from, &mut node_ids, &mut g);
        let tid = ensure_node(content, path, to, &mut node_ids, &mut g);
        g.add_edge(Edge::new(fid, tid, EdgeKind::Handoff));
    }

    // Conditional edges: add_conditional_edges("src", router, {...})
    let cond = Regex::new(
        r#"\.add_conditional_edges\s*\(\s*["']([^"']+)["']\s*,\s*([A-Za-z_]\w*)"#,
    )
    .unwrap();
    for c in cond.captures_iter(content) {
        let from = c.get(1).unwrap().as_str();
        let predicate = c.get(2).unwrap().as_str();
        let fid = ensure_node(content, path, from, &mut node_ids, &mut g);
        // Resolve the mapping dict for destinations.
        let m0 = c.get(0).unwrap();
        let map = balanced_brace(&content[m0.start()..]);
        let dests = conditional_dests(&map.unwrap_or_default());
        if dests.is_empty() {
            // Unknown destination → audit node.
            let uid = mint_id("unknown", path, &format!("{from}_branch"));
            g.add_unknown(uid.clone(), format!("conditional branch from `{from}`"));
            g.add_edge(
                Edge::new(fid, uid, EdgeKind::Handoff).with_label(predicate),
            );
        } else {
            for d in dests {
                let tid = ensure_node(content, path, &d, &mut node_ids, &mut g);
                g.add_edge(
                    Edge::new(fid.clone(), tid, EdgeKind::Handoff).with_label(predicate),
                );
            }
        }
    }

    // Connect each graph node to all bound tools (conservative).
    let aids: Vec<String> = g.agents.iter().map(|a| a.id.as_str().to_string()).collect();
    let tids: Vec<String> = tool_ids.values().cloned().collect();
    for aid in &aids {
        for tid in &tids {
            g.add_edge(Edge::new(aid.clone(), tid.clone(), EdgeKind::Calls));
        }
    }

    g
}

fn register_node(
    content: &str,
    path: &Path,
    name: &str,
    node_ids: &mut HashMap<String, String>,
    g: &mut AgentGraph,
) {
    if name == "START" || name == "END" || node_ids.contains_key(name) {
        return;
    }
    let id = mint_id("agent", path, name);
    let mut a = AgentNode::new(id.clone(), name, FW);
    a.model = extract_model(content);
    if let Some(sp) = extract_system_prompt(content) {
        a.set_system_prompt(sp);
    }
    a.location = locate(path, content, name);
    node_ids.insert(name.to_string(), id.clone());
    g.add_agent(a);
}

fn ensure_node(
    content: &str,
    path: &Path,
    name: &str,
    node_ids: &mut HashMap<String, String>,
    g: &mut AgentGraph,
) -> String {
    if name == "START" || name == "END" {
        let id = mint_id("agent", path, name);
        if !node_ids.contains_key(name) {
            let mut a = AgentNode::new(id.clone(), name, FW);
            a.accepts_user_input = name == "START";
            a.location = locate(path, content, name);
            node_ids.insert(name.to_string(), id.clone());
            g.add_agent(a);
        }
        return node_ids[name].clone();
    }
    if let Some(id) = node_ids.get(name) {
        return id.clone();
    }
    register_node(content, path, name, node_ids, g);
    node_ids[name].clone()
}

fn parse_tools(
    content: &str,
    path: &Path,
    tool_ids: &mut HashMap<String, String>,
    g: &mut AgentGraph,
) {
    // @tool decorated funcs
    let tool_dec = Regex::new(
        r#"(?m)^\s*@tool(?:\([^)]*\))?\s*\n\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)"#,
    )
    .unwrap();
    for c in tool_dec.captures_iter(content) {
        let fname = c.get(1).unwrap().as_str();
        let sig = c.get(2).map(|m| m.as_str()).unwrap_or("");
        let id = mint_id("tool", path, fname);
        let mut t = ToolNode::new(id.clone(), fname);
        t.source = ToolSource::Native;
        let (e, r) = infer_effects(content);
        t.effects = e;
        t.effects_resolved = r;
        t.signature = Some(sig.trim().to_string());
        t.location = locate(path, content, fname);
        tool_ids.insert(fname.to_string(), id);
        g.add_tool(t);
    }
    // bind_tools([...]) / ToolNode([...])
    let binds = Regex::new(r"(?i)(?:bind_tools|ToolNode)\s*\(").unwrap();
    for m in binds.find_iter(content) {
        // `m.end()` points just past the `(`; back up one to the open paren.
        let args = crate::common::balanced(content, m.end() - 1, '(', ')').unwrap_or_default();
        for n in ident_list(&args) {
            let name = unquote(&n);
            if tool_ids.contains_key(&name) {
                continue;
            }
            let id = mint_id("tool", path, &name);
            let mut t = ToolNode::new(id.clone(), name.clone());
            t.source = ToolSource::Native;
            t.location = locate(path, content, m.as_str());
            tool_ids.insert(name, id);
            g.add_tool(t);
        }
    }
}

/// Destinations from a conditional-edge mapping dict `{ "a": "node_a", ... }`
/// or a `["node_a", "node_b"]` list.
fn conditional_dests(map: &str) -> Vec<String> {
    let mut out = Vec::new();
    // dict values
    let val = Regex::new(r#":\s*["']([^"']+)["']"#).unwrap();
    for c in val.captures_iter(map) {
        out.push(c.get(1).unwrap().as_str().to_string());
    }
    if out.is_empty() {
        let bare = Regex::new(r#"["']([^"']+)["']"#).unwrap();
        for c in bare.captures_iter(map) {
            out.push(c.get(1).unwrap().as_str().to_string());
        }
    }
    out.retain(|d| d != "START" && d != "END");
    out
}

/// Locate the first `{...}` block in `s` (balanced).
fn balanced_brace(s: &str) -> Option<String> {
    let open = s.find('{')?;
    crate::common::balanced(s, open, '{', '}')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_state_machine() {
        let src = r#"
from langgraph.graph import StateGraph, MessagesState
g = StateGraph(MessagesState)
g.add_node("agent", call_model)
g.add_node("tools", tool_node)
g.add_edge("agent", "tools")
g.add_conditional_edges("agent", should_continue, {"continue": "tools", "end": "END"})
"#;
        let g = parse(src, Path::new("g.py"), &ParseOptions::default());
        assert!(g.agents.iter().any(|a| a.name == "agent"));
        assert!(g.edges.iter().any(|e| e.label.as_deref() == Some("should_continue")));
        assert!(g.memory.iter().any(|m| m.kind == "MessagesState"));
    }
}
