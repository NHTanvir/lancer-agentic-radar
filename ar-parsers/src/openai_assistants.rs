//! OpenAI Assistants parser (JSON from the API or YAML config).
//!
//! Parses `tools: [{ type: "function" | "code_interpreter" | "file_search" }]`.
//! `file_search` is mapped to a RAG source; `code_interpreter` to a sandboxed
//! shell-capable tool; thread/run state to a memory store.

use crate::common::mint_id;
use ar_core::{
    AgentGraph, AgentNode, Edge, EdgeKind, Framework, MemoryStore, ParseOptions, SourceLocation,
    ToolEffects, ToolNode, ToolSource,
};
use serde_json::Value as Json;
use serde_yaml::Value as Yaml;
use std::path::Path;

const FW: Framework = Framework::OpenAIAssistants;

/// Detect an OpenAI Assistants definition (JSON or YAML, structural).
pub fn detect(path: &Path, content: &str) -> bool {
    match path.extension().and_then(|e| e.to_str()) {
        Some("json") => serde_json::from_str::<Json>(content)
            .map(|v| json_is_assistant(&v))
            .unwrap_or(false),
        Some("yaml") | Some("yml") => serde_yaml::from_str::<Yaml>(content)
            .map(|v| yaml_is_assistant(&v))
            .unwrap_or(false),
        _ => false,
    }
}

fn json_is_assistant(v: &Json) -> bool {
    let obj = match v.as_object() {
        Some(o) => o,
        None => {
            // array of assistants?
            return v.as_array().map(|a| a.iter().any(json_is_assistant)).unwrap_or(false);
        }
    };
    let is_assistant_obj = obj.get("object").and_then(|x| x.as_str()) == Some("assistant");
    let has_instructions = obj.contains_key("instructions");
    let has_tools = obj
        .get("tools")
        .and_then(|t| t.as_array())
        .map(|arr| arr.iter().any(|t| t.get("type").is_some()))
        .unwrap_or(false);
    is_assistant_obj || (has_instructions && has_tools)
}

fn yaml_is_assistant(v: &Yaml) -> bool {
    if let Yaml::Mapping(m) = v {
        let has = |k: &str| m.contains_key(k);
        return (has("instructions") || has("assistant")) && has("tools");
    }
    false
}

/// Parse an OpenAI Assistants definition into a partial [`AgentGraph`].
pub fn parse(content: &str, path: &Path, _opts: &ParseOptions) -> AgentGraph {
    // Try JSON first, then YAML; convert YAML→JSON Value for uniform handling.
    let json: Option<Json> = serde_json::from_str(content)
        .ok()
        .or_else(|| serde_yaml::from_str::<Yaml>(content).ok().and_then(yaml_to_json));
    let mut g = AgentGraph::new();
    let Some(json) = json else { return g };

    match &json {
        Json::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                parse_one(v, path, &mut g, i);
            }
        }
        _ => parse_one(&json, path, &mut g, 0),
    }
    g
}

fn parse_one(v: &Json, path: &Path, g: &mut AgentGraph, idx: usize) {
    let obj = match v.as_object() {
        Some(o) => o,
        None => return,
    };
    let name = obj
        .get("name")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("assistant_{idx}"));
    let id = mint_id("agent", path, &name);
    let mut a = AgentNode::new(id.clone(), name.clone(), FW);
    if let Some(instr) = obj.get("instructions").and_then(|x| x.as_str()) {
        if !instr.trim().is_empty() {
            a.set_system_prompt(instr);
        }
    }
    a.model = obj.get("model").and_then(|x| x.as_str()).map(|s| s.to_string());
    a.accepts_user_input = true;
    a.location = SourceLocation::new(path);
    g.add_agent(a);

    // thread/run state → memory
    if obj.contains_key("thread_id") || obj.contains_key("threads") || obj.contains_key("metadata") {
        let mid = mint_id("memory", path, &format!("{name}_thread"));
        let mut m = MemoryStore::new(mid.clone(), format!("{name} thread"), "thread");
        m.cross_session = true;
        m.location = SourceLocation::new(path);
        g.add_memory(m);
        g.add_edge(Edge::new(id.clone(), mid, EdgeKind::Writes));
    }

    // tools: [{type: function|code_interpreter|file_search}]
    if let Some(tools) = obj.get("tools").and_then(|t| t.as_array()) {
        for (ti, tv) in tools.iter().enumerate() {
            let ttype = tv.get("type").and_then(|x| x.as_str()).unwrap_or("function");
            match ttype {
                "file_search" | "retrieval" => {
                    let rid = mint_id("rag", path, &format!("{name}_file_search"));
                    let mut r = ar_core::RAGSource::new(rid.clone(), "file_search", "file_search");
                    r.has_source_attribution = false;
                    r.location = SourceLocation::new(path);
                    g.add_rag(r);
                    g.add_edge(Edge::new(id.clone(), rid, EdgeKind::Reads));
                }
                "code_interpreter" => {
                    let tid = mint_id("tool", path, &format!("{name}_code_interpreter"));
                    let mut t = ToolNode::new(tid.clone(), "code_interpreter");
                    t.source = ToolSource::Builtin("code_interpreter".into());
                    t.effects = ToolEffects {
                        code_eval: true,
                        shell_exec: true,
                        writes_fs: true,
                        reads_fs: true,
                        ..ToolEffects::default()
                    };
                    t.effects_resolved = true;
                    t.location = SourceLocation::new(path);
                    g.add_tool(t);
                    g.add_edge(Edge::new(id.clone(), tid, EdgeKind::Calls));
                }
                "function" => {
                    let func = tv.get("function").unwrap_or(tv);
                    let fname = func
                        .get("name")
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| format!("function_{ti}"));
                    let tid = mint_id("tool", path, &fname);
                    let mut t = ToolNode::new(tid.clone(), fname);
                    t.source = ToolSource::Native;
                    if let Some(d) = func.get("description").and_then(|x| x.as_str()) {
                        t.description = Some(d.to_string());
                    }
                    t.has_input_schema = func.get("parameters").is_some();
                    let (e, r) = crate::common::infer_effects(
                        &t.description.clone().unwrap_or_default(),
                    );
                    t.effects = e;
                    t.effects_resolved = r;
                    t.location = SourceLocation::new(path);
                    g.add_tool(t);
                    g.add_edge(Edge::new(id.clone(), tid, EdgeKind::Calls));
                }
                other => {
                    let tid = mint_id("tool", path, &format!("{name}_{other}"));
                    let mut t = ToolNode::new(tid.clone(), other);
                    t.source = ToolSource::Builtin(other.to_string());
                    t.location = SourceLocation::new(path);
                    g.add_tool(t);
                    g.add_edge(Edge::new(id.clone(), tid, EdgeKind::Calls));
                }
            }
        }
    }
}

/// Convert a parsed YAML value into a serde_json value (best-effort, lossless
/// for the scalar/map/seq subset we care about).
fn yaml_to_json(y: Yaml) -> Option<Json> {
    serde_json::to_value(y).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_assistant_json() {
        let src = r#"
{
  "object": "assistant",
  "name": "Helper",
  "model": "gpt-4o",
  "instructions": "You are helpful.",
  "tools": [
    { "type": "file_search" },
    { "type": "code_interpreter" },
    { "type": "function", "function": { "name": "lookup", "description": "fetch via requests.get", "parameters": {} } }
  ]
}
"#;
        assert!(detect(Path::new("a.json"), src));
        let g = parse(src, Path::new("a.json"), &ParseOptions::default());
        assert_eq!(g.agents.len(), 1);
        assert!(g.rag.iter().any(|r| r.kind == "file_search"));
        assert!(g.tools.iter().any(|t| t.name == "code_interpreter" && t.effects.code_eval));
        assert!(g.tools.iter().any(|t| t.name == "lookup"));
    }
}
