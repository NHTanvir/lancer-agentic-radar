//! Anthropic Computer Use parser (JSON tool definitions).
//!
//! Parses tool definitions of the shape `{ name, description, input_schema }`
//! and recognizes the builtin tool types `computer_20241022` /
//! `computer_20250124` / `bash_*` / `text_editor_*` (mapped to
//! [`ar_core::ToolSource::Builtin`]). `computer`/`bash` builtins imply
//! `shell_exec` effects.

use crate::common::{infer_effects, mint_id};
use ar_core::{
    AgentGraph, AgentNode, Edge, EdgeKind, Framework, ParseOptions, SourceLocation, ToolEffects,
    ToolNode, ToolSource,
};
use serde_json::Value as Json;
use std::path::Path;

const FW: Framework = Framework::AnthropicComputerUse;

/// Detect an Anthropic Computer Use / tool-definitions JSON file.
pub fn detect(path: &Path, content: &str) -> bool {
    if path.extension().and_then(|e| e.to_str()) != Some("json") {
        // Also recognize the builtin type strings in any text (e.g. python).
        return content.contains("computer_2024")
            || content.contains("computer_2025")
            || content.contains("text_editor_2024")
            || content.contains("bash_2024");
    }
    let v: Json = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return false,
    };
    json_has_tooldefs(&v)
}

fn json_has_tooldefs(v: &Json) -> bool {
    let check = |t: &Json| {
        if let Some(ty) = t.get("type").and_then(|x| x.as_str()) {
            if is_builtin(ty) {
                return true;
            }
        }
        t.get("name").is_some()
            && (t.get("input_schema").is_some() || t.get("description").is_some())
    };
    match v {
        Json::Array(arr) => arr.iter().any(check),
        Json::Object(o) => {
            if let Some(tools) = o.get("tools").and_then(|t| t.as_array()) {
                tools.iter().any(check)
            } else {
                check(v)
            }
        }
        _ => false,
    }
}

fn is_builtin(ty: &str) -> bool {
    ty.starts_with("computer_")
        || ty.starts_with("bash_")
        || ty.starts_with("text_editor_")
        || ty == "computer"
        || ty == "bash"
}

/// Parse an Anthropic Computer Use definition into a partial [`AgentGraph`].
pub fn parse(content: &str, path: &Path, _opts: &ParseOptions) -> AgentGraph {
    let mut g = AgentGraph::new();
    let v: Json = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => {
            // Best-effort: still capture builtin types mentioned in non-JSON.
            return parse_builtins_from_text(content, path);
        }
    };

    // synthetic agent
    let aid = mint_id("agent", path, "claude");
    let mut a = AgentNode::new(aid.clone(), "Claude (Computer Use)", FW);
    if let Some(o) = v.as_object() {
        if let Some(sp) = o.get("system").and_then(|x| x.as_str()) {
            a.set_system_prompt(sp);
        }
        a.model = o.get("model").and_then(|x| x.as_str()).map(|s| s.to_string());
    }
    a.accepts_user_input = true;
    a.location = SourceLocation::new(path);
    g.add_agent(a);

    let tools = match &v {
        Json::Array(arr) => arr.clone(),
        Json::Object(o) => o
            .get("tools")
            .and_then(|t| t.as_array())
            .cloned()
            .unwrap_or_else(|| vec![v.clone()]),
        _ => vec![],
    };
    for (i, t) in tools.iter().enumerate() {
        add_tool(t, path, &aid, i, &mut g);
    }

    g
}

fn add_tool(t: &Json, path: &Path, agent_id: &str, idx: usize, g: &mut AgentGraph) {
    let ty = t.get("type").and_then(|x| x.as_str());
    let name = t
        .get("name")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .or_else(|| ty.map(|s| s.to_string()))
        .unwrap_or_else(|| format!("tool_{idx}"));
    let tid = mint_id("tool", path, &name);
    let mut tn = ToolNode::new(tid.clone(), name.clone());

    if let Some(ty) = ty.filter(|ty| is_builtin(ty)) {
        tn.source = ToolSource::Builtin(ty.to_string());
        let mut e = ToolEffects::default();
        if ty.starts_with("computer") || ty.starts_with("bash") || ty == "computer" || ty == "bash" {
            e.shell_exec = true;
            e.reads_fs = true;
            e.writes_fs = true;
        }
        if ty.starts_with("text_editor") {
            e.reads_fs = true;
            e.writes_fs = true;
        }
        tn.effects = e;
        tn.effects_resolved = true;
    } else {
        tn.source = ToolSource::Native;
        if let Some(d) = t.get("description").and_then(|x| x.as_str()) {
            tn.description = Some(d.to_string());
            let (e, r) = infer_effects(d);
            tn.effects = e;
            tn.effects_resolved = r;
        }
    }
    tn.has_input_schema = t.get("input_schema").is_some();
    tn.location = SourceLocation::new(path);
    g.add_tool(tn);
    g.add_edge(Edge::new(agent_id.to_string(), tid, EdgeKind::Calls));
}

/// Fallback for non-JSON content that nonetheless mentions builtin tool types.
fn parse_builtins_from_text(content: &str, path: &Path) -> AgentGraph {
    let mut g = AgentGraph::new();
    let aid = mint_id("agent", path, "claude");
    let mut a = AgentNode::new(aid.clone(), "Claude (Computer Use)", FW);
    a.accepts_user_input = true;
    a.location = SourceLocation::new(path);
    g.add_agent(a);
    for ty in [
        "computer_20241022",
        "computer_20250124",
        "bash_20241022",
        "bash_20250124",
        "text_editor_20241022",
        "text_editor_20250124",
    ] {
        if content.contains(ty) {
            let tid = mint_id("tool", path, ty);
            let mut tn = ToolNode::new(tid.clone(), ty);
            tn.source = ToolSource::Builtin(ty.to_string());
            let mut e = ToolEffects::default();
            if ty.starts_with("computer") || ty.starts_with("bash") {
                e.shell_exec = true;
                e.reads_fs = true;
                e.writes_fs = true;
            } else {
                e.reads_fs = true;
                e.writes_fs = true;
            }
            tn.effects = e;
            tn.effects_resolved = true;
            tn.location = crate::common::locate(path, content, ty);
            g.add_tool(tn);
            g.add_edge(Edge::new(aid.clone(), tid, EdgeKind::Calls));
        }
    }
    g
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tool_defs_and_builtins() {
        let src = r#"
{
  "model": "claude-3-5-sonnet-20241022",
  "tools": [
    { "type": "computer_20250124", "name": "computer", "display_width_px": 1024 },
    { "type": "bash_20250124", "name": "bash" },
    { "name": "get_weather", "description": "fetch via requests", "input_schema": { "type": "object" } }
  ]
}
"#;
        assert!(detect(Path::new("cu.json"), src));
        let g = parse(src, Path::new("cu.json"), &ParseOptions::default());
        assert!(g.tools.iter().any(|t| matches!(&t.source, ToolSource::Builtin(b) if b == "computer_20250124")));
        assert!(g.tools.iter().any(|t| t.effects.shell_exec));
        assert!(g.tools.iter().any(|t| t.name == "get_weather" && t.has_input_schema));
    }
}
